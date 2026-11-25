"""Verified running XOR16 with the client's 64-bit counter and live checkpoints."""
import hashlib
import struct
import time
from pathlib import Path

import psutil
from emulate_capture_function import ReadOnlyProcess
from .alignment import wire_slice
from .ciphers import xor_encrypt
from .tcp_records import TcpRecords
from .character import parse_classic_character
from .classic_inventory import parse_classic_inventory
from .classic_skills import parse_classic_skills
from .classic_skill_menu import parse_classic_skill_menu
from .packet_sources import decode_packet
from analyze_prime_timeline import transport


class RunningXor64:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError('XOR16 requires a 16-byte key')
        self.key = bytearray(key)

    def decrypt(self, body):
        previous, result = 0, bytearray()
        for index, value in enumerate(body):
            result.append(value ^ self.key[index & 15] ^ previous)
            previous = value
        counter = (int.from_bytes(self.key[8:16], 'little') + len(body)) & ((1 << 64) - 1)
        self.key[8:16] = counter.to_bytes(8, 'little')
        return bytes(result)


class ClassicLiveState:
    """Read-only, build-matched layout; addresses relocate with Engine.dll."""
    def __init__(self, pid, executable, profile):
        self.profile = profile
        engine = Path(executable).parent / 'Engine.dll'
        if hashlib.sha256(engine.read_bytes()).hexdigest() != profile['engine_sha256']:
            raise ValueError('Engine.dll does not match the selected cipher profile')
        bases = [int(region.addr.split('-')[0], 16)
                 for region in psutil.Process(pid).memory_maps(grouped=False)
                 if Path(region.path).name.lower() == 'engine.dll']
        if not bases:
            raise ValueError('Loaded Engine.dll was not found')
        self.base = min(bases)
        self.memory = ReadOnlyProcess(pid)
        try:
            for fingerprint in profile['fingerprints']:
                actual = self.memory.read(self.base + fingerprint['rva'], fingerprint['size'])
                if hashlib.sha256(actual).hexdigest() != fingerprint['sha256']:
                    raise ValueError('Loaded cipher code does not match the saved profile')
        except Exception:
            self.close()
            raise

    def _u32(self, address):
        return struct.unpack('<I', self.memory.read(address, 4))[0]

    def _map(self, socket, offset, width, expected):
        _, begin, end, capacity = struct.unpack('<4I', self.memory.read(socket + offset, 16))
        if end < begin or capacity < end or end - begin != expected * width:
            raise ValueError('Client opcode table layout changed')
        data = self.memory.read(begin, expected * width)
        result = list(data) if width == 1 else list(struct.unpack('<' + str(expected) + 'H', data))
        if len(set(result)) != expected:
            raise ValueError('Client opcode table is not a permutation')
        return result

    def _read(self):
        spec = self.profile
        root = self._u32(self.base + spec['root_pointer_rva'])
        mode = self._u32(root + spec['socket_mode_offset'])
        offset = spec['auth_socket_offset'] if mode in (0, 1) else spec['game_socket_offset']
        socket = self._u32(root + offset)
        if self._u32(socket) != self.base + spec['socket_vtable_rva']:
            raise ValueError('The active socket does not match the cipher profile')
        if not self._u32(socket + spec['encryption_enabled_offset']):
            raise ValueError('The game cipher has not been initialized')
        pending = self.memory.read(socket + spec['receive_progress_offset'], 12)
        if pending != bytes(12):
            raise ValueError('A receive packet is incomplete; waiting for a record boundary')
        if self._u32(socket + spec.get('alternate_receive_offset', 0xa114)):
            raise ValueError('The alternate receive buffer is active; waiting for the profiled receive boundary')
        outgoing = self.memory.read(socket + spec['outgoing_key_offset'], 16)
        incoming = self.memory.read(socket + spec['incoming_key_offset'], 16)
        if self.memory.read(socket + spec['outgoing_key_offset'] - 1, 1) != b'\1' or self.memory.read(socket + spec['incoming_key_offset'] - 1, 1) != b'\1':
            raise ValueError('The directional cipher state is not initialized')
        packet_address = socket + spec.get('receive_packet_buffer_offset', 0x850)
        packet_size = int.from_bytes(self.memory.read(packet_address, 2), 'little')
        if not 3 <= packet_size <= 32768:
            raise ValueError('Waiting for a retained native receive packet')
        last_packet = self.memory.read(packet_address, packet_size)
        return dict(socket=socket, outgoing_key=outgoing.hex(), incoming_key=incoming.hex(),
                    last_server_packet_hex=last_packet.hex(),
                    client_wire=self._u32(socket + spec['outgoing_bytes_offset']),
                    server_wire=self._u32(socket + spec['incoming_bytes_offset']),
                    opcode_map=self._map(socket, spec['opcode_map_offset'], 1, spec['opcode_map_count']),
                    extended_map=self._map(socket, spec['extended_map_offset'], 2, spec['extended_map_count']))

    def snapshot(self):
        for _ in range(40):
            start = time.time_ns()
            try:
                first = self._read()
                time.sleep(.003)
                second = self._read()
                if first == second:
                    return dict(first, read_start_ns=start, read_end_ns=time.time_ns())
            except ValueError:
                pass
            time.sleep(.005)
        raise ValueError('Cannot read a stable game-cipher checkpoint yet')

    def close(self):
        self.memory.close()


def _stream_bytes(rows, direction, endpoint):
    local = (endpoint['local_ip'], str(endpoint['local_port']))
    remote = (endpoint['remote_ip'], str(endpoint['remote_port']))
    source, destination = (remote, local) if direction == 'server' else (local, remote)
    selected = [row for row in rows if row.get('tcp.payload') and
                (row.get('ip.src'), str(row.get('tcp.srcport'))) == source and
                (row.get('ip.dst'), str(row.get('tcp.dstport'))) == destination]
    if not selected:
        return b'', None
    data, _, _ = transport(selected, 0, endpoint['remote_ip'], direction == 'server')
    anchor = int(selected[0]['tcp.seq_raw'])
    offsets = [(int(row['tcp.seq_raw']) - anchor + 2**31) % 2**32 - 2**31 for row in selected]
    return data, (anchor + min(offsets)) & 0xffffffff


def _native_wire(checkpoint):
    try:
        plain = bytes.fromhex(checkpoint['last_server_packet_hex'])
        key = bytes.fromhex(checkpoint['incoming_key'])
    except (TypeError, ValueError) as error:
        raise ValueError('Invalid native receive-packet checkpoint') from error
    if (not 3 <= len(plain) <= 32768 or int.from_bytes(plain[:2], 'little') != len(plain)
            or len(key) != 16):
        raise ValueError('Invalid native receive-packet checkpoint')
    counter = (int.from_bytes(key[8:], 'little') - (len(plain) - 2)) & ((1 << 64) - 1)
    previous_key = key[:8] + counter.to_bytes(8, 'little')
    return plain, plain[:2] + xor_encrypt(plain[2:], previous_key)


def _unique_end(data, base, wire, *, required, ambiguous_ok=False):
    position = data.find(wire)
    if position < 0:
        if required:
            raise ValueError('Waiting for captured bytes of the native packet anchor')
        return None
    if data.find(wire, position + 1) >= 0:
        if ambiguous_ok:
            return None
        raise ValueError('Ambiguous native packet anchor in captured TCP bytes')
    return (base + position + len(wire)) & 0xffffffff


def _anchored_slice(data, base, start, length):
    if base is None:
        if length:
            raise ValueError('Waiting for captured TCP bytes at the native packet anchor')
        return b''
    offset = (start - base + 2**31) % 2**32 - 2**31
    if offset < 0 or offset + length > len(data):
        raise ValueError('Waiting for captured TCP bytes to cover the native packet checkpoint')
    return data[offset:offset + length]


def _server_plan(rows, before, after, endpoint, wire_bytes, cursor):
    data, base = _stream_bytes(rows, 'server', endpoint)
    plain, wire = _native_wire(after)
    end = _unique_end(data, base, wire, required=bool(wire_bytes) and cursor is None,
                      ambiguous_ok=cursor is not None)
    if end is None and cursor is None:
        return None, b'', plain
    start = cursor if cursor is not None else (end - wire_bytes) & 0xffffffff
    if end is not None and end != (start + wire_bytes) & 0xffffffff:
        raise ValueError('TCP cursor disagrees with the native receive anchor')
    if 'last_server_packet_hex' in before:
        _, previous_wire = _native_wire(before)
        previous_end = _unique_end(data, base, previous_wire, required=False, ambiguous_ok=True)
        if previous_end is not None and previous_end != start:
            raise ValueError('Native receive anchors disagree with the wire-byte checkpoint')
    return start, _anchored_slice(data, base, start, wire_bytes), plain


def _client_plan(rows, before, after, endpoint, wire_bytes, cursor, proofs):
    if not wire_bytes:
        return None, b''
    data, base = _stream_bytes(rows, 'client', endpoint)
    candidates, proofs_to_check = [], []
    trusted_base = None if cursor is None else (cursor - before['client_wire']) & 0xffffffff
    for proof in proofs:
        count = proof.get('client_wire_after')
        try:
            wire = bytes.fromhex(proof.get('wire_hex', ''))
        except (TypeError, ValueError) as error:
            raise ValueError('Invalid native client-send proof') from error
        if (type(count) is not int or not 0 <= count <= 0xffffffff or
                not 3 <= len(wire) <= 32768 or int.from_bytes(wire[:2], 'little') != len(wire)):
            raise ValueError('Invalid native client-send proof')
        if trusted_base is not None:
            current_proof = 0 < ((count - before['client_wire']) & 0xffffffff) <= wire_bytes
            if base is not None:
                end_offset = ((trusted_base + count - base + 2**31) % 2**32) - 2**31
                start_offset = end_offset - len(wire)
                if 0 <= start_offset and end_offset <= len(data) and data[start_offset:end_offset] != wire:
                    raise ValueError('Native client-send proof disagrees with the verified TCP cursor')
                if current_proof and not (0 <= start_offset and end_offset <= len(data)):
                    position = data.find(wire)
                    if position >= 0 and data.find(wire, position + 1) < 0:
                        raise ValueError('TCP cursor disagrees with the native client-send proof')
                    raise ValueError('Waiting for captured bytes of the native client-send proof')
            elif current_proof:
                raise ValueError('Waiting for captured bytes of the native client-send proof')
            continue
        proofs_to_check.append((count, wire))
        position = data.find(wire)
        if position < 0:
            continue
        if data.find(wire, position + 1) >= 0:
            continue
        candidates.append((len(wire), (base + position + len(wire) - count) & 0xffffffff))
    if trusted_base is not None:
        candidates.append((0, trusted_base))
    if not candidates:
        raise ValueError('Waiting for a unique captured native client-send proof')
    # A long BBS request includes the changing counter bytes. Attribute older
    # short repeated requests at their counter-derived positions, rather than
    # confusing their identical bytes with a later request still in capture.
    sequence_base = max(candidates, key=lambda candidate: candidate[0])[1]
    for count, wire in proofs_to_check:
        end_offset = ((sequence_base + count - base + 2**31) % 2**32) - 2**31
        start_offset = end_offset - len(wire)
        if 0 <= start_offset and end_offset <= len(data) and data[start_offset:end_offset] != wire:
            raise ValueError('Native client-send proofs disagree on the TCP sequence base')
    start = (sequence_base + before['client_wire']) & 0xffffffff
    if cursor is not None and cursor != start:
        raise ValueError('TCP cursor disagrees with the native client-send proof')
    return start, _anchored_slice(data, base, start, wire_bytes)


def decode_classic_window(rows, before, after, endpoint, catalog, session_id, cursors=None, client_anchors=None):
    """Publish a window only after byte counts and both full ending keys match."""
    if before['socket'] != after['socket']:
        raise ValueError('The active game socket changed')
    if before['opcode_map'] != after['opcode_map'] or before['extended_map'] != after['extended_map']:
        raise ValueError('Client opcode permutation changed inside a checkpoint window')
    assembler = TcpRecords(endpoint)
    plans = {}
    for direction, field in (('server', 'incoming_key'), ('client', 'outgoing_key')):
        old_key, new_key = bytes.fromhex(before[field]), bytes.fromhex(after[field])
        if old_key[:8] != new_key[:8]:
            raise ValueError('Session cipher key changed')
        body_bytes = (int.from_bytes(new_key[8:], 'little') - int.from_bytes(old_key[8:], 'little')) & ((1 << 64) - 1)
        wire_bytes = (after[direction + '_wire'] - before[direction + '_wire']) & 0xffffffff
        overhead = wire_bytes - body_bytes
        if body_bytes > 8 * 1024 * 1024 or overhead < 0 or overhead & 1:
            raise ValueError('Cipher counter and wire-byte checkpoint disagree')
        count = overhead // 2
        cursor = (cursors or {}).get(direction)
        native_last = None
        if direction == 'server' and 'last_server_packet_hex' in after:
            start, data, native_last = _server_plan(rows, before, after, endpoint, wire_bytes, cursor)
        elif direction == 'client' and client_anchors is not None:
            start, data = _client_plan(rows, before, after, endpoint, wire_bytes, cursor, client_anchors)
        else:
            # Retained offline fixtures predating native checkpoints only.
            data, _, _, start = wire_slice(rows, direction, endpoint['remote_ip'], before, after, cursor)
        if wire_bytes and start is None:
            raise ValueError('Waiting for captured game data at the checkpoint')
        if len(data) < wire_bytes:
            raise ValueError('Waiting for captured TCP bytes to reach the client checkpoint')
        if start is not None:
            assembler.seed(direction, start)
        plans[direction] = (field, wire_bytes, count, start, data[:wire_bytes], native_last)
    records = assembler.feed(rows)
    packets, results, next_cursors = [], {}, {}
    for direction, (field, wire_bytes, count, start, expected_wire, native_last) in plans.items():
        chosen = [record for record in records if record['direction'] == direction][:count]
        if len(chosen) != count or b''.join(record['wire'] for record in chosen) != expected_wire:
            raise ValueError('TCP records do not match the client byte checkpoint')
        if assembler.state(direction)['status'] in ('conflict', 'overflow', 'invalid_length'):
            raise ValueError('TCP stream has conflicting or invalid data')
        cipher = RunningXor64(bytes.fromhex(before[field]))
        last_decoded = None
        for record in chosen:
            wire = record['wire']
            key = bytes(cipher.key)
            body = cipher.decrypt(wire[2:])
            if xor_encrypt(body, key) != wire[2:]:
                raise ValueError('Re-encrypted packet does not match the captured bytes')
            normalized = bytearray(body)
            if direction == 'client':
                if normalized[0] >= len(before['opcode_map']):
                    raise ValueError('Client opcode is outside its observed permutation')
                normalized[0] = before['opcode_map'][normalized[0]]
                if normalized[0] == 0xd0:
                    if len(normalized) < 3:
                        raise ValueError('Incomplete extended client opcode')
                    extended = int.from_bytes(normalized[1:3], 'little')
                    if extended >= len(before['extended_map']):
                        raise ValueError('Extended client opcode is outside its observed permutation')
                    normalized[1:3] = before['extended_map'][extended].to_bytes(2, 'little')
            raw = wire[:2] + normalized
            last_decoded = bytes(raw)
            packet = decode_packet(catalog, direction, raw, record['completion_time'], record['completion_frame'], session_id, 'classic-h5',
                                    cipher='l2xor16-u64', ciphertext_reproduced=True,
                                    cipher_end_state_verified=True, wire_sha256=hashlib.sha256(wire).hexdigest(),
                                    data_layer='game-packet', actions_supported=False)
            if direction == 'client' and bytes(normalized) != body:
                packet['decrypted_wire_hex'] = (wire[:2] + body).hex()
            packets.append(packet)
        if bytes(cipher.key).hex() != after[field]:
            raise ValueError('XOR16 ending key does not match the live client')
        if native_last is not None and wire_bytes and last_decoded != native_last:
            raise ValueError('Decoded final packet does not match the retained native receive packet')
        next_cursors[direction] = ((start + wire_bytes) & 0xffffffff) if start is not None else (cursors or {}).get(direction)
        results[direction] = dict(records=count, wire_bytes=wire_bytes, key_matches=True, ciphertext_reproduced=True)
    packets.sort(key=lambda packet: (float(packet['ts_epoch']), packet['frame']))
    return packets, dict(cipher='l2xor16-u64', directions=results, wire_cursors=next_cursors,
                         compressed_blocks=0, expanded_bytes=0, end_states_verified=True)
