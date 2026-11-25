"""Validate a current-session capture against two retained live cipher states.

No networking or live process access. Mid-session compression history is not
invented: compressed bodies are retained, with expansion reported separately.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
import struct
import subprocess
from decimal import Decimal
from pathlib import Path

from analyze_prime_timeline import parse_fields, transport
from asterios_game_cipher import AsteriosServerCipher
from decode_prime_client_native import NativeCipherOracle
from reference_xor import split_records


def digest(data):
    return hashlib.sha256(data).hexdigest()


def optional_fields(direction, packet):
    """A partial semantic schema must not invalidate verified ciphertext."""
    try:
        return parse_fields(direction, packet)
    except (ValueError, struct.error, UnicodeError) as error:
        return {'schema_error': str(error)}


def inverse(oracle, cipher, key, counter):
    mask, _ = oracle.encrypt(bytes(len(cipher)), key, counter)
    direct = bytes(a ^ b for a, b in zip(cipher, mask))
    previous_cipher = previous_mask = 0
    running = bytearray()
    for value, mask_value in zip(cipher, mask):
        running.append(value ^ previous_cipher ^ mask_value ^ previous_mask)
        previous_cipher, previous_mask = value, mask_value
    for mode, plain in [('direct-xor', direct), ('reverse-then-xor', direct[::-1]),
                        ('running-xor', bytes(running)), ('reverse-then-running-xor', bytes(running)[::-1])]:
        recipher, next_key = oracle.encrypt(plain, key, counter)
        if recipher == cipher:
            return plain, next_key, mode
    raise ValueError('No ciphertext-verified client inverse')


def interval_bytes(rows, direction, before, after, server='146.59.110.40'):
    data, ready, integrity = transport(rows, 0, server, direction == 'server')
    timestamps = {int(r['frame.number']): int(Decimal(r['frame.time_epoch']) * 10**9) for r in rows}
    selected = [i for i, frame in enumerate(ready)
                if before['read_end_ns'] < timestamps[frame] < after['read_start_ns']]
    if not selected:
        return b'', [], integrity
    start, end = selected[0], selected[-1] + 1
    if selected != list(range(start, end)):
        raise ValueError('Selected wire interval is not contiguous')
    return data[start:end], ready[start:end], integrity


def decode_server(data, frames, before, after):
    records = split_records(data)
    expected = (after['server_counter'] - before['server_counter']) & 0xffffffff
    if len(records) != expected:
        raise ValueError(f'Server capture/state count mismatch: {len(records)} versus {expected}')
    cipher = AsteriosServerCipher(bytes.fromhex(before['incoming_key']), before['server_counter'])
    outer, plain_packets, index = [], [], []
    offset = 0
    for ordinal, record in enumerate(records, 1):
        body = cipher.decrypt(record[2:])
        packet = struct.pack('<H', len(body) + 2) + body
        outer.append(packet)
        entry = dict(ordinal=ordinal, completion_frame=frames[offset + len(record) - 1],
                     compressed=body[0] == 0x8d, decoded_body_sha256=digest(body),
                     decoded_length=len(packet))
        if body[0] != 0x8d:
            entry.update(opcode=f'{body[0]:02X}', **optional_fields('server', packet))
            plain_packets.append(packet)
        index.append(entry)
        offset += len(record)
    if cipher.key.hex() != after['incoming_key'] or cipher.packet_counter != after['server_counter']:
        raise ValueError('Server final live key/counter mismatch')
    return outer, plain_packets, index


def decode_client(data, frames, before, after, oracle, return_consumed=False):
    expected = (after['client_counter'] - before['client_counter']) & 0xffffffff
    key = bytes.fromhex(before['outgoing_key'])
    header = before['client_header_state'] & 0xffff
    offset, packets, index = 0, [], []
    for ordinal in range(1, expected + 1):
        if offset + 2 > len(data):
            raise ValueError('Incomplete client length')
        size = int.from_bytes(data[offset:offset + 2], 'little') ^ header
        if size < 4 or offset + size > len(data):
            raise ValueError(f'Client boundary mismatch at {offset}: {size}')
        cipher = data[offset + 2:offset + size]
        count = (before['client_counter'] + ordinal - 1) & 0xffffffff
        plain, key, mode = inverse(oracle, cipher, key, count)
        signed_opcode = plain[0] if plain[0] < 128 else plain[0] - 256
        header = (((header * plain[-1]) ^ header) + signed_opcode * len(plain)) & 0xffff
        packet = struct.pack('<H', len(plain) + 1) + plain[:-1]
        packets.append(packet)
        index.append(dict(ordinal=ordinal, completion_frame=frames[offset + size - 1],
                          opcode=f'{plain[0]:02X}', decoded_length=len(packet), mode=mode,
                          ciphertext_reproduced=True, plaintext_sha256=digest(packet),
                          **optional_fields('client', packet)))
        offset += size
    if (not return_consumed and offset != len(data)) or key.hex() != after['outgoing_key']:
        raise ValueError('Client final live key/byte count mismatch')
    if header != (after['client_header_state'] & 0xffff):
        raise ValueError('Client final live header state mismatch')
    return (packets, index, offset) if return_consumed else (packets, index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe_dir', type=Path)
    parser.add_argument('--runtime-path', type=Path, required=True)
    parser.add_argument('--snapshot-dir', type=Path, action='append', required=True)
    args = parser.parse_args()
    state_path = args.probe_dir / 'private-state.json'
    state = json.loads(state_path.read_text('utf-8'))
    capture = args.probe_dir / 'online.pcapng'
    capture_hash = digest(capture.read_bytes())
    if capture_hash != state['capture_sha256'] or state['capture_exit_code']:
        raise ValueError('Capture identity or exit status mismatch')
    fields = ['frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.stream',
              'tcp.seq_raw', 'tcp.flags.syn', 'tcp.payload']
    command = ['C:/Program Files/Wireshark/tshark.exe', '-n', '-r', str(capture),
               '-T', 'fields', '-E', 'header=y']
    for field in fields:
        command.extend(['-e', field])
    result = subprocess.run(command, capture_output=True, check=True, timeout=60)
    rows = list(csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), delimiter='\t'))
    before, after = state['snapshots'][0], state['snapshots'][-1]
    server_data, server_frames, server_integrity = interval_bytes(rows, 'server', before, after)
    client_data, client_frames, client_integrity = interval_bytes(rows, 'client', before, after)
    outer, server_packets, server_index = decode_server(server_data, server_frames, before, after)
    oracle = NativeCipherOracle(args.snapshot_dir, args.runtime_path)
    try:
        client_packets, client_index = decode_client(client_data, client_frames, before, after, oracle)
    finally:
        oracle.close()
    output = args.probe_dir / 'decoded'
    output.mkdir(exist_ok=True)
    (output / 'server-outer-decrypted.bin').write_bytes(b''.join(outer))
    (output / 'server-uncompressed-packets.bin').write_bytes(b''.join(server_packets))
    (output / 'client-packets.bin').write_bytes(b''.join(client_packets))
    (output / 'server-index.json').write_text(json.dumps(server_index, indent=2) + '\n', 'utf-8')
    (output / 'client-index.json').write_text(json.dumps(client_index, indent=2) + '\n', 'utf-8')
    report = dict(validated=True, capture_sha256=capture_hash,
                  state_observations_sha256=digest(state_path.read_bytes()),
                  server_records=len(server_index), client_records=len(client_index),
                  server_compressed_records=sum(r['compressed'] for r in server_index),
                  server_uncompressed_packets=len(server_packets),
                  server_semantic_events=dict(collections.Counter(r.get('event', 'unparsed') for r in server_index)),
                  client_semantic_events=dict(collections.Counter(r.get('event', 'unparsed') for r in client_index)),
                  server_counter_start=before['server_counter'], server_counter_end=after['server_counter'],
                  client_counter_start=before['client_counter'], client_counter_end=after['client_counter'],
                  final_server_key_matches_live=True, final_client_key_matches_live=True,
                  final_client_header_low16_matches_live=True, all_client_ciphertexts_reproduced=True,
                  server_integrity=server_integrity, client_integrity=client_integrity,
                  oracle_live_process_read_used=False, known_initial_handshake_required=False,
                  snapshot_manifests=[dict(path=str(p / 'manifest.json'),
                      sha256=digest((p / 'manifest.json').read_bytes())) for p in args.snapshot_dir],
                  compressed_history='Capture starts mid-session; raw DEFLATE history was not retained. '
                                     'Compressed bodies are decrypted but not expanded by this test.',
                  intervention='No input, process writes, packet injection, logout or reconnect')
    (output / 'online-verification.json').write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
