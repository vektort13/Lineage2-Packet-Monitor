"""Decode saved C2S traffic with the retained original client cipher in Unicorn.

No socket is opened and no client code runs in the host process. A normal
query/read process handle is optional, solely to retain missing cipher pages.
Every candidate plaintext must reproduce the exact captured ciphertext through
the original encryption routine before its key state is accepted.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from reference_xor import extract_rows, reassemble_direction, split_records


class NativeCipherOracle:
    def __init__(self, snapshot_dirs, runtime_path, capture_dir=None, live_pid=None):
        sys.path.insert(0, str(runtime_path.resolve()))
        import unicorn as un
        from unicorn import x86_const as xc
        self.un, self.xc = un, xc
        self.pages = {}
        self.capture_dir = capture_dir
        self.capture_manifest = {'entry': '0x538660c', 'pages': {},
                                 'provenance': 'ordinary ReadProcessMemory for missing cipher pages only'}
        if capture_dir and (capture_dir / 'manifest.json').exists():
            self.capture_manifest = json.loads((capture_dir / 'manifest.json').read_text('utf-8'))
        self.process = None
        if live_pid:
            from emulate_capture_function import ReadOnlyProcess
            self.process = ReadOnlyProcess(live_pid)
            if self.capture_dir:
                self.capture_dir.mkdir(parents=True, exist_ok=True)
        for directory in snapshot_dirs:
            manifest = json.loads((directory / 'manifest.json').read_text('utf-8'))
            for address, item in manifest['pages'].items():
                content = (directory / item['file']).read_bytes()
                if len(content) != 4096 or hashlib.sha256(content).hexdigest() != item['sha256']:
                    raise ValueError('Snapshot page identity mismatch')
                self.pages[int(address, 16)] = content
        self.uc = un.Uc(un.UC_ARCH_X86, un.UC_MODE_32)
        self.stack, self.buffer, self.key, self.sentinel = 0x0101f000, 0x02000102, 0x02100000, 0x02200000
        for address, size in [(0x01000000, 0x20000), (0x02000000, 0x20000),
                              (self.key, 4096), (self.sentinel, 4096)]:
            self.uc.mem_map(address, size)
        self.loaded = set()
        self.missing_error = None
        self.uc.hook_add(un.UC_HOOK_MEM_UNMAPPED, self._missing)
        self._load(0x053b5000)

    def _load(self, page):
        if page in self.loaded:
            return
        if page not in self.pages and self.process:
            region = self.process.query(page)
            if (region.allocation not in (0x006b0000, 0x05300000, 0x20000000, 0x753b0000)
                    or region.state != 0x1000 or region.protect & 0x100
                    or region.protect & 255 == 1):
                raise ValueError(f'Unestablished external page {page:#x}')
            content = self.process.read(page, 4096)
            if self.capture_dir:
                name = f'{page:08x}.bin'
                (self.capture_dir / name).write_bytes(content)
                self.capture_manifest['pages'][hex(page)] = {'file': name,
                    'sha256': hashlib.sha256(content).hexdigest(), 'protect': region.protect}
            self.pages[page] = content
        if page not in self.pages:
            raise ValueError(f'Missing retained cipher page {page:#x}')
        self.uc.mem_map(page, 4096)
        self.uc.mem_write(page, self.pages[page])
        self.loaded.add(page)

    def _missing(self, uc, access, address, size, value, _):
        try:
            self._load(address & ~0xfff)
            return True
        except Exception as error:
            self.missing_error = str(error)
            return False

    def encrypt(self, plain, key, previous_counter):
        if not 1 <= len(plain) <= 0xfffd:
            raise ValueError('Invalid cipher input length')
        uc, xc = self.uc, self.xc
        uc.mem_write(self.buffer, plain)
        uc.mem_write(self.key, b'\x01' + bytes(key))
        uc.mem_write(0x053b5248, struct.pack('<I', previous_counter))
        uc.mem_write(self.stack, struct.pack('<IIII', self.sentinel, self.buffer, self.key, len(plain)))
        for name in ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP'):
            uc.reg_write(getattr(xc, 'UC_X86_REG_' + name), 0)
        uc.reg_write(xc.UC_X86_REG_EFLAGS, 2)
        uc.reg_write(xc.UC_X86_REG_ESP, self.stack)
        self.missing_error = None
        try:
            uc.emu_start(0x0538660c, self.sentinel, timeout=5_000_000, count=2_000_000)
        except self.un.UcError as error:
            raise ValueError(self.missing_error or str(error)) from error
        if uc.reg_read(xc.UC_X86_REG_EIP) != self.sentinel:
            raise ValueError('Native routine did not return within its execution limit')
        counter = int.from_bytes(uc.mem_read(0x053b5248, 4), 'little')
        if counter != (previous_counter + 1) & 0xffffffff:
            raise ValueError('Unexpected outgoing packet counter')
        return bytes(uc.mem_read(self.buffer, len(plain))), bytes(uc.mem_read(self.key + 1, 16))

    def close(self):
        if self.process:
            self.process.close()
            if self.capture_dir:
                (self.capture_dir / 'manifest.json').write_text(json.dumps(self.capture_manifest, indent=2) + '\n', 'utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--runtime-path', type=Path, required=True)
    parser.add_argument('--snapshot-dir', type=Path, action='append', required=True)
    parser.add_argument('--new-pages-dir', type=Path)
    parser.add_argument('--live-pid', type=int)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--first-wire-size', type=int, default=64,
                        help='Framing hypothesis; accepted only if the complete direction parses')
    args = parser.parse_args()
    rows = extract_rows(args.capture, 'C:/Program Files/Wireshark/tshark.exe')
    server = split_records(reassemble_direction(rows, 0, '146.59.110.40', True)[0])
    client, integrity = reassemble_direction(rows, 0, '146.59.110.40', False)
    initial_size = int.from_bytes(client[:2], 'little')
    encoded = client[initial_size:]
    header_state = int.from_bytes(encoded[:2], 'little') ^ args.first_wire_size
    initial_header_state = header_state
    key = server[0][4:20]
    oracle = NativeCipherOracle(args.snapshot_dir, args.runtime_path, args.new_pages_dir, args.live_pid)
    args.output_dir.mkdir(exist_ok=True, parents=True)
    packets, concatenated, offset, counter = [], bytearray(), 0, 0
    try:
        while offset < len(encoded):
            if offset + 2 > len(encoded):
                raise ValueError('Truncated encrypted C2S length')
            size = int.from_bytes(encoded[offset:offset + 2], 'little') ^ header_state
            if size < 4 or offset + size > len(encoded):
                raise ValueError(f'Invalid C2S boundary at {offset}: {size}')
            cipher = encoded[offset + 2:offset + size]
            mask, _ = oracle.encrypt(bytes(len(cipher)), key, counter)
            direct = bytes(a ^ b for a, b in zip(cipher, mask))
            candidates = [('direct-xor', direct)]
            candidates.append(('reverse-then-xor', direct[::-1]))
            previous_cipher = previous_mask = 0
            running = bytearray()
            for value, mask_value in zip(cipher, mask):
                running.append(value ^ previous_cipher ^ mask_value ^ previous_mask)
                previous_cipher, previous_mask = value, mask_value
            if bytes(running) != direct:
                candidates.append(('running-xor', bytes(running)))
                candidates.append(('reverse-then-running-xor', bytes(running)[::-1]))
            accepted = None
            for mode, plain in candidates:
                recipher, next_key = oracle.encrypt(plain, key, counter)
                if recipher == cipher:
                    accepted = mode, plain, next_key
                    break
            if accepted is None:
                raise ValueError(f'No independently verified inverse at C2S record {counter + 1}')
            mode, plain, key = accepted
            opcode = plain[0]
            signed_opcode = opcode if opcode < 128 else opcode - 256
            next_state = (((header_state * plain[-1]) ^ header_state)
                          + signed_opcode * len(plain)) & 0xffff
            decoded = struct.pack('<H', len(plain) + 1) + plain[:-1]
            packets.append({'record_index': counter + 1, 'wire_offset': offset + initial_size,
                            'wire_length': size, 'decoded_offset': len(concatenated),
                            'decoded_length': len(decoded), 'opcode': f'{opcode:02x}',
                            'mode': mode, 'ciphertext_reproduced': True,
                            'ciphertext_sha256': hashlib.sha256(cipher).hexdigest(),
                            'key_after_sha256': hashlib.sha256(key).hexdigest(),
                            'plaintext_sha256': hashlib.sha256(decoded).hexdigest()})
            concatenated.extend(decoded)
            header_state = next_state
            counter += 1
            offset += size
    finally:
        oracle.close()
    report = {'capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
              'client_integrity': integrity, 'initial_plain_record_bytes': initial_size,
              'encrypted_bytes_consumed': offset, 'total_encrypted_bytes': len(encoded),
              'initial_length_state_low16': initial_header_state, 'client_counter_initial': 0,
              'native_cipher_entry': '0x0538660c', 'live_process_read_used': bool(args.live_pid),
              'loaded_snapshot_pages': len(oracle.loaded),
              'snapshot_manifests': [{'path': str(directory / 'manifest.json'),
                  'sha256': hashlib.sha256((directory / 'manifest.json').read_bytes()).hexdigest()}
                  for directory in args.snapshot_dir],
              'decoded_packets': len(packets), 'decoded_bytes': len(concatenated),
              'decoded_sha256': hashlib.sha256(concatenated).hexdigest(), 'packets': packets}
    (args.output_dir / 'client-packets.bin').write_bytes(concatenated)
    (args.output_dir / 'client-packets.json').write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'packets'}))


if __name__ == '__main__':
    main()
