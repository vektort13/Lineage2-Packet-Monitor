"""Offline candidate framing probes using retained original x86 cipher pages.

This does not open any process or socket. Candidates are not accepted as decoded
traffic unless their contents supply independent semantic evidence.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from reference_xor import extract_rows, reassemble_direction, split_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--runtime-path', type=Path, required=True)
    parser.add_argument('--snapshot-dir', type=Path, action='append', required=True)
    parser.add_argument('--character-list', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.runtime_path.resolve()))
    import unicorn as un
    from unicorn import x86_const as xc
    rows = extract_rows(args.capture, 'C:/Program Files/Wireshark/tshark.exe')
    server = split_records(reassemble_direction(rows, 0, '146.59.110.40', True)[0])
    client = reassemble_direction(rows, 0, '146.59.110.40', False)[0]
    client = client[int.from_bytes(client[:2], 'little'):]
    key = server[0][4:20]
    names = re.findall(rb'(?:[\x20-\x7e]\x00){6,}', args.character_list.read_bytes())
    semantic_needles = set(names)
    for name in names:
        decoded = name.decode('utf-16le')
        semantic_needles.update([decoded.encode('ascii'), decoded.upper().encode('ascii'),
                                decoded.upper().encode('utf-16le')])
    pages = {}
    for directory in args.snapshot_dir:
        manifest = json.loads((directory / 'manifest.json').read_text('utf-8'))
        for address, item in manifest['pages'].items():
            content = (directory / item['file']).read_bytes()
            if hashlib.sha256(content).hexdigest() != item['sha256']:
                raise ValueError('Snapshot identity mismatch')
            pages[int(address, 16)] = content
    results = []
    for full_size in range(4, 129):
        packet = client[2:full_size]
        uc = un.Uc(un.UC_ARCH_X86, un.UC_MODE_32)
        stack, buffer, key_pointer, sentinel = 0x0101f000, 0x02000102, 0x02100000, 0x02200000
        for address, size in [(0x01000000, 0x20000), (0x02000000, 0x20000),
                              (key_pointer, 4096), (sentinel, 4096)]:
            uc.mem_map(address, size)
        uc.mem_write(buffer, packet)
        uc.mem_write(key_pointer, b'\x01' + key)
        uc.mem_write(stack, struct.pack('<IIII', sentinel, buffer, key_pointer, len(packet)))
        uc.reg_write(xc.UC_X86_REG_ESP, stack)
        missing_pages = []
        key_indices = {}
        last_key_index = None

        def missing(emu, access, address, size, value, _):
            page = address & ~0xfff
            if page not in pages:
                missing_pages.append(hex(page))
                return False
            emu.mem_map(page, 4096)
            emu.mem_write(page, pages[page])
            return True

        def access(emu, kind, address, size, value, _):
            nonlocal last_key_index
            if kind == un.UC_MEM_READ and key_pointer + 1 <= address < key_pointer + 17:
                last_key_index = address - key_pointer - 1
            if kind == un.UC_MEM_WRITE and buffer <= address < buffer + len(packet):
                key_indices[address - buffer] = last_key_index

        uc.hook_add(un.UC_HOOK_MEM_UNMAPPED, missing)
        uc.hook_add(un.UC_HOOK_MEM_READ | un.UC_HOOK_MEM_WRITE, access)
        error = None
        try:
            uc.emu_start(0x0538660c, sentinel, timeout=5_000_000, count=2_000_000)
        except un.UcError as exc:
            error = str(exc)
        if error or uc.reg_read(xc.UC_X86_REG_EIP) != sentinel:
            results.append({'full_size_hypothesis': full_size, 'error': error,
                            'missing_pages': missing_pages})
            continue
        candidate = bytes(uc.mem_read(buffer, len(packet)))
        matches = []
        for common_flip in range(256):
            alternative = bytes(value ^ (common_flip if key_indices.get(i) is not None
                                         and key_indices[i] < 8 else 0)
                                for i, value in enumerate(candidate))
            if any(needle in alternative for needle in semantic_needles):
                matches.append(common_flip)
                args.report.with_name(f'{args.report.stem}-{full_size}-{common_flip}.bin').write_bytes(alternative)
        results.append({'full_size_hypothesis': full_size, 'returned': True,
                        'semantic_key_flip_matches': matches,
                        'candidate_sha256': hashlib.sha256(candidate).hexdigest()})
    report = {'scope': 'Candidate lengths 4..128; 256 common first-eight-key-byte flips per XOR candidate',
              'semantic_needle_count': len(semantic_needles), 'results': results}
    args.report.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps({'probes': len(results), 'returned': sum(x.get('returned', False) for x in results),
                      'semantic_matches': [x for x in results if x.get('semantic_key_flip_matches')],
                      'missing_pages': sorted({p for x in results for p in x.get('missing_pages', [])})}))


if __name__ == '__main__':
    main()
