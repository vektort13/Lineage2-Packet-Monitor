"""Search selected live client bytes for direct x86 CALL/JMP targets, read-only."""
import argparse
import json
import struct
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--target', type=lambda value: int(value, 0), action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    targets = set(args.target)
    scopes = [(0x05300000, 25374720, 'client-private-allocation'),
              (0x20000000, 0x01000000, 'engine-module-range'),
              (0x10900000, 23552000, 'game-executable-image')]
    process = ReadOnlyProcess(args.pid)
    result = []
    try:
        for start, size, title in scopes:
            hits = []
            for page_address in range(start, start + size, 4096):
                try:
                    region = process.query(page_address)
                    if region.state != 0x1000 or region.protect & 0x100 or region.protect & 255 == 1:
                        continue
                    page = process.read(page_address, 4096)
                except OSError:
                    continue
                for offset, opcode in enumerate(page[:-4]):
                    if opcode not in (0xe8, 0xe9):
                        continue
                    source = page_address + offset
                    dest = (source + 5 + struct.unpack_from('<i', page, offset + 1)[0]) & 0xffffffff
                    if dest in targets:
                        hits.append(dict(source=hex(source), destination=hex(dest),
                                         opcode='call' if opcode == 0xe8 else 'jmp'))
            result.append(dict(scope=title, hits=hits, count=len(hits)))
    finally:
        process.close()
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps([dict(scope=row['scope'], count=row['count']) for row in result]))


if __name__ == '__main__':
    main()
