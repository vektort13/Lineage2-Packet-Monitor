"""Find exact 32-bit thread-ID values in selected readable client regions."""
import argparse
import json
import struct
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--thread-id', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = struct.pack('<I', args.thread_id)
    scopes = [(0x05300000, 25374720, 'client-private-allocation'),
              (0x20000000, 0x01000000, 'engine-module-range'),
              (0x10900000, 23552000, 'game-executable-image')]
    process = ReadOnlyProcess(args.pid)
    results = []
    try:
        for start, size, title in scopes:
            hits = []
            skipped = 0
            previous = b''
            for address in range(start, start + size, 4096):
                try:
                    region = process.query(address)
                    if region.state != 0x1000 or region.protect & 0x100 or region.protect & 255 == 1:
                        raise ValueError('unreadable')
                    page = process.read(address, 4096)
                except (OSError, ValueError):
                    previous = b''
                    skipped += 1
                    continue
                data = previous + page
                offset = data.find(value)
                while offset >= 0:
                    candidate = address - len(previous) + offset
                    if candidate not in hits:
                        hits.append(candidate)
                    offset = data.find(value, offset + 1)
                previous = page[-3:]
            results.append(dict(scope=title, hits=[hex(hit) for hit in hits],
                                count=len(hits), skipped_pages=skipped))
    finally:
        process.close()
    args.output.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps([dict(scope=row['scope'], count=row['count'], skipped_pages=row['skipped_pages'])
                      for row in results]))


if __name__ == '__main__':
    main()
