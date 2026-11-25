"""Read-only scan for literal diagnostic text in selected client regions."""
import argparse
import json
import sys
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    needles = []
    for phrase in ('Fake Send Thrd', 'Send Thrd', 'Packet Fake', 'Thrd', 'Fake', 'Packet', 'Send',
                   'CMPF0', '6B8C11AD'):
        needles += [(phrase, 'ascii', phrase.encode('ascii')),
                    (phrase, 'utf16le', phrase.encode('utf-16le'))]
    scopes = [(0x05300000, 25374720, 'observed-private-allocation'),
              (0x006b0000, 0x00400000, 'engine-adjacent'),
              (0x20000000, 0x01000000, 'engine-module-range'),
              (0x10900000, 23552000, 'game-executable-image')]
    process = ReadOnlyProcess(args.pid)
    results = []
    try:
        for start, size, title in scopes:
            searched = 0
            skipped = 0
            hits = []
            previous = b''
            for address in range(start, start + size, 4096):
                try:
                    region = process.query(address)
                    if (region.state != 0x1000 or region.protect & 0x100 or
                            region.protect & 255 == 1):
                        raise ValueError('unreadable')
                    page = process.read(address, 4096)
                except (OSError, ValueError):
                    previous = b''
                    skipped += 1
                    continue
                searched += 1
                data = previous + page
                for phrase, encoding, needle in needles:
                    offset = data.find(needle)
                    while offset >= 0:
                        hits.append(dict(phrase=phrase, encoding=encoding,
                                         address=hex(address - len(previous) + offset)))
                        offset = data.find(needle, offset + 1)
                previous = page[-64:]
            results.append(dict(scope=title, start=hex(start), pages_searched=searched,
                                pages_skipped=skipped, hits=hits))
    finally:
        process.close()
    report = json.dumps(results, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    print(json.dumps([dict(scope=row['scope'], pages_searched=row['pages_searched'],
                           pages_skipped=row['pages_skipped'], hits=len(row['hits']))
                      for row in results]))


if __name__ == '__main__':
    main()
