"""Retain a bounded, read-only snapshot of the previously observed client image.

No target thread is suspended, executed, injected or modified. Missing pages
are recorded as gaps, never invented. The result is not an atomic snapshot.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pefile
import psutil

from emulate_capture_function import ReadOnlyProcess


ROOT = Path(__file__).resolve().parents[1]
BASE = 0x05300000
EXPECTED_HEADER = 'dfb87464f06562784db935ae0466a94e660095075f0c6c36861676d339facdba'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    selected = psutil.Process(args.pid)
    expected_exe = (ROOT.parent / 'asterios' / 'AsteriosGame.exe').resolve()
    if Path(selected.exe()).resolve() != expected_exe:
        raise ValueError('Selected PID does not belong to the requested client executable')
    profile = json.loads((ROOT / 'config/monitor-profile.json').read_text(encoding='utf-8'))
    engine_path = expected_exe.parent / 'Engine.dll'
    if hashlib.sha256(engine_path.read_bytes()).hexdigest() != profile['engine_sha256']:
        raise ValueError('On-disk Engine.dll differs from the investigation profile')
    process = ReadOnlyProcess(args.pid)
    try:
        header = process.read(BASE, 4096)
        if hashlib.sha256(header).hexdigest() != EXPECTED_HEADER:
            raise ValueError('Observed private PE header differs; do not reuse its old address range')
        image = pefile.PE(data=header, fast_load=True)
        size = image.OPTIONAL_HEADER.SizeOfImage
        if size != 0x1833000 or size > 64 * 1024 * 1024:
            raise ValueError('Private image size differs from the recorded bounds')
        root_region = process.query(BASE)
        if root_region.allocation != BASE:
            raise ValueError('Private allocation base differs from the recorded image')
        args.output.mkdir(parents=True, exist_ok=False)
        report = dict(schema='l2-diagnostic-read-only-image-v1', pid=args.pid,
                      executable=str(expected_exe), process_create_time=selected.create_time(),
                      access='PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ',
                      started_utc=datetime.now(timezone.utc).isoformat(),
                      private_image_base=hex(BASE), private_image_size=size,
                      pages=[], gaps=[], atomic_snapshot=False,
                      limitations=[
                          'Memory is read while the client continues running; cross-page state consistency is not established.',
                          'This snapshot postdates the diagnostic experiments and does not reconstruct their exact-time state.',
                          'A matching PE header does not establish an emitting function or a file of origin.'])
        digest = hashlib.sha256()
        with (args.output / 'private-image-pages.bin').open('wb') as stream:
            for address in range(BASE, BASE + size, 4096):
                try:
                    region = process.query(address)
                    if (region.allocation != BASE or region.state != 0x1000 or
                            region.protect & 0x100 or region.protect & 0xff == 1):
                        raise ValueError('Page is outside the original readable allocation')
                    data = process.read(address, 4096)
                except (OSError, ValueError) as error:
                    report['gaps'].append(dict(address=hex(address), reason=str(error)))
                    continue
                report['pages'].append(dict(address=hex(address), offset=stream.tell(), bytes=len(data),
                                           sha256=hashlib.sha256(data).hexdigest(), protect=region.protect))
                stream.write(data)
                digest.update(data)
        report['page_file_sha256'] = digest.hexdigest()
        report['all_private_pages_retained'] = not report['gaps'] and len(report['pages']) == size // 4096
        report['header_unchanged_after_read'] = process.read(BASE, 4096) == header
        entry = profile['native_sender']['entry']
        page = entry & ~4095
        entry_data = process.read(page, 4096)
        (args.output / 'engine-entry-page.bin').write_bytes(entry_data)
        fingerprint = profile['native_sender']['fingerprints'][0]
        body = entry_data[entry - page:entry - page + fingerprint['size']]
        report['engine_entry_page'] = dict(address=hex(page), sha256=hashlib.sha256(entry_data).hexdigest(),
                                           entry=hex(entry), function_prefix_sha256=hashlib.sha256(body).hexdigest(),
                                           function_prefix_matches_profile=hashlib.sha256(body).hexdigest() == fingerprint['sha256'])
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (args.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(dict(pages=len(report['pages']), gaps=len(report['gaps']),
                              header_unchanged=report['header_unchanged_after_read'],
                              entry_matches_profile=report['engine_entry_page']['function_prefix_matches_profile'])), flush=True)
    finally:
        process.close()


if __name__ == '__main__':
    main()
