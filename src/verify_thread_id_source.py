"""Verify the observed GetCurrentThreadId import and stored value, read-only."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
import psutil

from emulate_capture_function import ReadOnlyProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    process = ReadOnlyProcess(args.pid)
    try:
        call_site = process.read(0x0539208a, 10)
        thunk = process.read(0x05301348, 6)
        import_slot = 0x053b67e0
        import_target = struct.unpack('<I', process.read(import_slot, 4))[0]
        stored_thread_id = struct.unpack('<I', process.read(0x053a4030, 4))[0]
    finally:
        process.close()
    if call_site[0] != 0xe8 or call_site[5] != 0xa3:
        raise ValueError('Observed call/store instruction sequence changed')
    called_address = (0x0539208f + struct.unpack_from('<i', call_site, 1)[0]) & 0xffffffff
    stored_address = struct.unpack_from('<I', call_site, 6)[0]
    if called_address != 0x05301348 or stored_address != 0x053a4030:
        raise ValueError('Observed call/store targets changed')
    if thunk != b'\xff\x25\xe0\x67\x3b\x05':
        raise ValueError('Observed import thunk changed')

    kernel_path = Path('C:/Windows/SysWOW64/kernel32.dll')
    image = pefile.PE(str(kernel_path), fast_load=True)
    image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    module_regions = [int(region.addr, 16) for region in psutil.Process(args.pid).memory_maps(grouped=False)
                      if Path(region.path).name.lower() == kernel_path.name.lower()
                      and 'syswow64' in region.path.lower()]
    if not module_regions:
        raise ValueError('32-bit kernel32 image is not mapped')
    module_base = min(module_regions)
    export_rva = import_target - module_base
    export_names = [entry.name.decode('ascii') for entry in image.DIRECTORY_ENTRY_EXPORT.symbols
                    if entry.address == export_rva and entry.name]
    report = dict(pid=args.pid, call_site='0x0539208a', call_site_bytes=call_site.hex(' '),
                  called_thunk=hex(called_address), thunk_bytes=thunk.hex(' '),
                  import_slot=hex(import_slot), import_target=hex(import_target),
                  kernel_module=str(kernel_path), kernel_module_base=hex(module_base),
                  export_rva=hex(export_rva), export_names=export_names,
                  stored_address=hex(stored_address), stored_thread_id=stored_thread_id,
                  kernel_sha256=hashlib.sha256(kernel_path.read_bytes()).hexdigest())
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
