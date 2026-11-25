"""Read-only Windows thread inventory for the active game process."""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
from datetime import datetime, timezone
from pathlib import Path

import psutil


class FileTime(ctypes.Structure):
    _fields_ = [('low', wt.DWORD), ('high', wt.DWORD)]


def iso_filetime(value):
    ticks = (value.high << 32) | value.low
    return datetime.fromtimestamp((ticks - 116444736000000000) / 10000000,
                                  tz=timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')
    kernel.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel.OpenThread.restype = wt.HANDLE
    kernel.GetThreadTimes.argtypes = [wt.HANDLE, ctypes.POINTER(FileTime),
                                     ctypes.POINTER(FileTime), ctypes.POINTER(FileTime),
                                     ctypes.POINTER(FileTime)]
    kernel.GetThreadTimes.restype = wt.BOOL
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    ntdll.NtQueryInformationThread.argtypes = [wt.HANDLE, wt.ULONG, wt.LPVOID,
                                                wt.ULONG, ctypes.POINTER(wt.ULONG)]
    ntdll.NtQueryInformationThread.restype = wt.LONG
    process = psutil.Process(args.pid)
    rows = []
    for thread in process.threads():
        row = dict(tid=thread.id, user_time=thread.user_time,
                   system_time=thread.system_time)
        handle = kernel.OpenThread(0x0040, False, thread.id)
        if handle:
            try:
                start = ctypes.c_void_p()
                length = wt.ULONG()
                status = ntdll.NtQueryInformationThread(handle, 9, ctypes.byref(start),
                                                          ctypes.sizeof(start), ctypes.byref(length))
                row['win32_start_address'] = hex(start.value or 0) if status == 0 else None
                row['start_query_status'] = hex(status & 0xffffffff)
                created, exited, kernel_time, user_time = (FileTime() for _ in range(4))
                if kernel.GetThreadTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                         ctypes.byref(kernel_time), ctypes.byref(user_time)):
                    row['created_utc'] = iso_filetime(created)
            finally:
                kernel.CloseHandle(handle)
        else:
            row['open_error'] = ctypes.get_last_error()
        rows.append(row)
    report = dict(pid=args.pid, process_create_utc=datetime.fromtimestamp(
        process.create_time(), tz=timezone.utc).isoformat(), threads=rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    selected = [row for row in rows if row['tid'] in (21896, 125724)]
    print(json.dumps(dict(total_threads=len(rows), selected=selected), indent=2))


if __name__ == '__main__':
    main()
