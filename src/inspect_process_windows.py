"""List windows and owner threads for a process using read-only Win32 queries."""
import argparse
import ctypes
from ctypes import wintypes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    args = parser.parse_args()
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def collect(window, _):
        pid = wintypes.DWORD()
        thread = user.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value == args.pid:
            title = ctypes.create_unicode_buffer(user.GetWindowTextLengthW(window) + 1)
            user.GetWindowTextW(window, title, len(title))
            print(f'window={window:#x} thread={thread} visible={bool(user.IsWindowVisible(window))} title={title.value!r}')
        return True

    user.EnumWindows(collect, 0)


if __name__ == '__main__':
    main()
