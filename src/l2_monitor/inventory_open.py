"""Open the selected client's inventory through its normal Alt+V shortcut."""
import ctypes
import time
from ctypes import wintypes


class InputNotReady(RuntimeError):
    """No shortcut was sent; wait for a usable game window/input state."""


def open_inventory(pid):
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user.GetWindow.restype = wintypes.HWND
    user.GetForegroundWindow.restype = wintypes.HWND
    user.SetForegroundWindow.argtypes = [wintypes.HWND]
    user.BringWindowToTop.argtypes = [wintypes.HWND]
    user.IsIconic.argtypes = [wintypes.HWND]
    user.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user.GetAsyncKeyState.restype = wintypes.SHORT
    user.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
    windows = []

    @callback_type
    def collect(window, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window) and not user.GetWindow(window, 4):
            windows.append(window)
        return True

    user.EnumWindows(collect, 0)
    if len(windows) != 1:
        raise InputNotReady('Ожидание игрового окна')
    window = windows[0]
    # Do not alter a shortcut while the user is holding another key/button.
    if any(user.GetAsyncKeyState(key) & 0x8000 for key in (1, 2, 4, 0x10, 0x11, 0x12, 0x56, 0x5B, 0x5C)):
        raise InputNotReady('Ожидание завершения ввода')
    if user.IsIconic(window):
        user.ShowWindow(window, 9)  # SW_RESTORE
    if user.GetForegroundWindow() != window:
        user.SetForegroundWindow(window)
        if user.GetForegroundWindow() != window:
            foreground_thread = user.GetWindowThreadProcessId(user.GetForegroundWindow(), None)
            current_thread = kernel.GetCurrentThreadId()
            attached = bool(user.AttachThreadInput(current_thread, foreground_thread, True))
            try:
                user.BringWindowToTop(window)
                user.SetForegroundWindow(window)
            finally:
                if attached:
                    user.AttachThreadInput(current_thread, foreground_thread, False)
        time.sleep(0.25)
    if user.GetForegroundWindow() != window:
        raise InputNotReady('Не удалось активировать игровое окно')

    class MouseInput(ctypes.Structure):
        _fields_ = [('dx', wintypes.LONG), ('dy', wintypes.LONG), ('mouseData', wintypes.DWORD),
                    ('dwFlags', wintypes.DWORD), ('time', wintypes.DWORD), ('dwExtraInfo', ctypes.c_size_t)]

    class KeyboardInput(ctypes.Structure):
        _fields_ = [('wVk', wintypes.WORD), ('wScan', wintypes.WORD), ('dwFlags', wintypes.DWORD),
                    ('time', wintypes.DWORD), ('dwExtraInfo', ctypes.c_size_t)]

    class InputData(ctypes.Union):
        _fields_ = [('mi', MouseInput), ('ki', KeyboardInput)]

    class Input(ctypes.Structure):
        _anonymous_ = ('data',)
        _fields_ = [('type', wintypes.DWORD), ('data', InputData)]

    user.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(Input), ctypes.c_int]
    user.SendInput.restype = wintypes.UINT

    def key(scan, up=False):
        event = Input(type=1, ki=KeyboardInput(wScan=scan, dwFlags=0x0008 | (0x0002 if up else 0)))
        if user.SendInput(1, ctypes.byref(event), ctypes.sizeof(Input)) != 1:
            raise OSError('Windows не приняла клавишу автооткрытия инвентаря')

    # Scan codes keep Alt+V independent of the current keyboard language.
    try:
        key(0x38)  # Left Alt
        time.sleep(0.08)
        if user.GetForegroundWindow() != window:
            raise InputNotReady('Игровое окно потеряло фокус')
        key(0x2F)  # V
        time.sleep(0.12)
    finally:
        try:
            key(0x2F, up=True)
        finally:
            key(0x38, up=True)
    return int(window)


class AutoInventoryOpen:
    """Bound toggles and wait for a verified full ItemList, including an empty one."""

    def __init__(self, opener=None, clock=None):
        self.opener = opener or open_inventory
        self.clock = clock or time.monotonic
        self.attempts = 0
        self.next_attempt = 0
        self.state = 'waiting'
        self.error = None

    def tick(self, pid, inventory, enabled=True):
        if inventory.get('coverage_gap') and self.state == 'received':
            self.state, self.attempts, self.next_attempt = 'waiting', 0, 0
        if inventory.get('full_list_received') and not inventory.get('coverage_gap'):
            self.state, self.error = 'received', None
        elif not enabled:
            return dict(state='disabled', attempts=self.attempts, error=self.error)
        elif self.state not in ('received', 'failed') and self.clock() >= self.next_attempt:
            if self.attempts >= 2:
                self.state = 'failed'
                self.error = 'Полный список предметов не получен после автооткрытия'
            else:
                try:
                    self.opener(pid)
                except InputNotReady as error:
                    self.state, self.error = 'waiting', str(error)
                    self.next_attempt = self.clock() + 3
                except OSError as error:
                    self.state, self.error = 'failed', str(error)
                else:
                    self.attempts += 1
                    self.state, self.error = 'requested', None
                    # If the inventory was already open, the first toggle closes
                    # it. A single second toggle opens it and requests ItemList.
                    self.next_attempt = self.clock() + 20
        return dict(state=self.state, attempts=self.attempts, error=self.error)
