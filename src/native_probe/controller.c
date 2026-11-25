#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdarg.h>

typedef LRESULT (CALLBACK *HookProc)(int, WPARAM, LPARAM);
static BYTE test_root[128];
static void *test_root_pointer = test_root;
static volatile LONG test_calls;

static void __cdecl test_send(void *socket, const char *format, ...) {
    va_list args;
    va_start(args, format);
    unsigned int size = va_arg(args, unsigned int);
    BYTE *body = va_arg(args, BYTE *);
    if (socket == test_root && format[0] == 'b' && size == 1 && body[0] == 0x50)
        InterlockedIncrement(&test_calls);
    va_end(args);
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--module-base") == 0) {
        HMODULE module = LoadLibraryW(argv[2]);
        if (!module) { fwprintf(stderr, L"LoadLibrary: %lu\n", GetLastError()); return 1; }
        wprintf(L"%p\n", module);
        FreeLibrary(module);
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--target") == 0) {
        MSG msg;
        *(void **)(test_root + 72) = test_root;
        PeekMessageW(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);
        wprintf(L"%lu %lu %p %p\n", GetCurrentProcessId(), GetCurrentThreadId(), test_send, &test_root_pointer);
        fflush(stdout);
        while (GetMessageW(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (InterlockedExchange(&test_calls, 0)) { wprintf(L"mock-called\n"); fflush(stdout); }
        }
        return 0;
    }
    if (argc != 4) {
        fwprintf(stderr, L"usage: controller <pid> <thread-id> <probe.dll>\n");
        return 2;
    }
    DWORD pid = wcstoul(argv[1], NULL, 10);
    DWORD thread = wcstoul(argv[2], NULL, 10);
    WCHAR name[100];
    wsprintfW(name, L"Local\\L2PacketMonitor.Probe.%lu", pid);
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, name);
    if (!event) { fwprintf(stderr, L"CreateEvent: %lu\n", GetLastError()); return 3; }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"Probe already active\n"); CloseHandle(event); return 4;
    }
    HMODULE module = LoadLibraryW(argv[3]);
    if (!module) { fwprintf(stderr, L"LoadLibrary: %lu\n", GetLastError()); CloseHandle(event); return 5; }
    HookProc hook_proc = (HookProc)GetProcAddress(module, "_ObserveMessage@12");
    if (!hook_proc) { fwprintf(stderr, L"GetProcAddress: %lu\n", GetLastError()); FreeLibrary(module); CloseHandle(event); return 6; }
    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, hook_proc, module, thread);
    if (!hook) { fwprintf(stderr, L"SetWindowsHookEx: %lu\n", GetLastError()); FreeLibrary(module); CloseHandle(event); return 7; }
    UINT message = RegisterWindowMessageW(L"L2PacketMonitor.Probe.1");
    if (!message || !PostThreadMessageW(thread, message, 0, 0)) {
        fwprintf(stderr, L"PostThreadMessage: %lu\n", GetLastError());
        UnhookWindowsHookEx(hook); FreeLibrary(module); CloseHandle(event); return 8;
    }
    DWORD wait = WaitForSingleObject(event, 5000);
    wprintf(L"%ls\n", wait == WAIT_OBJECT_0 ? L"observed" : L"not-observed");
    UnhookWindowsHookEx(hook);
    FreeLibrary(module);
    CloseHandle(event);
    return wait == WAIT_OBJECT_0 ? 0 : 9;
}
