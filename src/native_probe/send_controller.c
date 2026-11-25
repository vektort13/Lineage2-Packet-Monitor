#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef struct {
    LONG state;
    DWORD length, entry, root_pointer, socket_offset, exception_code;
    BYTE body[32766];
} SendRequest;

static int nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 7) {
        fwprintf(stderr, L"usage: send_controller pid tid dll entry root offset\n");
        return 2;
    }
    DWORD pid = wcstoul(argv[1], NULL, 10), thread = wcstoul(argv[2], NULL, 10);
    WCHAR name[100];
    wsprintfW(name, L"Local\\L2PacketMonitor.Lock.%lu", pid);
    HANDLE lock = CreateMutexW(NULL, TRUE, name);
    if (!lock || GetLastError() == ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"Another send is in progress\n"); if (lock) CloseHandle(lock); return 3;
    }
    wsprintfW(name, L"Local\\L2PacketMonitor.Send.%lu", pid);
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SendRequest), name);
    if (!mapping || GetLastError() == ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"CreateFileMapping: %lu\n", GetLastError()); if (mapping) CloseHandle(mapping); CloseHandle(lock); return 4;
    }
    SendRequest *request = (SendRequest *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SendRequest));
    if (!request) { fwprintf(stderr, L"MapViewOfFile: %lu\n", GetLastError()); CloseHandle(mapping); CloseHandle(lock); return 5; }
    ZeroMemory(request, sizeof(*request));
    request->entry = wcstoul(argv[4], NULL, 0);
    request->root_pointer = wcstoul(argv[5], NULL, 0);
    request->socket_offset = wcstoul(argv[6], NULL, 0);
    int first, second;
    while ((first = getchar()) != EOF && first != '\n' && first != '\r') {
        second = getchar();
        int hi = nibble(first), lo = nibble(second);
        if (hi < 0 || lo < 0 || request->length >= sizeof(request->body)) {
            fwprintf(stderr, L"Invalid payload\n"); UnmapViewOfFile(request); CloseHandle(mapping); CloseHandle(lock); return 6;
        }
        request->body[request->length++] = (BYTE)((hi << 4) | lo);
    }
    if (!request->length) { fwprintf(stderr, L"Empty payload\n"); UnmapViewOfFile(request); CloseHandle(mapping); CloseHandle(lock); return 6; }
    wsprintfW(name, L"Local\\L2PacketMonitor.Done.%lu", pid);
    HANDLE done = CreateEventW(NULL, TRUE, FALSE, name);
    HMODULE module = LoadLibraryW(argv[3]);
    if (!done || !module) {
        fwprintf(stderr, L"CreateEvent/LoadLibrary: %lu\n", GetLastError());
        if (done) CloseHandle(done); if (module) FreeLibrary(module);
        UnmapViewOfFile(request); CloseHandle(mapping); CloseHandle(lock); return 7;
    }
    HOOKPROC proc = (HOOKPROC)GetProcAddress(module, "_ObserveMessage@12");
    HHOOK hook = proc ? SetWindowsHookExW(WH_GETMESSAGE, proc, module, thread) : NULL;
    if (!hook) {
        fwprintf(stderr, L"SetWindowsHookEx: %lu\n", GetLastError());
        FreeLibrary(module); CloseHandle(done); UnmapViewOfFile(request); CloseHandle(mapping); CloseHandle(lock); return 8;
    }
    UINT message = RegisterWindowMessageW(L"L2PacketMonitor.Send.1");
    int posted = message && PostThreadMessageW(thread, message, 0, 0);
    DWORD wait = posted ? WaitForSingleObject(done, 5000) : WAIT_FAILED;
    LONG state = InterlockedCompareExchange(&request->state, 0, 0);
    DWORD error = request->exception_code;
    wprintf(L"state=%ld exception=%lu wait=%lu\n", state, error, wait);
    UnhookWindowsHookEx(hook);
    FreeLibrary(module);
    CloseHandle(done);
    UnmapViewOfFile(request);
    CloseHandle(mapping);
    CloseHandle(lock);
    return wait == WAIT_OBJECT_0 && state == 2 ? 0 : 9;
}
