#define UNICODE
#define _UNICODE
#include <windows.h>

typedef struct {
    LONG state;
    DWORD length, entry, root_pointer, socket_offset, exception_code;
    BYTE body[32766];
} SendRequest;

typedef void (__cdecl *NativeSend)(void *, const char *, ...);

static void handle_send(void) {
    WCHAR name[100];
    wsprintfW(name, L"Local\\L2PacketMonitor.Send.%lu", GetCurrentProcessId());
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!mapping) return;
    SendRequest *request = (SendRequest *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SendRequest));
    if (!request) { CloseHandle(mapping); return; }
    if (InterlockedCompareExchange(&request->state, 1, 0) == 0) {
        __try {
            if (!request->length || request->length > sizeof(request->body)) {
                request->exception_code = ERROR_INVALID_DATA;
                InterlockedExchange(&request->state, -1);
            } else {
                DWORD root = *(DWORD *)(ULONG_PTR)request->root_pointer;
                void *socket = *(void **)(ULONG_PTR)(root + request->socket_offset);
                if (!root || !socket) {
                    request->exception_code = ERROR_INVALID_ADDRESS;
                    InterlockedExchange(&request->state, -1);
                } else {
                    NativeSend send = (NativeSend)(ULONG_PTR)request->entry;
                    send(socket, "b", request->length, request->body);
                    InterlockedExchange(&request->state, 2);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            request->exception_code = GetExceptionCode();
            InterlockedExchange(&request->state, -1);
        }
    }
    UnmapViewOfFile(request);
    CloseHandle(mapping);
    wsprintfW(name, L"Local\\L2PacketMonitor.Done.%lu", GetCurrentProcessId());
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (event) { SetEvent(event); CloseHandle(event); }
}

/* Runs requested operations on the owner thread's regular message pump. */
__declspec(dllexport) LRESULT CALLBACK ObserveMessage(int code, WPARAM wparam, LPARAM lparam) {
    if (code >= 0 && lparam) {
        const MSG *message = (const MSG *)lparam;
        if (message->message == RegisterWindowMessageW(L"L2PacketMonitor.Probe.1")) {
            WCHAR name[100];
            wsprintfW(name, L"Local\\L2PacketMonitor.Probe.%lu", GetCurrentProcessId());
            HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
            if (event) {
                SetEvent(event);
                CloseHandle(event);
            }
        }
        if (message->message == RegisterWindowMessageW(L"L2PacketMonitor.Send.1")) {
            handle_send();
        }
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}
