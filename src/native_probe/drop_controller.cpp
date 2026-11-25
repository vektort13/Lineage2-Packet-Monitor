#include "drop_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdarg.h>

static int __stdcall mock_drop(DropItemInfo item, DropPosition position) {
    printf("mock-drop %lu %llu %.0f %.0f %.0f %lu\n", *(DWORD *)(item.bytes + 4),
           *(ULONGLONG *)(item.bytes + 16), position.x, position.y, position.z, GetCurrentThreadId());
    fflush(stdout);
    return 1;
}
static void __stdcall mock_position(void *, DropPosition *position) { position->x = 100; position->y = 200; position->z = 300; }
static int __stdcall mock_pickup(DWORD oid, DropPosition position) {
    printf("mock-pickup %lu %.0f %.0f %.0f\n", oid, position.x, position.y, position.z);
    fflush(stdout);
    return 1;
}
static void __stdcall mock_skill(void *frame, void *) {
    BYTE *code = (BYTE *)(ULONG_PTR)((DWORD *)frame)[3];
    if (code[0] == 0x16) printf("mock-skills list\n");
    else if (code[0] == 0x34) printf("mock-bypass %ls\n", (WCHAR *)(code + 1));
    else if (code[0] == 0x1d && code[5] == 0x1d && code[10] == 0x1d && code[15] == 0x16)
        printf("mock-skills %lu %lu %lu\n", *(DWORD *)(code+1), *(DWORD *)(code+6), *(DWORD *)(code+11));
    else RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
    fflush(stdout);
}
static DWORD mock_player[64] = {};
static BYTE mock_socket[128] = {};
static DWORD mock_manager = (DWORD)(ULONG_PTR)mock_socket;
static DWORD mock_root = (DWORD)(ULONG_PTR)&mock_manager;
static void __cdecl mock_packet(void *socket, const char *format, ...) {
    va_list args;
    va_start(args, format);
    DWORD opcode = va_arg(args, DWORD);
    DWORD size = 0, digest = (2166136261U ^ opcode) * 16777619U;
    BYTE *body = NULL;
    if (!strcmp(format, "cb")) {
        size = va_arg(args, DWORD);
        body = va_arg(args, BYTE *);
        for (DWORD i = 0; i < size; ++i) digest = (digest ^ body[i]) * 16777619U;
    } else if (strcmp(format, "c")) RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
    *(DWORD *)(mock_socket + 64) += size + 3;
    if (size > 255) printf("mock-packet-size %lu %08lx\n", size + 1, digest);
    else {
        printf("mock-packet %02x", opcode);
        for (DWORD i = 0; i < size; ++i) printf("%02x", body[i]);
        printf("\n");
    }
    fflush(stdout);
    va_end(args);
}
static void * __stdcall mock_player_info() { return mock_player; }
static int __stdcall mock_heal(DWORD oid) {
    printf("mock-heal %lu %lu\n", oid, mock_player[0xb4 / 4]);
    fflush(stdout);
    mock_player[0xb4 / 4] += 12;
    if (mock_player[0xb4 / 4] > 100) mock_player[0xb4 / 4] = 100;
    return 1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && !wcscmp(argv[1], L"--target")) {
        for (int i = 0; i < 16; ++i) mock_socket[80+i] = (BYTE)(0x30+i);
        MSG message;
        PeekMessageW(&message, NULL, WM_USER, WM_USER, PM_NOREMOVE);
        mock_player[0xb0 / 4] = 100;
        mock_player[0xb4 / 4] = 79;
        printf("%lu %lu %p %p %p %p %p %p %p %p %p\n", GetCurrentProcessId(), GetCurrentThreadId(), mock_drop, mock_position, mock_pickup, mock_skill, mock_player_info, mock_heal, &mock_manager, mock_packet, &mock_root);
        fflush(stdout);
        while (GetMessageW(&message, NULL, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
        return 0;
    }
    if (argc != 11 && argc != 13 && argc != 15) return 2;
    DWORD pid = wcstoul(argv[1], NULL, 10), tid = wcstoul(argv[2], NULL, 10);
    WCHAR name[100];
    wsprintfW(name, L"Local\\L2PacketMonitor.DropLock.%lu", pid);
    HANDLE lock = CreateMutexW(NULL, TRUE, name);
    if (!lock || GetLastError() == ERROR_ALREADY_EXISTS) { if (lock) CloseHandle(lock); return 3; }
    wsprintfW(name, L"Local\\L2PacketMonitor.Drop.%lu", pid);
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(DropRequest), name);
    if (!mapping || GetLastError() == ERROR_ALREADY_EXISTS) { if (mapping) CloseHandle(mapping); CloseHandle(lock); return 4; }
    DropRequest *request = (DropRequest *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(DropRequest));
    if (!request) { CloseHandle(mapping); CloseHandle(lock); return 5; }
    ZeroMemory(request, sizeof(*request));
    request->drop = wcstoul(argv[4], NULL, 0);
    request->player_position = wcstoul(argv[5], NULL, 0);
    request->object_id = wcstoul(argv[6], NULL, 10);
    request->amount = _wcstoui64(argv[7], NULL, 10);
    request->position.x = (float)_wtof(argv[8]);
    request->position.y = (float)_wtof(argv[9]);
    request->position.z = (float)_wtof(argv[10]);
    if (argc == 13 && !wcscmp(argv[11], L"pickup")) {
        request->operation = 1;
        request->radius = (float)_wtof(argv[12]);
    }
    if (argc == 13 && !wcscmp(argv[11], L"skill")) request->operation = wcstoul(argv[12], NULL, 10);
    if (argc == 13 && !wcscmp(argv[11], L"bypass")) {
        request->operation = 5;
        wcsncpy_s(request->command, argv[12], _TRUNCATE);
    }
    if (argc == 13 && !wcscmp(argv[11], L"heal")) {
        request->operation = 6;
        request->manager_global = wcstoul(argv[12], NULL, 0);
    }
    if (argc == 13 && !wcscmp(argv[11], L"use-item")) {
        request->operation = 7;
        request->manager_global = wcstoul(argv[12], NULL, 0);
    }
    if ((argc == 13 || argc == 15) && !wcscmp(argv[11], L"packet")) {
        request->operation = 8;
        request->manager_global = wcstoul(argv[12], NULL, 0);
        if (argc == 15) {
            request->tx_wire_offset = wcstoul(argv[13], NULL, 0);
            request->tx_key_offset = wcstoul(argv[14], NULL, 0);
        }
        int hi, lo;
        while ((hi = getchar()) != EOF && hi != '\n' && hi != '\r') {
            lo = getchar();
            if (hi >= '0' && hi <= '9') hi -= '0';
            else if (hi >= 'a' && hi <= 'f') hi -= 'a' - 10;
            else return 6;
            if (lo >= '0' && lo <= '9') lo -= '0';
            else if (lo >= 'a' && lo <= 'f') lo -= 'a' - 10;
            else return 6;
            if (request->packet_size >= sizeof(request->packet)) return 6;
            request->packet[request->packet_size++] = (BYTE)((hi << 4) | lo);
        }
    }
    wsprintfW(name, L"Local\\L2PacketMonitor.DropDone.%lu", pid);
    HANDLE done = CreateEventW(NULL, TRUE, FALSE, name);
    HMODULE module = LoadLibraryW(argv[3]);
    HOOKPROC proc = module ? (HOOKPROC)GetProcAddress(module, "_DropMessage@12") : NULL;
    HHOOK hook = done && proc ? SetWindowsHookExW(WH_GETMESSAGE, proc, module, tid) : NULL;
    DWORD wait = WAIT_FAILED;
    if (hook && PostThreadMessageW(tid, RegisterWindowMessageW(L"L2PacketMonitor.Drop.1"), 0, 0))
        wait = WaitForSingleObject(done, 5000);
    LONG state = InterlockedCompareExchange(&request->state, 0, 0);
    printf("{\"state\":%ld,\"exception\":%lu,\"wait\":%lu,\"thread\":%lu,\"result\":%ld,\"sent\":%lu,\"hp\":%lu,\"max_hp\":%lu,\"healing\":%lu,\"destination\":[%.3f,%.3f,%.3f]",
           state, request->exception_code, wait, request->call_thread, request->result,
           request->sent,
           request->hp, request->max_hp, request->healing,
           request->position.x, request->position.y, request->position.z);
    if (request->tx_wire_offset && request->tx_key_offset) {
        printf(",\"tx_wire_before\":%lu,\"tx_wire_after\":%lu,\"tx_key_before\":\"", request->tx_wire_before, request->tx_wire_after);
        for (int i = 0; i < 16; ++i) printf("%02x", request->tx_key_before[i]);
        printf("\"");
    }
    printf("}\n");
    if (hook) UnhookWindowsHookEx(hook);
    if (module) FreeLibrary(module);
    if (done) CloseHandle(done);
    UnmapViewOfFile(request); CloseHandle(mapping); CloseHandle(lock);
    return wait == WAIT_OBJECT_0 && state == 2 ? 0 : 9;
}

