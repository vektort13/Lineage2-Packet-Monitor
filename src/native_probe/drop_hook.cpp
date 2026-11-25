#include "drop_bridge.h"
#include <float.h>
#include <math.h>

static void handle_drop() {
    WCHAR name[100];
    wsprintfW(name, L"Local\\L2PacketMonitor.Drop.%lu", GetCurrentProcessId());
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!mapping) return;
    DropRequest *request = (DropRequest *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(DropRequest));
    if (!request) { CloseHandle(mapping); return; }
    if (InterlockedCompareExchange(&request->state, 1, 0) == 0) {
        __try {
            if (request->operation == 8 && request->drop && request->player_position && request->packet_size && request->packet_size <= sizeof(request->packet)) {
                BYTE *root = *(BYTE **)(ULONG_PTR)request->player_position;
                void *socket = root ? *(void **)(root + request->manager_global) : NULL;
                if (!socket) RaiseException(ERROR_NOT_FOUND, 0, 0, NULL);
                if (request->tx_wire_offset && request->tx_key_offset) {
                    if (request->tx_wire_offset > 0x10000 || request->tx_key_offset > 0x10000)
                        RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                    request->tx_wire_before = *(DWORD *)((BYTE *)socket + request->tx_wire_offset);
                    CopyMemory(request->tx_key_before, (BYTE *)socket + request->tx_key_offset, 16);
                }
                request->call_thread = GetCurrentThreadId();
                if (request->packet_size == 1)
                    ((ClientPacket)(ULONG_PTR)request->drop)(socket, "c", (DWORD)request->packet[0]);
                else
                    ((ClientPacket)(ULONG_PTR)request->drop)(socket, "cb", (DWORD)request->packet[0], request->packet_size - 1, request->packet + 1);
                request->sent = 1;
                if (request->tx_wire_offset)
                    request->tx_wire_after = *(DWORD *)((BYTE *)socket + request->tx_wire_offset);
                InterlockedExchange(&request->state, 2);
            } else if (request->operation == 7 && request->drop && request->manager_global && request->object_id) {
                void *manager = *(void **)(ULONG_PTR)request->manager_global;
                if (!manager) RaiseException(ERROR_NOT_FOUND, 0, 0, NULL);
                request->call_thread = GetCurrentThreadId();
                request->result = ((ClientUseItem)(ULONG_PTR)request->drop)(manager, request->object_id);
                request->sent = 1;
                InterlockedExchange(&request->state, 2);
            } else if (request->operation == 6 && request->drop && request->player_position && request->manager_global && request->object_id) {
                void *manager = *(void **)(ULONG_PTR)request->manager_global;
                BYTE *player = manager ? (BYTE *)((ClientPlayerInfo)(ULONG_PTR)request->player_position)(manager) : NULL;
                if (!player) RaiseException(ERROR_NOT_FOUND, 0, 0, NULL);
                request->max_hp = *(DWORD *)(player + 0xb0);
                request->hp = *(DWORD *)(player + 0xb4);
                if (!request->max_hp || request->max_hp > 1000000000 || request->hp > request->max_hp
                    || !_finite(request->position.x) || request->position.x < 1 || request->position.x > 99)
                    RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                request->call_thread = GetCurrentThreadId();
                request->healing = request->hp > 0 && request->hp < request->max_hp
                    && (request->amount || (double)request->hp * 100 < (double)request->max_hp * request->position.x);
                if (request->healing) {
                    request->result = ((ClientUseItem)(ULONG_PTR)request->drop)(manager, request->object_id);
                    request->sent = 1;
                }
                InterlockedExchange(&request->state, 2);
            } else if (request->operation >= 2 && request->operation <= 5 && request->drop) {
                // Original UIScript native handlers, using the client's verified IntConst parser.
                BYTE parameters[520] = {};
                DWORD frame[16] = {};
                if (request->operation == 5) {
                    size_t length = wcsnlen_s(request->command, 256);
                    if (!length || length >= 256 || !request->amount || request->amount > 1000)
                        RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                    parameters[0] = 0x34; // Verified native UnicodeStringConst.
                    CopyMemory(parameters + 1, request->command, (length + 1) * sizeof(WCHAR));
                    parameters[1 + (length + 1) * sizeof(WCHAR)] = 0x16;
                } else if (request->operation == 2) parameters[0] = 0x16;
                else {
                    const DWORD values[] = {request->object_id, (DWORD)request->amount, (DWORD)request->position.x};
                    for (int i = 0; i < 3; ++i) {
                        parameters[i * 5] = 0x1d;
                        CopyMemory(parameters + i * 5 + 1, &values[i], 4);
                    }
                    parameters[15] = 0x16;
                }
                DWORD result = 0;
                request->call_thread = GetCurrentThreadId();
                DWORD repetitions = request->operation == 5 ? (DWORD)request->amount : 1;
                for (DWORD i = 0; i < repetitions; ++i) {
                    frame[3] = (DWORD)(ULONG_PTR)parameters;
                    ((ClientScript)(ULONG_PTR)request->drop)(NULL, frame, &result);
                    ++request->sent;
                }
                request->result = result;
                InterlockedExchange(&request->state, 2);
            } else if (request->operation > 1 || !request->drop || !request->player_position || !request->object_id || !request->amount || request->amount > 0x7fffffffffffffffULL) {
                request->exception_code = ERROR_INVALID_DATA;
                InterlockedExchange(&request->state, -1);
            } else {
                DropItemInfo item = {};
                // POD layout initialized by the observed client constructor.
                *(WORD *)(item.bytes) = 0xffff;
                *(WORD *)(item.bytes + 0x6c) = 0xfffe;
                *(WORD *)(item.bytes + 0x58) = 1;
                for (int i = 0; i < 4; ++i) {
                    const int offsets[] = {0x3c, 0x50, 0x7c, 0x80};
                    *(DWORD *)(item.bytes + offsets[i]) = 0xffffffff;
                }
                *(DWORD *)(item.bytes + 4) = request->object_id;
                *(ULONGLONG *)(item.bytes + 16) = request->amount;
                BYTE end_parameters[] = {0x16, 0, 0, 0};
                DWORD frame[16] = {};
                frame[3] = (DWORD)(ULONG_PTR)end_parameters;
                DropPosition offset = request->position;
                ((ClientPosition)(ULONG_PTR)request->player_position)(NULL, frame, &request->position);
                if (!_finite(request->position.x) || !_finite(request->position.y) || !_finite(request->position.z)
                    || fabs(request->position.x) > 10000000 || fabs(request->position.y) > 10000000 || fabs(request->position.z) > 10000000)
                    RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                request->call_thread = GetCurrentThreadId();
                if (request->operation == 1) {
                    float dx = request->position.x - offset.x, dy = request->position.y - offset.y;
                    if (dx * dx + dy * dy <= request->radius * request->radius && fabs(request->position.z - offset.z) <= 200) {
                        request->result = ((ClientPickup)(ULONG_PTR)request->drop)(request->object_id, request->position);
                        request->sent = 1;
                    }
                } else {
                    request->position.x += offset.x;
                    request->position.y += offset.y;
                    request->position.z += offset.z;
                    request->result = ((ClientDrop)(ULONG_PTR)request->drop)(item, request->position);
                    request->sent = 1;
                }
                InterlockedExchange(&request->state, 2);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            request->exception_code = GetExceptionCode();
            InterlockedExchange(&request->state, -1);
        }
    }
    UnmapViewOfFile(request);
    CloseHandle(mapping);
    wsprintfW(name, L"Local\\L2PacketMonitor.DropDone.%lu", GetCurrentProcessId());
    HANDLE done = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (done) { SetEvent(done); CloseHandle(done); }
}

extern "C" __declspec(dllexport) LRESULT CALLBACK DropMessage(int code, WPARAM wparam, LPARAM lparam) {
    if (code >= 0 && lparam && ((MSG *)lparam)->message == RegisterWindowMessageW(L"L2PacketMonitor.Drop.1"))
        handle_drop();
    return CallNextHookEx(NULL, code, wparam, lparam);
}

