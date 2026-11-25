#include "tap_bridge.h"

static TapShared *shared = NULL;
static HANDLE mapping = NULL;
static TapCipher original_encrypt = NULL, original_decrypt = NULL;

static void record_packet(void *self, BYTE *body, int size, DWORD direction) {
    TapShared *s = shared;
    if (!s || !s->enabled || (DWORD)(ULONG_PTR)self != s->target_socket) return;
    if (size < 1 || size > TAP_MAX_BODY) { InterlockedIncrement(&s->invalid); return; }
    // Prepare an independent copy before reserving a slot. Concurrent directions
    // never hold a lock while copying a large packet.
    BYTE packet[TAP_MAX_BODY + 2];
    FILETIME now;
    __try {
            *(WORD *)packet = (WORD)(size + 2);
            CopyMemory(packet + 2, body, size);
            if (direction == 0) {
                BYTE *socket = (BYTE *)self;
                BYTE *map = *(BYTE **)(socket + s->opcode_offset + 4);
                DWORD opcode = packet[2];
                if (!map || opcode >= s->opcode_count) RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                packet[2] = map[opcode];
                if (packet[2] == 0xd0) {
                    if (size < 3) RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                    WORD *extended = *(WORD **)(socket + s->extended_offset + 4);
                    WORD index = *(WORD *)(packet + 3);
                    if (!extended || index >= s->extended_count) RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
                    *(WORD *)(packet + 3) = extended[index];
                }
            }
            GetSystemTimeAsFileTime(&now);
    } __except(EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&s->invalid); return; }
    LONG position = 0; bool reserved = false;
    for (int attempt = 0; attempt < 16; ++attempt) {
        position = s->written;
        if ((DWORD)(position - s->consumed) >= TAP_CAPACITY) break;
        if (InterlockedCompareExchange(&s->written, position + 1, position) == position) { reserved = true; break; }
    }
    if (!reserved) { InterlockedIncrement(&s->dropped); return; }
    TapRecord *r = &s->records[(DWORD)position % TAP_CAPACITY];
    r->ready = 0;
    r->sequence = (DWORD)position + 1; r->direction = direction; r->size = size + 2;
    r->filetime = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    CopyMemory(r->bytes, packet, size + 2);
    InterlockedExchange(&r->ready, (LONG)r->sequence);
}

static int __fastcall tap_encrypt(void *self, void *, BYTE *body, BYTE *key, int size) {
    record_packet(self, body, size, 0);
    return original_encrypt(self, body, key, size);
}
static int __fastcall tap_decrypt(void *self, void *, BYTE *body, BYTE *key, int size) {
    int result = original_decrypt(self, body, key, size);
    record_packet(self, body, size, 1);
    return result;
}

static bool replace_slot(DWORD *slot, DWORD expected, DWORD replacement) {
    DWORD protection;
    if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &protection)) return false;
    LONG previous = InterlockedCompareExchange((LONG *)slot, replacement, expected);
    DWORD unused; VirtualProtect(slot, sizeof(DWORD), protection, &unused);
    return (DWORD)previous == expected;
}

static void handle_command() {
    if (!shared) {
        WCHAR name[100]; tap_name(name, GetCurrentProcessId());
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!mapping) return;
        shared = (TapShared *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(TapShared));
        if (!shared) { CloseHandle(mapping); mapping = NULL; return; }
    }
    TapShared *s = shared;
    if (InterlockedCompareExchange(&s->state, 1, 0) != 0) return;
    __try {
        DWORD *table = (DWORD *)(ULONG_PTR)s->vtable;
        if (s->version != 1 || s->encrypt_slot > 255 || s->decrypt_slot > 255 || s->encrypt_slot == s->decrypt_slot)
            RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
        if (s->command == 1) {
            if (*(DWORD *)(ULONG_PTR)s->target_socket != s->vtable || !s->opcode_count || s->opcode_count > 256 || s->extended_count > 65536)
                RaiseException(ERROR_INVALID_DATA, 0, 0, NULL);
            if (table[s->encrypt_slot] != s->encrypt_entry || table[s->decrypt_slot] != s->decrypt_entry)
                RaiseException(ERROR_REVISION_MISMATCH, 0, 0, NULL);
            HMODULE pinned = NULL;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                  (LPCWSTR)(ULONG_PTR)&handle_command, &pinned))
                RaiseException(GetLastError(), 0, 0, NULL);
            original_encrypt = (TapCipher)(ULONG_PTR)s->encrypt_entry;
            original_decrypt = (TapCipher)(ULONG_PTR)s->decrypt_entry;
            if (!replace_slot(table + s->encrypt_slot, s->encrypt_entry, (DWORD)(ULONG_PTR)tap_encrypt))
                RaiseException(ERROR_REVISION_MISMATCH, 0, 0, NULL);
            if (!replace_slot(table + s->decrypt_slot, s->decrypt_entry, (DWORD)(ULONG_PTR)tap_decrypt)) {
                replace_slot(table + s->encrypt_slot, (DWORD)(ULONG_PTR)tap_encrypt, s->encrypt_entry);
                RaiseException(ERROR_REVISION_MISMATCH, 0, 0, NULL);
            }
            InterlockedExchange(&s->enabled, 1);
        } else if (s->command == 2) {
            InterlockedExchange(&s->enabled, 0);
            bool a = replace_slot(table + s->encrypt_slot, (DWORD)(ULONG_PTR)tap_encrypt, s->encrypt_entry);
            bool b = replace_slot(table + s->decrypt_slot, (DWORD)(ULONG_PTR)tap_decrypt, s->decrypt_entry);
            if (!a || !b) RaiseException(ERROR_REVISION_MISMATCH, 0, 0, NULL);
        } else RaiseException(ERROR_INVALID_FUNCTION, 0, 0, NULL);
        InterlockedExchange(&s->state, 2);
    } __except(EXCEPTION_EXECUTE_HANDLER) { s->exception_code = GetExceptionCode(); InterlockedExchange(&s->state, -1); }
}

extern "C" __declspec(dllexport) LRESULT CALLBACK TapMessage(int code, WPARAM wparam, LPARAM lparam) {
    if (code >= 0 && lparam && ((MSG *)lparam)->message == tap_message()) handle_command();
    return CallNextHookEx(NULL, code, wparam, lparam);
}
