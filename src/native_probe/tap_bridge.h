#define UNICODE
#define _UNICODE
#include <windows.h>

const DWORD TAP_CAPACITY = 128, TAP_MAX_BODY = 32766;
struct TapRecord {
    volatile LONG ready;
    DWORD sequence, direction, size;
    ULONGLONG filetime;
    BYTE bytes[TAP_MAX_BODY + 2];
};
struct TapShared {
    DWORD version, owner, target_socket, vtable, encrypt_slot, decrypt_slot;
    DWORD encrypt_entry, decrypt_entry, opcode_offset, opcode_count, extended_offset, extended_count;
    volatile LONG command, state, enabled, producer_lock, written, consumed, dropped, invalid, exception_code;
    TapRecord records[TAP_CAPACITY];
};
typedef int (__thiscall *TapCipher)(void *, BYTE *, BYTE *, int);
inline UINT tap_message() { return RegisterWindowMessageW(L"L2PacketMonitor.PlaintextTap.1"); }
inline void tap_name(WCHAR *name, DWORD pid) { wsprintfW(name, L"Local\\L2PacketMonitor.PlaintextTap.%lu", pid); }
