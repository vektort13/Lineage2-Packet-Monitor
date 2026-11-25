#define UNICODE
#define _UNICODE
#include <windows.h>

struct DropItemInfo { BYTE bytes[136]; };
struct DropPosition { float x, y, z; };
struct DropRequest {
    LONG state;
    DWORD drop, player_position, object_id;
    ULONGLONG amount;
    DropPosition position;
    DWORD exception_code, call_thread;
    LONG result;
    DWORD operation, sent;
    float radius;
    WCHAR command[256];
    DWORD manager_global, hp, max_hp, healing;
    DWORD packet_size;
    BYTE packet[32766];
    DWORD tx_wire_offset, tx_key_offset, tx_wire_before, tx_wire_after;
    BYTE tx_key_before[16];
};
typedef int (__stdcall *ClientDrop)(DropItemInfo, DropPosition);
typedef void (__thiscall *ClientPosition)(void *, void *, DropPosition *);
typedef int (__stdcall *ClientPickup)(DWORD, DropPosition);
typedef void (__thiscall *ClientScript)(void *, void *, void *);
typedef void * (__thiscall *ClientPlayerInfo)(void *);
typedef int (__thiscall *ClientUseItem)(void *, DWORD);
typedef void (__cdecl *ClientPacket)(void *, const char *, ...);

