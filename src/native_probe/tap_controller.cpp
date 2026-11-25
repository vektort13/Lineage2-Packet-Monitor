#include "tap_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static DWORD mock_table[40] = {};
static BYTE mock_socket[256] = {}, other_socket[256] = {}, primary[209] = {};
static WORD extended[152] = {};
static DWORD encrypt_calls = 0, decrypt_calls = 0;
static int __fastcall mock_encrypt(void *, void *, BYTE *body, BYTE *key, int size) {
    ++encrypt_calls; ++key[0]; for (int i=0;i<size;++i) body[i] ^= 0xa5; return 77;
}
static int __fastcall mock_decrypt(void *, void *, BYTE *body, BYTE *key, int size) {
    ++decrypt_calls; ++key[0]; for (int i=0;i<size;++i) body[i] ^= 0xa5; return 88;
}
static bool mock_call(BYTE *socket, bool decrypt, BYTE *body, int size, int expected) {
    BYTE key[17] = {}, original[16] = {}; CopyMemory(original,body,size);
    TapCipher function = (TapCipher)(ULONG_PTR)mock_table[decrypt ? 32 : 31];
    int result = function(socket,body,key,size);
    bool ok = result == expected && key[0] == 1;
    for(int i=0;i<size;++i) ok = ok && body[i] == (BYTE)(original[i]^0xa5);
    return ok;
}
struct ConcurrentArgs { HANDLE go; bool decrypt; };
static DWORD WINAPI concurrent_calls(void *parameter) {
    ConcurrentArgs *args=(ConcurrentArgs *)parameter;
    if(WaitForSingleObject(args->go,5000)!=WAIT_OBJECT_0)return 1;
    BYTE body[TAP_MAX_BODY],key[17];
    for(int iteration=0;iteration<50;++iteration){
        FillMemory(body,sizeof(body),args->decrypt?(0x11^0xa5):0x11);
        body[0]=args->decrypt?(0x47^0xa5):5;ZeroMemory(key,sizeof(key));
        TapCipher function=(TapCipher)(ULONG_PTR)mock_table[args->decrypt?32:31];
        if(function(mock_socket,body,key,sizeof(body))!=(args->decrypt?88:77)||key[0]!=1)return 2;
        if(body[0]!=(args->decrypt?0x47:(5^0xa5)))return 3;
        for(int i=1;i<TAP_MAX_BODY;++i)if(body[i]!=(args->decrypt?0x11:(0x11^0xa5)))return 4;
    }
    return 0;
}
static int mock_target() {
    for(int i=0;i<209;++i) primary[i]=(BYTE)i;
    primary[5]=0x50; primary[0x50]=5; primary[6]=0xd0; primary[0xd0]=6;
    for(int i=0;i<152;++i) extended[i]=(WORD)i;
    extended[3]=18; extended[18]=3;
    *(DWORD *)mock_socket=(DWORD)(ULONG_PTR)mock_table;
    *(DWORD *)other_socket=(DWORD)(ULONG_PTR)mock_table;
    *(DWORD *)(mock_socket+68)=(DWORD)(ULONG_PTR)primary;
    *(DWORD *)(mock_socket+84)=(DWORD)(ULONG_PTR)extended;
    mock_table[31]=(DWORD)(ULONG_PTR)mock_encrypt;mock_table[32]=(DWORD)(ULONG_PTR)mock_decrypt;
    MSG message; PeekMessageW(&message,NULL,WM_USER,WM_USER,PM_NOREMOVE);
    printf("%lu %lu %p %p %p %p\n",GetCurrentProcessId(),GetCurrentThreadId(),mock_socket,mock_table,mock_encrypt,mock_decrypt);fflush(stdout);
    while(GetMessageW(&message,NULL,0,0)>0) {
        if(message.message==WM_APP+1) {
            BYTE a[]={5,0x11},b[]={6,3,0,0x22},c[]={0x47^0xa5,0x11^0xa5,0x22^0xa5},d[]={5};
            bool ok=mock_call(mock_socket,false,a,sizeof(a),77);
            ok=mock_call(mock_socket,false,b,sizeof(b),77)&&ok;
            ok=mock_call(mock_socket,true,c,sizeof(c),88)&&ok;
            ok=mock_call(other_socket,false,d,sizeof(d),77)&&ok;
            printf("{\"passed\":%s,\"encrypt_calls\":%lu,\"decrypt_calls\":%lu}\n",ok?"true":"false",encrypt_calls,decrypt_calls);fflush(stdout);
        } else if(message.message==WM_APP+2) {
            bool restored=mock_table[31]==(DWORD)(ULONG_PTR)mock_encrypt&&mock_table[32]==(DWORD)(ULONG_PTR)mock_decrypt;
            BYTE a[]={5}; bool ok=mock_call(mock_socket,false,a,sizeof(a),77);
            printf("{\"restored\":%s,\"passed\":%s}\n",restored?"true":"false",ok?"true":"false");fflush(stdout);
        } else if(message.message==WM_APP+3) {
            bool ok=true;for(int i=0;i<140;++i){BYTE a[]={5};ok=mock_call(mock_socket,false,a,sizeof(a),77)&&ok;}
            printf("{\"passed\":%s}\n",ok?"true":"false");fflush(stdout);
        } else if(message.message==WM_APP+4) {
            HANDLE go=CreateEventW(NULL,TRUE,FALSE,NULL);
            ConcurrentArgs args[2]={{go,false},{go,true}};
            HANDLE threads[2]={CreateThread(NULL,0,concurrent_calls,args,0,NULL),CreateThread(NULL,0,concurrent_calls,args+1,0,NULL)};
            SetEvent(go);bool ok=WaitForMultipleObjects(2,threads,TRUE,10000)==WAIT_OBJECT_0;
            for(int i=0;i<2;++i){DWORD code=1;GetExitCodeThread(threads[i],&code);ok=ok&&code==0;CloseHandle(threads[i]);}
            CloseHandle(go);
            printf("{\"passed\":%s}\n",ok?"true":"false");fflush(stdout);
        } else {TranslateMessage(&message);DispatchMessageW(&message);}
    }
    return 0;
}
static bool command(TapShared *s,DWORD tid,LONG value) {
    s->command=value;s->exception_code=0;InterlockedExchange(&s->state,0);
    if(!PostThreadMessageW(tid,tap_message(),0,0))return false;
    ULONGLONG deadline=GetTickCount64()+5000;
    while(s->state==0||s->state==1){if(GetTickCount64()>deadline)return false;Sleep(2);}
    return s->state==2;
}
static void print_records(TapShared *s) {
    LONG end=s->written, start=s->consumed;bool first=true;
    printf("{\"packets\":[");
    while(start!=end){
        TapRecord *r=&s->records[(DWORD)start%TAP_CAPACITY];
        if((DWORD)r->ready!=(DWORD)start+1||r->size<3||r->size>TAP_MAX_BODY+2)break;
        printf("%s{\"direction\":\"%s\",\"sequence\":%lu,\"timestamp\":%.7f,\"raw_hex\":\"",first?"":",",r->direction?"server":"client",r->sequence,(double)r->filetime/10000000.0-11644473600.0);
        for(DWORD i=0;i<r->size;++i)printf("%02x",r->bytes[i]);
        printf("\"}");first=false;++start;
    }
    InterlockedExchange(&s->consumed,start);
    printf("],\"written\":%lu,\"consumed\":%lu,\"dropped\":%lu,\"invalid\":%lu,\"active\":%s}\n",(DWORD)s->written,(DWORD)s->consumed,(DWORD)s->dropped,(DWORD)s->invalid,s->enabled?"true":"false");fflush(stdout);
}
int wmain(int argc,wchar_t **argv) {
    if(argc==2&&!wcscmp(argv[1],L"--target"))return mock_target();
    if(argc!=14)return 2;
    DWORD pid=wcstoul(argv[1],NULL,0),tid=wcstoul(argv[2],NULL,0);
    WCHAR name[120];wsprintfW(name,L"Local\\L2PacketMonitor.TapLock.%lu",pid);
    HANDLE lock=CreateMutexW(NULL,TRUE,name);
    if(!lock||GetLastError()==ERROR_ALREADY_EXISTS){if(lock)CloseHandle(lock);return 3;}
    tap_name(name,pid);
    HANDLE mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(TapShared),name);
    TapShared *s=mapping?(TapShared *)MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(TapShared)):NULL;
    if(!s){if(mapping)CloseHandle(mapping);CloseHandle(lock);return 4;}
    // A previous clean detach leaves the pinned DLL's view alive; reuse it only while disabled.
    if(s->enabled){UnmapViewOfFile(s);CloseHandle(mapping);CloseHandle(lock);return 5;}
    ZeroMemory(s,sizeof(*s));s->version=1;s->owner=GetCurrentProcessId();
    DWORD *fields[]={&s->target_socket,&s->vtable,&s->encrypt_slot,&s->decrypt_slot,&s->encrypt_entry,&s->decrypt_entry,&s->opcode_offset,&s->opcode_count,&s->extended_offset,&s->extended_count};
    for(int i=0;i<10;++i)*fields[i]=wcstoul(argv[i+4],NULL,0);
    HMODULE module=LoadLibraryW(argv[3]);
    HOOKPROC proc=module?(HOOKPROC)GetProcAddress(module,"_TapMessage@12"):NULL;
    HHOOK hook=proc?SetWindowsHookExW(WH_GETMESSAGE,proc,module,tid):NULL;
    const char *stage=!module?"load-library":!proc?"find-export":!hook?"install-hook":"post-command";
    bool started=hook&&command(s,tid,1);
    DWORD start_error=started?ERROR_SUCCESS:GetLastError();
    printf("{\"started\":%s,\"state\":%ld,\"exception\":%lu,\"win32_error\":%lu,\"stage\":\"%s\"}\n",started?"true":"false",s->state,(DWORD)s->exception_code,start_error,stage);fflush(stdout);
    if(started){
        char line[32];
        while(fgets(line,sizeof(line),stdin)){
            if(!strncmp(line,"read",4))print_records(s);
            else if(!strncmp(line,"close",5))break;
            else{printf("{\"error\":\"Unknown tap command\"}\n");fflush(stdout);}
        }
    }
    bool detached=!started||command(s,tid,2);
    printf("{\"closed\":%s,\"state\":%ld,\"exception\":%lu}\n",detached?"true":"false",s->state,(DWORD)s->exception_code);fflush(stdout);
    if(hook)UnhookWindowsHookEx(hook);if(module)FreeLibrary(module);
    UnmapViewOfFile(s);CloseHandle(mapping);CloseHandle(lock);
    return started&&detached?0:9;
}
