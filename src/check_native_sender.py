"""Check native blob formatting and the thread ABI entirely in Unicorn."""
import hashlib
import json
import struct
from pathlib import Path

from decode_prime_client_native import NativeCipherOracle
from l2_monitor.discovery import select_process
from l2_monitor.live_state import ROOT, load_profile
from sender_abi import call_stub


def main():
    profile = load_profile()
    process, _ = select_process()
    output = ROOT / 'reports/native-sender-preflight'
    output.mkdir(exist_ok=True)
    oracle = NativeCipherOracle([ROOT / p for p in profile['snapshot_dirs']],
        ROOT / profile['runtime_path'], output / 'new-pages', process['pid'])
    results = []
    try:
        uc, xc = oracle.uc, oracle.xc
        format_address, arguments, source = 0x02100100, 0x02100200, 0x02010000
        for body in [b'\x50', bytes.fromhex('7c030000000900000000000000')]:
            uc.mem_write(format_address,b'b\0')
            uc.mem_write(source,body + bytes(32))
            uc.mem_write(arguments,struct.pack('<II',len(body),source))
            uc.mem_write(oracle.stack,struct.pack('<III',oracle.sentinel,format_address,arguments))
            for name in ('EAX','EBX','ECX','EDX','ESI','EDI','EBP'):
                uc.reg_write(getattr(xc,'UC_X86_REG_'+name),0)
            uc.reg_write(xc.UC_X86_REG_EAX,oracle.buffer)
            uc.reg_write(xc.UC_X86_REG_ECX,0x7ffe)
            uc.reg_write(xc.UC_X86_REG_ESP,oracle.stack)
            uc.reg_write(xc.UC_X86_REG_EFLAGS,2)
            oracle.missing_error = None
            uc.emu_start(0x20460cf0,oracle.sentinel,timeout=2_000_000,count=1_000_000)
            if uc.reg_read(xc.UC_X86_REG_EIP) != oracle.sentinel:
                raise ValueError('Formatter did not return: ' + str(oracle.missing_error))
            length = uc.reg_read(xc.UC_X86_REG_EAX)
            actual = bytes(uc.mem_read(oracle.buffer,length))
            if actual != body:
                raise ValueError('Native blob formatting changed bytes')
            results.append(dict(length=length,sha256=hashlib.sha256(actual).hexdigest(),exact_match=True))
        un = oracle.un
        test = un.Uc(un.UC_ARCH_X86,un.UC_MODE_32)
        for address in (0x100000,0x200000,0x300000,0x400000,0x500000):
            test.mem_map(address,4096)
        test.mem_write(0x100000,call_stub(0x200000,0x12340000,0x300000,0x300100,13,0x300008))
        test.mem_write(0x200000,b'\xb8\x78\x56\x34\x12\xc3')
        test.mem_write(0x400f00,struct.pack('<II',0x500000,0))
        test.reg_write(xc.UC_X86_REG_ESP,0x400f00)
        seen = []
        def entry(u,address,size,_):
            if address == 0x200000:
                esp = u.reg_read(xc.UC_X86_REG_ESP)
                seen.append(struct.unpack('<4I',bytes(u.mem_read(esp+4,16))))
        test.hook_add(un.UC_HOOK_CODE,entry)
        test.emu_start(0x100000,0x500000,count=100)
        assert seen == [(0x12340000,0x300000,13,0x300100)], seen
        assert test.reg_read(xc.UC_X86_REG_ESP) == 0x400f08
        assert bytes(test.mem_read(0x300008,4)) == b'\x01\x00\x00\x00'
        report = dict(native_blob_formatter=results,thread_stub_abi_verified=True,
                      execution='Unicorn only',game_process_writes=False,network_sends=False)
        (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n','utf-8')
        print(json.dumps(report))
    finally:
        oracle.close()


if __name__ == '__main__':
    main()
