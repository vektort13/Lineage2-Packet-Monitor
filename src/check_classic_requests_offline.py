"""Verify retained client c/cb request formatting in isolated Unicorn memory.

The original formatter and embedded jump tables are executed unchanged. Its
external memcpy dependency is an explicitly declared bounded cdecl copy stub.
This checks serialization only, without invoking a game, sender or network.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRY = 0x203d5e30
COPY = 0x2017ac50
SENTINEL = 0x01000000
OUTPUT = 0x02000100
FORMAT = 0x02100100
ARGUMENTS = 0x02100200
SOURCE = 0x02100300
STACK = 0x02208000
SNAPSHOT_SHA256 = '56930e9f96cca46e4fe38db6cf8f8d9105abad1c586fb366e4c3256b73fd3c5f'


class Formatter:
    def __init__(self, snapshot, runtime):
        code = snapshot.read_bytes()
        if len(code) != 704 or hashlib.sha256(code).hexdigest() != SNAPSHOT_SHA256:
            raise ValueError('retained formatter snapshot identity changed')
        sys.path.insert(0, str(runtime))
        import unicorn
        from unicorn import x86_const
        self.xc = x86_const
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        for address, size in ((ENTRY & ~4095, 8192), (COPY & ~4095, 4096),
                              (SENTINEL, 4096), (OUTPUT & ~4095, 65536),
                              (FORMAT & ~4095, 65536), (STACK & ~65535, 65536)):
            self.uc.mem_map(address, size)
        self.uc.mem_write(ENTRY, code)
        self.uc.mem_write(COPY, b'\xc3')
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self._copy, begin=COPY, end=COPY)
        self.copy_calls = 0
        self.capacity = self.source_size = 0

    def _copy(self, uc, address, size, data):
        esp = uc.reg_read(self.xc.UC_X86_REG_ESP)
        ret, destination, source, count = struct.unpack('<4I', bytes(uc.mem_read(esp, 16)))
        if not (OUTPUT <= destination <= destination + count <= OUTPUT + self.capacity and
                SOURCE <= source <= source + count <= SOURCE + self.source_size):
            raise ValueError('formatter memcpy escaped the declared source/destination bounds')
        uc.mem_write(destination, bytes(uc.mem_read(source, count)))
        uc.reg_write(self.xc.UC_X86_REG_EAX, destination)
        uc.reg_write(self.xc.UC_X86_REG_ESP, esp + 4)  # Caller owns three args.
        uc.reg_write(self.xc.UC_X86_REG_EIP, ret)
        self.copy_calls += 1

    def verify(self, body, capacity, stack_offset):
        uc, xc = self.uc, self.xc
        self.capacity, self.source_size = capacity, len(body) - 1
        fmt = b'c\0' if len(body) == 1 else b'cb\0'
        tail = body[1:]
        uc.mem_write(OUTPUT - 32, b'\xa5' * (32766 + 64))
        uc.mem_write(SOURCE - 16, b'\x5a' * (len(tail) + 32))
        if tail:
            uc.mem_write(SOURCE, tail)
        uc.mem_write(FORMAT, fmt)
        args = struct.pack('<3I', body[0], len(tail), SOURCE)
        uc.mem_write(ARGUMENTS, args)
        stack = STACK + stack_offset
        uc.mem_write(stack, struct.pack('<3I', SENTINEL, FORMAT, ARGUMENTS))
        preserved = dict(EBX=0x11223344, ESI=0x55667788, EDI=0x12345678, EBP=0x23456789)
        for name, value in preserved.items():
            uc.reg_write(getattr(xc, 'UC_X86_REG_' + name), value)
        uc.reg_write(xc.UC_X86_REG_EDX, 0)
        uc.reg_write(xc.UC_X86_REG_EAX, OUTPUT)
        uc.reg_write(xc.UC_X86_REG_ECX, capacity)
        uc.reg_write(xc.UC_X86_REG_ESP, stack)
        uc.reg_write(xc.UC_X86_REG_EFLAGS, 2)
        previous_copies = self.copy_calls
        uc.emu_start(ENTRY, SENTINEL, timeout=1_000_000, count=100_000)
        if uc.reg_read(xc.UC_X86_REG_EIP) != SENTINEL:
            raise ValueError('formatter did not return')
        if uc.reg_read(xc.UC_X86_REG_ESP) != stack + 4:
            raise ValueError('formatter changed its cdecl stack convention')
        for name, value in preserved.items():
            if uc.reg_read(getattr(xc, 'UC_X86_REG_' + name)) != value:
                raise ValueError('formatter changed preserved register ' + name)
        if (bytes(uc.mem_read(OUTPUT - 32, 32)) != b'\xa5' * 32 or
                bytes(uc.mem_read(OUTPUT + capacity, 32)) != b'\xa5' * 32):
            raise ValueError('formatter wrote outside output capacity')
        if (bytes(uc.mem_read(SOURCE - 16, 16)) != b'\x5a' * 16 or
                bytes(uc.mem_read(SOURCE, len(tail))) != tail or
                bytes(uc.mem_read(SOURCE + len(tail), 16)) != b'\x5a' * 16 or
                bytes(uc.mem_read(ARGUMENTS, len(args))) != args or
                bytes(uc.mem_read(FORMAT, len(fmt))) != fmt):
            raise ValueError('formatter mutated input bytes or source guards')
        result_length = uc.reg_read(xc.UC_X86_REG_EAX)
        if capacity >= len(body):
            if result_length != len(body) or bytes(uc.mem_read(OUTPUT, result_length)) != body:
                raise ValueError('formatter output does not reproduce expected request bytes')
            if bytes(uc.mem_read(OUTPUT + result_length, 32)) != b'\xa5' * 32:
                raise ValueError('formatter overwrote suffix after actual output')
            expected_copies = int(bool(tail))
        else:
            if result_length != 0:
                raise ValueError('formatter did not reject insufficient capacity')
            expected_copies = 0
        if self.copy_calls - previous_copies != expected_copies:
            raise ValueError('unexpected formatter memcpy call count')


def bbs_request_bodies(folder):
    """Use captured client bytes and exact search commands offered by the server."""
    from l2_monitor.classic_skill_menu import SkillMenu, parse_classic_skill_menu
    manual = folder / 'manual-learning/packets.json'
    search = folder / 'menu-search.json'
    manual_rows = json.loads(manual.read_text('utf-8'))
    queries = json.loads(search.read_text('utf-8'))['queries']
    bodies = {}
    for rows, source in [(manual_rows, 'retained-manual-client-request'),
                         *((query['packets'], 'retained-search-client-request') for query in queries)]:
        for row in rows:
            raw = bytes.fromhex(row['raw_hex'])
            if row['direction'] != 'client' or len(raw) < 5 or raw[2] != 0x23:
                continue
            if (int.from_bytes(raw[:2], 'little') != len(raw) or (len(raw) - 3) % 2 or
                    raw[-2:] != b'\0\0' or '\0' in raw[3:-2].decode('utf-16le')):
                raise ValueError('retained bypass request framing is invalid')
            bodies.setdefault(raw[2:], source)
    menu = SkillMenu()
    menu.reset('offline-retained-search')
    for query in queries:
        for row in query['packets']:
            raw = bytes.fromhex(row['raw_hex'])
            if row['direction'] == 'server' and len(raw) > 3 and raw[2] == 0x7b:
                fields = parse_classic_skill_menu(raw, 'server')
                menu.apply([dict(row, fields=fields)])
    for offer in menu.snapshot()['offers']:
        if offer['command'].startswith('_bbslearnSkills_learnFromSearch_'):
            body = b'\x23' + (offer['command'] + '\0').encode('utf-16le')
            bodies.setdefault(body, 'exact-server-offered-search-command-serialization')
    for query in ("Warrior's Spirit", '\u041b\u0435\u0447\u0435\u043d\u0438\u0435'):
        command = '_bbslearnSkills_search_ ' + query
        bodies.setdefault(b'\x23' + (command + '\0').encode('utf-16le'), 'synthetic-unicode-command-data')
    required = ('_bbslearnSkills', '_bbslearnSkills_search_ Wind Walk')
    for command in required:
        if b'\x23' + (command + '\0').encode('utf-16le') not in bodies:
            raise ValueError('required actual root/name-search request was not retained')
    if not any(origin == 'exact-server-offered-search-command-serialization' for origin in bodies.values()):
        raise ValueError('no retained server-offered learnFromSearch command')
    sources = [dict(path=str(path.relative_to(ROOT)), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
               for path in (manual, search)]
    return list(bodies.items()), sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, default=ROOT / 'reports/new-client-decryption/203d5e30.bin')
    parser.add_argument('--runtime', type=Path, default=ROOT / 'reports/decryption-20261121/emulation-runtime')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'reports/new-client-decryption/skill-actions/formatter-check.json')
    parser.add_argument('--captures', type=Path, default=ROOT / 'reports/new-client-decryption/skill-actions')
    args = parser.parse_args()
    report = dict(passed=False, live_process_access=False, network_used=False,
                  native_entry=hex(ENTRY), snapshot_sha256=SNAPSHOT_SHA256,
                  source_module_base='0x20000000', jump_tables=['0x203d601c', '0x203d6040'],
                  execution='Unmodified original formatter and embedded jump tables in Unicorn',
                  scope='Serialization only; no original send/encrypt/network chain is invoked',
                  external_stub=dict(address=hex(COPY), symbol='memcpy', calling_convention='cdecl',
                                     behavior='Bounded dest/source/count copy, return dest; caller removes arguments'))
    checks = []
    try:
        formatter = Formatter(args.snapshot, args.runtime)
        bodies = [(bytes([0x14]), 'synthetic-list-request'), (bytes([0x50]), 'synthetic-list-request')]
        cases = [(4683, 1), *((skill, level) for skill in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff)
                             for level in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff))]
        for opcode in (0x7c, 0x73):
            bodies.extend((bytes([opcode]) + struct.pack('<III', skill, level, 0), 'synthetic-acquire-skill-fields')
                          for skill, level in cases)
        bbs, capture_sources = bbs_request_bodies(args.captures)
        bodies.extend(bbs)
        for body, origin in bodies:
            for capacity in (len(body), 32766, len(body) - 1):
                for stack_offset in (0, 4):
                    formatter.verify(body, capacity, stack_offset)
                    checks.append(dict(opcode=f'{body[0]:02X}', format='c' if len(body) == 1 else 'cb', origin=origin,
                                       body_hex=body.hex(), body_sha256=hashlib.sha256(body).hexdigest(),
                                       bytes=len(body), capacity=capacity, stack_mod8=stack_offset,
                                       outcome='exact-bytes' if capacity >= len(body) else 'rejected-capacity'))
        report.update(passed=True, logical_bodies=len(bodies), native_calls=len(checks),
                      exact_byte_checks=sum(row['outcome'] == 'exact-bytes' for row in checks),
                      capacity_rejection_checks=sum(row['outcome'] == 'rejected-capacity' for row in checks),
                      memcpy_stub_calls=formatter.copy_calls, buffer_guards_checked=True,
                      source_immutable_checked=True, esp_checked=True, callee_saved_registers_checked=True,
                      bbs_logical_bodies=len(bbs),
                      retained_bbs_bodies=sum(origin.startswith('retained-') for body, origin in bbs),
                      server_offered_search_bodies=sum(origin.startswith('exact-server-') for body, origin in bbs),
                      synthetic_unicode_bbs_bodies=sum(origin.startswith('synthetic-') for body, origin in bbs),
                      bbs_exact_byte_checks=sum(row['opcode'] == '23' and row['outcome'] == 'exact-bytes'
                                               for row in checks),
                      capture_sources=capture_sources,
                      integer_boundary_scope='DWORD serialization tests include values outside application learning limits',
                      checks=checks)
    except Exception as error:
        report.update(error=repr(error), completed_checks=len(checks), checks=checks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'checks'}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
