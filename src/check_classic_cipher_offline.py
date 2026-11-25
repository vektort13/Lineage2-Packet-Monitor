"""Compare retained x86 XOR16/uint64 decrypt code with an independent model.

Uses only local capture/snapshot files and Unicorn memory. Two calls to the
external CRT memcpy_s are replaced with a declared bounded 8-byte copy stub;
the complete network chain is neither emulated nor exercised.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRY = 0x203da520
COPY = 0x20176dc6
SENTINEL = 0x01000000
BODY = 0x02000100
KEY = 0x02100100
STACK = 0x02208000
MASK64 = (1 << 64) - 1


def reference(ciphertext, key):
    """Independent decrypt recurrence and little-endian uint64 key advance."""
    if len(key) != 16 or not 1 <= len(ciphertext) <= 32766:
        raise ValueError('reference requires a 16-byte key and body length 1..32766')
    previous = 0
    output = bytearray()
    for position, encrypted in enumerate(ciphertext):
        output.append(encrypted ^ key[position % 16] ^ previous)
        previous = encrypted
    tail = (int.from_bytes(key[8:16], 'little') + len(ciphertext)) & MASK64
    return bytes(output), key[:8] + tail.to_bytes(8, 'little')


class NativeDecrypt:
    def __init__(self, snapshot, runtime):
        sys.path.insert(0, str(runtime))
        import unicorn
        from unicorn import x86_const
        self.xc = x86_const
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        for address, size in ((ENTRY & ~4095, 4096), (COPY & ~4095, 4096),
                              (SENTINEL, 4096), (BODY & ~4095, 65536),
                              (KEY & ~4095, 4096), (STACK & ~65535, 65536)):
            self.uc.mem_map(address, size)
        data = snapshot.read_bytes()
        if data[0x81:0x84] != b'\xc2\x0c\x00':
            raise ValueError('retained function no longer ends with expected stdcall ret 0xc')
        self.uc.mem_write(ENTRY, data)
        self.uc.mem_write(COPY, b'\xc3')
        self.copy_calls = 0
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self._copy_stub, begin=COPY, end=COPY)

    def _copy_stub(self, uc, address, size, data):
        esp = uc.reg_read(self.xc.UC_X86_REG_ESP)
        return_address, destination, destination_size, source, count = struct.unpack(
            '<5I', bytes(uc.mem_read(esp, 20)))
        if count != 8 or destination_size != 8:
            raise ValueError('unexpected memcpy_s arguments')
        uc.mem_write(destination, bytes(uc.mem_read(source, count)))
        uc.reg_write(self.xc.UC_X86_REG_EAX, 0)
        uc.reg_write(self.xc.UC_X86_REG_ESP, esp + 4)  # cdecl: caller removes args.
        uc.reg_write(self.xc.UC_X86_REG_EIP, return_address)
        self.copy_calls += 1

    def decrypt(self, ciphertext, key, flag=1):
        if len(key) != 16 or not 1 <= len(ciphertext) <= 32766:
            raise ValueError('native check body/key outside verified bounds')
        uc, xc = self.uc, self.xc
        uc.mem_write(BODY - 32, b'\xa5' * (len(ciphertext) + 64))
        uc.mem_write(BODY, ciphertext)
        uc.mem_write(KEY - 16, b'\x5a' * 49)
        uc.mem_write(KEY, bytes([flag]) + key)
        uc.mem_write(STACK, struct.pack('<4I', SENTINEL, BODY, KEY, len(ciphertext)))
        preserved = {'EBX': 0x12345678, 'ESI': 0x12345679,
                     'EDI': 0x1234567a, 'EBP': 0x1234567b}
        for name in ('EAX', 'ECX', 'EDX'):
            uc.reg_write(getattr(xc, 'UC_X86_REG_' + name), 0)
        for name, value in preserved.items():
            uc.reg_write(getattr(xc, 'UC_X86_REG_' + name), value)
        uc.reg_write(xc.UC_X86_REG_EFLAGS, 2)
        uc.reg_write(xc.UC_X86_REG_ESP, STACK)
        before_copies = self.copy_calls
        uc.emu_start(ENTRY, SENTINEL, timeout=2_000_000, count=1_000_000)
        if uc.reg_read(xc.UC_X86_REG_EIP) != SENTINEL:
            raise ValueError('native function did not return to sentinel')
        if uc.reg_read(xc.UC_X86_REG_ESP) != STACK + 16:
            raise ValueError('native stdcall stack cleanup changed')
        for name, value in preserved.items():
            if uc.reg_read(getattr(xc, 'UC_X86_REG_' + name)) != value:
                raise ValueError('native callee-saved register changed: ' + name)
        if self.copy_calls - before_copies != 2:
            raise ValueError('native function did not make exactly two copy calls')
        if (bytes(uc.mem_read(BODY - 32, 32)) != b'\xa5' * 32 or
                bytes(uc.mem_read(BODY + len(ciphertext), 32)) != b'\xa5' * 32):
            raise ValueError('native body guard changed')
        if (bytes(uc.mem_read(KEY - 16, 16)) != b'\x5a' * 16 or
                bytes(uc.mem_read(KEY + 17, 16)) != b'\x5a' * 16 or
                bytes(uc.mem_read(KEY, 1)) != bytes([flag])):
            raise ValueError('native key guard or flag changed')
        return bytes(uc.mem_read(BODY, len(ciphertext))), bytes(uc.mem_read(KEY + 1, 16))


def split_records(data):
    position = 0
    while position < len(data):
        if position + 2 > len(data):
            raise ValueError('incomplete retained record prefix')
        size = int.from_bytes(data[position:position + 2], 'little')
        if not 3 <= size <= 32768 or position + size > len(data):
            raise ValueError('invalid or incomplete retained record')
        yield data[position:position + size]
        position += size


def verify_capture(native, folder):
    from l2_monitor.alignment import wire_slice
    capture_path = folder / 'capture-window.json'
    capture = json.loads(capture_path.read_text('utf-8'))
    before, after = capture['before'], capture['after']
    beginning = dict(read_start_ns=before['time'], read_end_ns=before['end'])
    ending = dict(read_start_ns=after['time'], read_end_ns=after['end'])
    results = {}
    for direction, field, count_index in (('server', 'key_in', 4), ('client', 'key_out', 6)):
        expected_path = folder / (direction + '-decoded-probe.json')
        expected = json.loads(expected_path.read_text('utf-8'))
        if expected.get('key_matches') is not True:
            raise ValueError(direction + ' retained probe did not validate its final key')
        wire, frames, integrity, seq = wire_slice(capture['rows'], direction,
                                                capture['endpoint']['remote_ip'], beginning, ending)
        count = (after['counts'][count_index] - before['counts'][count_index]) & 0xffffffff
        if len(wire) != count:
            raise ValueError(direction + ' TCP bytes disagree with retained socket byte counter')
        ciphertext_records = list(split_records(wire))
        if len(ciphertext_records) != len(expected['packets']):
            raise ValueError(direction + ' expected record count differs')
        key = bytes.fromhex(before[field])
        body_bytes = 0
        digest = hashlib.sha256()
        for packet, plaintext in zip(ciphertext_records, expected['packets']):
            output, next_key = native.decrypt(packet[2:], key)
            model_output, model_key = reference(packet[2:], key)
            if (output, next_key) != (model_output, model_key):
                raise ValueError(direction + ' native/reference disagreement')
            if packet[:2] + output != bytes.fromhex(plaintext):
                raise ValueError(direction + ' native plaintext differs from retained decoded probe')
            digest.update(packet[:2] + output)
            body_bytes += len(packet) - 2
            key = next_key
        if key != bytes.fromhex(after[field]):
            raise ValueError(direction + ' native final key differs from retained live state')
        results[direction] = dict(records=len(ciphertext_records), wire_bytes=len(wire),
                                  body_bytes=body_bytes, initial_record_seq=seq,
                                  plaintext_sha256=digest.hexdigest(), native_plaintext_matches=True,
                                  final_key_matches=True, byte_counter_matches=True,
                                  expected_probe_sha256=hashlib.sha256(expected_path.read_bytes()).hexdigest())
    return dict(source_sha256=hashlib.sha256(capture_path.read_bytes()).hexdigest(), directions=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, default=ROOT / 'reports/new-client-decryption')
    parser.add_argument('--runtime', type=Path,
                        default=ROOT / 'reports/decryption-20261121/emulation-runtime')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'reports/new-client-decryption/native-xor-check.json')
    args = parser.parse_args()
    snapshot = args.folder / '203da520.bin'
    report = dict(passed=False, live_process_access=False, network_used=False,
                  execution='Retained original x86 decrypt function in Unicorn; isolated body transform only',
                  entry=hex(ENTRY), end_exclusive='0x203da5a4',
                  snapshot_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                  function_sha256=hashlib.sha256(snapshot.read_bytes()[:0x84]).hexdigest(),
                  external_stub=dict(address=hex(COPY), symbol='memcpy_s',
                                     calling_convention='cdecl', calls_per_decrypt=2,
                                     behavior='Require destSize=count=8; copy exactly 8 bytes; return 0',
                                     native_network_chain_verified=False))
    checks = []
    try:
        native = NativeDecrypt(snapshot, args.runtime)
        rng = random.Random(0x3da520)
        lengths = [1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
                   129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097,
                   16383, 16384, 16385, 32765, 32766]
        tails = [0, 0xfffffff0, 0xffffffff, 0xffffffffffffffef, MASK64]
        cases = [(size, tail) for size in lengths for tail in tails]
        cases.extend((rng.randint(1, 32766), rng.getrandbits(64)) for _ in range(256))
        for index, (size, tail) in enumerate(cases):
            key = rng.randbytes(8) + tail.to_bytes(8, 'little')
            ciphertext = rng.randbytes(size)
            output, next_key = native.decrypt(ciphertext, key, flag=(0, 1, 255)[index % 3])
            if (output, next_key) != reference(ciphertext, key):
                raise ValueError('native/reference mismatch in synthetic case ' + str(index))
            checks.append(dict(index=index, bytes=size, key_tail_before_hex=f'{tail:016x}',
                               crosses_uint32=(tail & 0xffffffff) + size > 0xffffffff,
                               crosses_uint64=tail + size > MASK64,
                               plaintext_sha256=hashlib.sha256(output).hexdigest()))
        capture = verify_capture(native, args.folder)
        captured_records = sum(value['records'] for value in capture['directions'].values())
        report.update(passed=True, synthetic_cases=len(checks), retained_records=captured_records,
                      total_decrypt_calls=len(checks) + captured_records,
                      memcpy_stub_calls=native.copy_calls, minimum_body_bytes=min(row['bytes'] for row in checks),
                      maximum_body_bytes=max(row['bytes'] for row in checks),
                      uint32_carry_cases=sum(row['crosses_uint32'] for row in checks),
                      uint64_wrap_cases=sum(row['crosses_uint64'] for row in checks),
                      guards_checked=True, callee_saved_registers_checked=True,
                      capture=capture, checks=checks)
    except Exception as error:
        report.update(error=repr(error), synthetic_cases_completed=len(checks), checks=checks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ('checks', 'snapshot_sha256', 'function_sha256')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
