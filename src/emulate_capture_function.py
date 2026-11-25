"""Experimental isolated x86 emulation of an observed packet transform.

The live process is opened ONLY with query/read rights. Unicorn writes affect
only its own synthetic memory. No debugger, host execution, API stubs, code
patches or invented memory contents are used for the observed module pages.
Missing pages outside the explicitly observed scopes stop the run.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import struct
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from reference_xor import extract_rows, reassemble_direction, split_records


class Region(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('allocation', ctypes.c_void_p),
                ('allocation_protect', wt.DWORD), ('size', ctypes.c_size_t),
                ('state', wt.DWORD), ('protect', wt.DWORD), ('kind', wt.DWORD)]


class ReadOnlyProcess:
    def __init__(self, pid):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.kernel.OpenProcess.restype = wt.HANDLE
        self.kernel.VirtualQueryEx.argtypes = [wt.HANDLE, wt.LPCVOID,
                                              ctypes.POINTER(Region), ctypes.c_size_t]
        self.kernel.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID,
                                                 ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.handle = self.kernel.OpenProcess(0x1000 | 0x10, False, pid)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), 'Normal query/read access denied')

    def query(self, address):
        region = Region()
        if not self.kernel.VirtualQueryEx(self.handle, address, ctypes.byref(region), ctypes.sizeof(region)):
            raise OSError(ctypes.get_last_error(), f'VirtualQueryEx({address:#x})')
        return region

    def read(self, address, size):
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        ok = self.kernel.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(count))
        if not ok or count.value != size:
            raise OSError(ctypes.get_last_error(), f'Incomplete ordinary read at {address:#x}')
        return buffer.raw

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--runtime-path', type=Path, required=True)
    parser.add_argument('--entry', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--stop-at', type=lambda value: int(value, 0),
                        help='Optional observation boundary; does not patch the instruction stream')
    parser.add_argument('--snapshot-dir', type=Path, required=True)
    parser.add_argument('--live-pid', type=int)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--key-prefix-byte', type=int, choices=range(256), default=0,
                        help='Hypothesis for the unestablished first byte of the observed key structure')
    parser.add_argument('--record-index', type=int, default=1)
    parser.add_argument('--record-count', type=int, default=1,
                        help='Consecutive server records; preserves emulated key and module state')
    parser.add_argument('--trace-record', type=int, default=0,
                        help='Retain basic blocks and register values for one record, locally')
    parser.add_argument('--packet-counter-initial', type=lambda value: int(value, 0),
                        help='Initial emulated protocol state at observed data address 0x053b5244')
    parser.add_argument('--client-counter-initial', type=lambda value: int(value, 0),
                        help='Initial outgoing cipher counter at observed data address 0x053b5248')
    parser.add_argument('--synthetic-body-size', type=int,
                        help='Offline primitive probe: replace input with a zero-filled body of this size')
    parser.add_argument('--synthetic-opcode', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--winsock-send', action='store_true',
                        help='Offline Winsock ABI with a synthetic socket and SEH-chain cell; never sends')
    parser.add_argument('--then-send-wrapper', action='store_true',
                        help='Follow the observed encryption callback with send-wrapper emulation, stopping before send')
    parser.add_argument('--caller-return', type=lambda value: int(value, 0),
                        help='Observed caller return boundary instead of the synthetic sentinel')
    parser.add_argument('--client-first-body', action='store_true',
                        help='Probe the first observed 64-byte C2S portion after ProtocolVersion')
    parser.add_argument('--socket-receiver', action='store_true',
                        help='Supply a synthetic receiver matching the observed caller field offsets')
    parser.add_argument('--native-caller', action='store_true',
                        help='Emulate the observed native two-argument packet caller with its full record')
    parser.add_argument('--observed-read-page', action='append', default=[],
                        type=lambda value: int(value, 0),
                        help='Additional exact snapshot page after identifying an observed dependency')
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    args = parser.parse_args()
    sys.path.insert(0, str(args.runtime_path.resolve()))
    import unicorn as un
    from unicorn import x86_const as xc
    rows = extract_rows(args.capture, args.tshark)
    server, integrity = reassemble_direction(rows, 0, '146.59.110.40', True)
    records = split_records(server)
    if args.client_first_body:
        client, _ = reassemble_direction(rows, 0, '146.59.110.40', False)
        initial_length = int.from_bytes(client[:2], 'little')
        records = [records[0], client[initial_length:initial_length + 64]]
    if args.synthetic_body_size is not None:
        if not 1 <= args.synthetic_body_size <= 0xfffd:
            raise ValueError('Invalid synthetic body size')
        records = [records[0], struct.pack('<H', args.synthetic_body_size + 2)
                   + bytes([args.synthetic_opcode]) + bytes(args.synthetic_body_size - 1)]
    if args.record_index < 1 or args.record_count < 1 or args.record_index + args.record_count > len(records):
        raise ValueError('Invalid encrypted server record range')
    if args.record_index != 1:
        raise ValueError('Start with record 1 to preserve actual preceding state')
    packet, key = records[args.record_index][2:], records[0][4:20]
    if len(key) != 16 or len(packet) > 0x10000:
        raise ValueError('Unexpected initial data')
    args.snapshot_dir.mkdir(exist_ok=True, parents=True)
    process = ReadOnlyProcess(args.live_pid) if args.live_pid else None
    allowed_allocations = {process.query(address).allocation for address in
                           (args.entry, 0x20466f60, 0x053874d4)} if process else set()
    exact_data_pages = {address & ~0xfff for address in args.observed_read_page}
    if process and args.native_caller:
        profile_pointer = struct.unpack('<I', process.read(0x20a4de6c, 4))[0]
        exact_data_pages.add(profile_pointer & ~0xfff)
    manifest_file = args.snapshot_dir / 'manifest.json'
    if process:
        manifest = {'pid': args.live_pid, 'entry': hex(args.entry),
                    'observed_utc': datetime.now(timezone.utc).isoformat(),
                    'allowed_allocation_bases': [hex(a) for a in sorted(allowed_allocations)],
                    'additional_observed_data_pages': [hex(a) for a in sorted(exact_data_pages)],
                    'provenance': 'Normal ReadProcessMemory; exact pages retained only on emulator demand',
                    'pages': {}}
    else:
        manifest = json.loads(manifest_file.read_text('utf-8'))
        if int(manifest['entry'], 16) != args.entry:
            raise ValueError('Snapshot entry does not match')
    emulator = un.Uc(un.UC_ARCH_X86, un.UC_MODE_32)
    stack_base, buffer_base, key_base, sentinel = 0x01000000, 0x02000000, 0x02100000, 0x02200000
    emulator.mem_map(stack_base, 0x20000)
    emulator.mem_map(buffer_base, 0x20000)
    emulator.mem_map(key_base, 0x1000)
    emulator.mem_map(sentinel, 0x1000)
    call_return = args.caller_return or sentinel
    buffer_base += 0x102
    if args.winsock_send or args.then_send_wrapper:
        emulator.mem_map(0, 4096)
        emulator.mem_write(0, struct.pack('<I', 0xffffffff))
    if args.socket_receiver or args.native_caller:
        receiver = 0x03000000
        emulator.mem_map(receiver, 0xb000)
        emulator.mem_write(receiver, struct.pack('<I', 0x205d326c))
        emulator.mem_write(receiver + 0x9278, struct.pack('<I', 1))
        emulator.mem_write(receiver + 0x927c, bytes([args.key_prefix_byte]) + key)
        key_base = receiver + 0x928d
        emulator.reg_write(xc.UC_X86_REG_ECX, receiver)
    emulator.mem_write(buffer_base - 2, records[args.record_index])
    emulator.mem_write(key_base, bytes([args.key_prefix_byte]) + key)
    stack = stack_base + 0x1f000
    if args.native_caller:
        emulator.mem_write(buffer_base - 2, records[args.record_index])
        emulator.mem_write(stack, struct.pack('<III', sentinel, buffer_base - 2, len(records[args.record_index])))
    else:
        emulator.mem_write(stack, struct.pack('<IIII', sentinel, buffer_base, key_base, len(packet)))
    emulator.reg_write(xc.UC_X86_REG_ESP, stack)
    trail = deque(maxlen=32)
    errors = []
    loaded = set()
    detailed_blocks = []
    detailed_accesses = []
    current_record = 0

    def missing(uc, access, address, size, value, _):
        page = address & ~0xfff
        if page in loaded:
            errors.append(f'Access to already mapped page {page:#x}')
            return False
        name = f'{page:08x}.bin'
        try:
            if process:
                region = process.query(page)
                if ((region.allocation not in allowed_allocations and page not in exact_data_pages) or region.state != 0x1000
                        or region.protect & 0x100 or region.protect & 0xff == 1):
                    raise ValueError(f'Page outside readable observed allocation scopes: {page:#x}')
                data = process.read(page, 4096)
                (args.snapshot_dir / name).write_bytes(data)
                manifest['pages'][hex(page)] = {'file': name,
                    'sha256': hashlib.sha256(data).hexdigest(), 'protect': region.protect}
            else:
                info = manifest['pages'][hex(page)]
                data = (args.snapshot_dir / info['file']).read_bytes()
                if len(data) != 4096 or hashlib.sha256(data).hexdigest() != info['sha256']:
                    raise ValueError('Snapshot page identity mismatch')
            uc.mem_map(page, 4096)
            uc.mem_write(page, data)
            if page == 0x053b5000 and args.packet_counter_initial is not None:
                uc.mem_write(0x053b5244, struct.pack('<I', args.packet_counter_initial))
            if page == 0x053b5000 and args.client_counter_initial is not None:
                uc.mem_write(0x053b5248, struct.pack('<I', args.client_counter_initial))
            loaded.add(page)
            return True
        except Exception as error:
            errors.append(str(error))
            return False

    def block(uc, address, size, _):
        trail.append((hex(address), size))
        if current_record == args.trace_record and len(detailed_blocks) < 100000:
            detailed_blocks.append({'address': hex(address), 'size': size,
                'bytes': bytes(uc.mem_read(address, size)).hex(),
                'registers': {name: hex(uc.reg_read(getattr(xc, 'UC_X86_REG_' + name.upper())))
                              for name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eflags')}})

    def data_access(uc, access, address, size, value, _):
        if current_record != args.trace_record or len(detailed_accesses) >= 20000:
            return
        if not ((buffer_base - 2 <= address < buffer_base + len(packet) + 8)
                or (key_base <= address < key_base + 17)
                or (0x053b4fb0 <= address < 0x053b4fc0)):
            return
        detailed_accesses.append({'pc': hex(uc.reg_read(xc.UC_X86_REG_EIP)),
            'write': access == un.UC_MEM_WRITE, 'address': hex(address), 'size': size,
            'value': value if access == un.UC_MEM_WRITE else int.from_bytes(uc.mem_read(address, size), 'little'),
            'registers': {name: hex(uc.reg_read(getattr(xc, 'UC_X86_REG_' + name.upper())))
                          for name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp')}})

    emulator.hook_add(un.UC_HOOK_MEM_UNMAPPED, missing)
    emulator.hook_add(un.UC_HOOK_BLOCK, block)
    if args.trace_record:
        emulator.hook_add(un.UC_HOOK_MEM_READ | un.UC_HOOK_MEM_WRITE, data_access)
    error = None
    record_results = []
    try:
        for record_index in range(args.record_index, args.record_index + args.record_count):
            current_record = record_index
            packet = records[record_index][2:]
            if len(packet) > 0x10000:
                raise ValueError('Record too large for synthetic input region')
            if args.native_caller:
                emulator.mem_write(buffer_base - 2, records[record_index])
                emulator.mem_write(stack, struct.pack('<III', sentinel, buffer_base - 2, len(records[record_index])))
            elif args.winsock_send:
                emulator.mem_write(buffer_base - 2, records[record_index])
                emulator.mem_write(stack, struct.pack('<IIIII', sentinel, 1, buffer_base - 2, len(packet) + 2, 0))
            else:
                emulator.mem_write(buffer_base, packet)
                emulator.mem_write(stack, struct.pack('<IIII', call_return, buffer_base, key_base, len(packet)))
            emulator.reg_write(xc.UC_X86_REG_ESP, stack)
            if args.socket_receiver or args.native_caller:
                emulator.reg_write(xc.UC_X86_REG_ECX, receiver)
            trail.clear()
            try:
                emulator.emu_start(args.entry, args.stop_at or call_return, timeout=5_000_000, count=2_000_000)
            except un.UcError as exc:
                error = str(exc)
            eip = emulator.reg_read(xc.UC_X86_REG_EIP)
            if eip == call_return and args.then_send_wrapper:
                emulator.mem_write(stack, struct.pack('<IIIII', sentinel, 1, buffer_base - 2, len(packet) + 2, 0))
                emulator.reg_write(xc.UC_X86_REG_ESP, stack)
                try:
                    emulator.emu_start(0x05385c98, 0x05385c34, timeout=5_000_000, count=2_000_000)
                except un.UcError as exc:
                    error = str(exc)
                eip = emulator.reg_read(xc.UC_X86_REG_EIP)
            output = bytes(emulator.mem_read(buffer_base, len(packet)))
            record_results.append({'record_index': record_index, 'body_length': len(packet),
                'returned': eip == sentinel, 'instruction_pointer': hex(eip),
                'output_prefix': output[:32].hex(), 'output_sha256': hashlib.sha256(output).hexdigest(),
                'output_header': bytes(emulator.mem_read(buffer_base - 2, 2)).hex(),
                'key_struct_after': bytes(emulator.mem_read(key_base, 17)).hex()})
            if eip == sentinel and args.record_count > 1:
                destination = args.report.parent / (args.report.stem + '.records')
                destination.mkdir(exist_ok=True)
                (destination / f'{record_index:04d}.body.bin').write_bytes(output)
            if error or eip != sentinel:
                break
    finally:
        if process:
            process.close()
            manifest_file.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    output = bytes(emulator.mem_read(buffer_base, len(packet)))
    result_key = bytes(emulator.mem_read(key_base, 17))
    eip = emulator.reg_read(xc.UC_X86_REG_EIP)
    report = {'entry': hex(args.entry), 'returned': eip == sentinel,
              'requested_boundary': hex(args.stop_at) if args.stop_at else None,
              'boundary_reached': bool(args.stop_at and eip == args.stop_at),
              'instruction_pointer': hex(eip), 'emulator_error': error,
              'unavailable_pages': errors, 'mapped_snapshot_pages': len(loaded),
              'last_blocks': list(trail), 'output_prefix': output[:32].hex(),
              'key_struct_prefix_input': args.key_prefix_byte, 'key_struct_after': result_key.hex(),
              'synthetic_receiver_hypothesis': args.socket_receiver,
              'native_caller_hypothesis': args.native_caller,
              'packet_counter_initial_hypothesis': args.packet_counter_initial,
              'client_counter_initial_hypothesis': args.client_counter_initial,
              'synthetic_body_size': args.synthetic_body_size,
              'synthetic_opcode': args.synthetic_opcode if args.synthetic_body_size else None,
              'winsock_abi_hypothesis': args.winsock_send,
              'followed_send_wrapper': args.then_send_wrapper,
              'observed_caller_return_hypothesis': hex(args.caller_return) if args.caller_return else None,
              'client_first_64_byte_portion_hypothesis': args.client_first_body,
              'input_body_sha256': hashlib.sha256(packet).hexdigest(),
              'output_body_sha256': hashlib.sha256(output).hexdigest(),
              'record_results': record_results,
              'server_integrity': integrity, 'mode': 'capture-pages' if args.live_pid else 'offline',
              'limitations': 'Only observed module pages and synthetic arguments; no host APIs, instruction patches or protection-check stubs'}
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if detailed_blocks:
        args.report.with_suffix('.blocks.json').write_text(json.dumps(detailed_blocks, indent=2) + '\n', encoding='utf-8')
        args.report.with_suffix('.accesses.json').write_text(json.dumps(detailed_accesses, indent=2) + '\n', encoding='utf-8')
    if eip == sentinel:
        args.report.with_suffix('.body.bin').write_bytes(output)
    print(json.dumps({k: report[k] for k in ('returned', 'instruction_pointer', 'emulator_error',
                                          'unavailable_pages', 'mapped_snapshot_pages', 'output_prefix')}))


if __name__ == '__main__':
    main()
