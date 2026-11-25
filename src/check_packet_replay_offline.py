"""Run the retained client serializer and queue adapters without a game or network."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from decode_prime_client_native import NativeCipherOracle
from l2_monitor.live_state import ROOT, load_profile
from l2_monitor.sender import NativeSender, validate_packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'reports/offline-finish/serializer.json')
    args = parser.parse_args()
    profile = load_profile()
    directories = [ROOT / path for path in profile['snapshot_dirs']]
    directories.append(ROOT / 'reports/native-sender-preflight/new-pages')
    oracle = NativeCipherOracle(directories, ROOT / profile['runtime_path'])
    report = dict(passed=False, live_process_access=False, network_used=False,
                  execution='Retained original x86 formatter and scalar memcpy in Unicorn',
                  synthetic_state={'0x2185eab0': 0, 'meaning': 'CRT optimized-copy availability flag; scalar branch'},
                  snapshot_manifests=[dict(path=str(path / 'manifest.json'), sha256=hashlib.sha256(
                      (path / 'manifest.json').read_bytes()).hexdigest()) for path in directories])
    checks = []
    try:
        uc, xc = oracle.uc, oracle.xc
        # The retained code reads the CRT CPU dispatch flag for copies >= 256 bytes.
        # Supply a declared scalar-only CPU environment, keeping every code byte intact.
        uc.mem_map(0x2185e000, 4096)
        uc.mem_write(0x2185eab0, struct.pack('<I', 0))
        format_address, arguments, source = 0x02100100, 0x02100200, 0x02010000

        def verify(body, origin):
            uc.mem_write(format_address, b'c\0' if len(body) == 1 else b'cb\0')
            uc.mem_write(source, body[1:] or b'\0')
            uc.mem_write(arguments, struct.pack('<3I', body[0], len(body) - 1, source))
            uc.mem_write(oracle.stack, struct.pack('<3I', oracle.sentinel, format_address, arguments))
            uc.mem_write(oracle.buffer - 16, b'\xa5' * (32766 + 48))
            for name in ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP'):
                uc.reg_write(getattr(xc, 'UC_X86_REG_' + name), 0)
            uc.reg_write(xc.UC_X86_REG_EAX, oracle.buffer)
            uc.reg_write(xc.UC_X86_REG_ECX, 32766)
            uc.reg_write(xc.UC_X86_REG_ESP, oracle.stack)
            uc.reg_write(xc.UC_X86_REG_EFLAGS, 2)
            oracle.missing_error = None
            uc.emu_start(0x20460cf0, oracle.sentinel, timeout=2_000_000, count=1_000_000)
            if uc.reg_read(xc.UC_X86_REG_EIP) != oracle.sentinel:
                raise ValueError('Formatter did not return: ' + str(oracle.missing_error))
            length = uc.reg_read(xc.UC_X86_REG_EAX)
            if length != len(body) or bytes(uc.mem_read(oracle.buffer, length)) != body:
                raise ValueError('Formatter changed packet bytes: ' + str(origin))
            if bytes(uc.mem_read(oracle.buffer - 16, 16)) != b'\xa5' * 16:
                raise ValueError('Formatter overwrote prefix guard')
            if bytes(uc.mem_read(oracle.buffer + length, 16)) != b'\xa5' * 16:
                raise ValueError('Formatter overwrote suffix guard')
            checks.append(dict(origin=origin, bytes=length, sha256=hashlib.sha256(body).hexdigest()))

        lengths = [*range(1, 513), 1024, 4095, 4096, 4097, 16384, 32765, 32766]
        for length in lengths:
            verify(bytes([0x99]) + bytes((i * 73) % 256 for i in range(length - 1)), 'synthetic')
        verify(bytes.fromhex('d0f100aabb'), 'synthetic-extended-opcode')
        folder = ROOT / 'reports/decryption-20261121/offline-prime-verified'
        metadata = json.loads((folder / 'client-packets.json').read_text('utf-8'))
        raw = (folder / 'client-packets.bin').read_bytes()
        if hashlib.sha256(raw).hexdigest() != metadata['decoded_sha256']:
            raise ValueError('Retained packet file identity changed')
        adapters = {}
        for packet in metadata['packets']:
            full = raw[packet['decoded_offset']:packet['decoded_offset'] + packet['decoded_length']]
            if hashlib.sha256(full).hexdigest() != packet['plaintext_sha256'] or not packet['ciphertext_reproduced']:
                raise ValueError('Unverified retained plaintext')
            body = validate_packet(full)
            method, _ = NativeSender.prepare_legacy(full, dict(direction='client'))
            adapters[method] = adapters.get(method, 0) + 1
            verify(body, 'retained-' + str(packet['record_index']))
        report.update(passed=True, checks=checks, retained_packets=len(metadata['packets']), adapters=adapters,
                      synthetic_cases=len(lengths) + 1, maximum_body_bytes=max(row['bytes'] for row in checks),
                      live_server_acceptance_verified=False)
    except Exception as error:
        report.update(error=repr(error), missing_page=oracle.missing_error, checks=checks)
    finally:
        oracle.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), 'utf-8')
    print(json.dumps({key: value for key, value in report.items() if key not in ('checks', 'snapshot_manifests')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
