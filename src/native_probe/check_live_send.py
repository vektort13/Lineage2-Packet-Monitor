"""Send one RequestSkillList and verify it in a validated live capture."""
import hashlib
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from l2_monitor.engine import Monitor
from l2_monitor.discovery import NO_WINDOW, select_process
from l2_monitor.live_state import LiveState, load_profile


def main():
    process, endpoint = select_process(65124)
    profile = load_profile()
    native = profile['native_sender']
    live = LiveState(process['pid'], process['exe'], profile)
    try:
        for item in native['fingerprints']:
            actual = live.process.read(item['address'], item['size'])
            if hashlib.sha256(actual).hexdigest() != item['sha256']:
                raise ValueError('Sender fingerprint mismatch')
        root = struct.unpack('<I', live.process.read(profile['root_pointer'], 4))[0]
        sock = struct.unpack('<I', live.process.read(root + profile['socket_offset'], 4))[0]
        if struct.unpack('<I', live.process.read(sock, 4))[0] != profile['socket_vtable']:
            raise ValueError('Socket fingerprint mismatch')
        tid = struct.unpack('<I', live.process.read(0x053a4030, 4))[0]
        if tid != 21896:
            raise ValueError('Client thread changed')
    finally:
        live.close()
    monitor = Monitor(interval=4)
    monitor.start(pid=process['pid'])
    try:
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline and monitor.status()['state'] != 'live':
            time.sleep(0.25)
        if monitor.status()['state'] != 'live':
            raise RuntimeError('Capture did not reach validated live state: ' + str(monitor.status()['last_error']))
        with monitor.store.lock:
            cursor = monitor.store.sequence
        folder = ROOT / 'build' / 'native-probe'
        result = subprocess.run([str(folder / 'send_controller.exe'), str(process['pid']), str(tid),
                                 str(folder / 'probe.dll'), hex(native['entry']),
                                 hex(profile['root_pointer']), str(profile['socket_offset'])],
                                input='50\n', text=True, capture_output=True, timeout=10, creationflags=NO_WINDOW)
        print('native:', result.returncode, result.stdout.strip(), result.stderr.strip(), flush=True)
        if result.returncode:
            raise RuntimeError('Native call was not confirmed')
        deadline = time.monotonic() + 25
        packets = []
        while time.monotonic() < deadline:
            with monitor.store.lock:
                packets = [dict(p) for p in monitor.store.items if p['id'] > cursor and p['direction'] == 'client']
            if any(p.get('raw_hex', '').lower() == '030050' or p['opcode'].lower() == 'ff' for p in packets):
                break
            time.sleep(0.25)
        verified = any(p.get('raw_hex', '').lower() == '030050' for p in packets)
        diagnostic = [p for p in packets if p['opcode'].lower() == 'ff']
        report = dict(pid=process['pid'], thread=tid, endpoint=endpoint, native_returncode=result.returncode,
                      native_stdout=result.stdout.strip(), wire_verified=verified,
                      diagnostics=[dict(opcode=p['opcode'], name=p['name'], fields=p['fields'],
                                        raw_hex=p.get('raw_hex')) for p in diagnostic],
                      capture_state=monitor.status()['state'], sync_errors=monitor.status()['sync_errors'])
        output = ROOT / 'reports' / 'native-send-test-02.json'
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, ensure_ascii=False), flush=True)
        if not verified:
            raise SystemExit('The requested packet was not verified; do not automatically retry')
    finally:
        monitor.stop()


if __name__ == '__main__':
    main()
