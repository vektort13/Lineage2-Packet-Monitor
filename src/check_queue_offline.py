"""End-to-end queue run against an owned native test process and simulated capture."""
import ctypes
import hashlib
import json
import struct
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from l2_monitor.discovery import NO_WINDOW
from l2_monitor.engine import PacketStore
from l2_monitor.inventory_drop import native_folder
from l2_monitor.live_state import ROOT
from l2_monitor.packet_queue import PacketQueue
from l2_monitor.protocol import Catalog
from l2_monitor.queue_runner import QueueRunner
from l2_monitor.sender import NativeSender


def main():
    folder = native_folder()
    process = subprocess.Popen([str(folder / 'drop_controller.exe'), '--target'], stdout=subprocess.PIPE,
                               text=True, encoding='utf-8', creationflags=NO_WINDOW)
    report = dict(passed=False, network_used=False, game_accessed=False, simulated_capture=True)
    runner = None
    tid = None
    try:
        pid, tid, drop, position, pickup, skill, player, heal, manager, entry, root = process.stdout.readline().split()
        if int(pid) != process.pid:
            raise ValueError('Test process identity mismatch')
        store, catalog = PacketStore(), Catalog()
        calls = []

        def invoke(body, function=entry, position_entry=root, mode='packet', parameter='0', oid=0, amount=0, kind=0):
            args = [str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                    hex(int(function, 16)), hex(int(position_entry, 16)), str(oid), str(amount), str(kind), '0', '0', mode, parameter]
            result = subprocess.run(args, input=body.hex() + '\n' if mode == 'packet' else None,
                                    capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            native = json.loads(result.stdout) if result.returncode == 0 else {}
            if result.returncode or native.get('thread') != int(tid) or native.get('sent') != 1:
                raise RuntimeError('Native test dispatch failed')
            observed = process.stdout.readline().strip()
            if mode == 'packet':
                if len(body) <= 256:
                    expected = 'mock-packet ' + body.hex()
                else:
                    digest = 2166136261
                    for value in body:
                        digest = ((digest ^ value) * 16777619) & 0xffffffff
                    expected = f'mock-packet-size {len(body)} {digest:08x}'
            elif mode == 'bypass':
                expected = 'mock-bypass ' + parameter
            else:
                expected = 'mock-skills list' if parameter == '2' else f'mock-skills {oid} {amount} {kind}'
            if observed != expected:
                raise ValueError('Native test process received different arguments')
            # Only publish after the independent native receiver verified all bytes/arguments.
            full = struct.pack('<H', len(body) + 2) + body
            store.add([catalog.packet('client', full, time.time(), 'native-mock', 'offline-mock')])
            calls.append(dict(bytes=len(full), sha256=hashlib.sha256(full).hexdigest()))
            return native

        class Transport:
            def send_packet(self, status, body):
                return invoke(body)
            def request_bypass(self, status, command):
                return invoke(b'\x23' + command.encode('utf-16le') + b'\0\0', function=skill,
                              position_entry='0', mode='bypass', parameter=command, amount=1)
            def skill(self, status, operation, oid=0, level=0, kind=0):
                body = b'\x50' if operation == 'list' else bytes([0x73 if operation == 'info' else 0x7c]) + struct.pack('<3I', oid, level, kind)
                return invoke(body, function=skill, position_entry='0', mode='skill',
                              parameter=str({'list': 2, 'info': 3, 'learn': 4}[operation]), oid=oid, amount=level, kind=kind)

        activity = lambda: dict(active=False, pending=False)
        monitor = SimpleNamespace(store=store, inventory_drop=SimpleNamespace(transport=Transport(), snapshot=activity),
            auto_pickup=SimpleNamespace(snapshot=activity), skill_actions=SimpleNamespace(snapshot=activity),
            newbie_buff=SimpleNamespace(snapshot=activity),
            status=lambda: dict(running=True, state='live', session_id='offline-mock', sync_errors=0))
        queue = PacketQueue()
        source = ROOT / 'reports/decryption-20261121/offline-prime-verified/client-packets.bin'
        metadata = json.loads(source.with_suffix('.json').read_text('utf-8'))
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != metadata['decoded_sha256']:
            raise ValueError('Retained capture identity changed')
        for packet in metadata['packets']:
            raw = data[packet['decoded_offset']:packet['decoded_offset'] + packet['decoded_length']]
            if hashlib.sha256(raw).hexdigest() != packet['plaintext_sha256']:
                raise ValueError('Retained packet identity changed')
            queue.add(dict(raw_hex=raw.hex(), direction='client'))
        sender = NativeSender(monitor)
        runner = QueueRunner(monitor, queue, sender)
        runner.start(repeats=3, interval_ms=0)
        runner.thread.join(60)
        state = runner.snapshot()
        if state['active'] or state['state'] != 'completed' or state['completed'] != 375:
            raise RuntimeError('Queue run did not complete: ' + str(state))
        if calls[:125] != calls[125:250] or calls[:125] != calls[250:]:
            raise ValueError('Queue changed packet order between cycles')
        if len(sender.history) != 100:
            raise ValueError('Sender history is not bounded')
        report.update(passed=True, queue=state, retained_packets=125, cycles=3, native_calls=len(calls),
                      bounded_history=len(sender.history), calls=calls)
    except Exception as error:
        report['error'] = repr(error)
    finally:
        if runner:
            runner.close()
        if process.poll() is None and tid is not None:
            ctypes.windll.user32.PostThreadMessageW(int(tid), 0x12, 0, 0)
            process.wait(timeout=5)
        path = ROOT / 'reports/offline-finish/native-queue.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), 'utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'calls'}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
