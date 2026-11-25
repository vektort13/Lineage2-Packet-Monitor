"""Build-matched native plaintext capture; session keys never leave the client."""
import json
import hashlib
import math
import queue
import struct
import subprocess
import sys
import threading
from pathlib import Path

from .classic_cipher import ClassicLiveState
from .discovery import NO_WINDOW, select_process
from .inventory_drop import window_thread
from .live_state import ROOT, DATA_ROOT


def supports(profile):
    if not isinstance(profile, dict):
        return False
    spec = profile.get('plaintext_tap') or {}
    if not isinstance(spec, dict):
        return False
    return (spec.get('kind') == 'xor64-vtable'
            and spec.get('encrypt_slot') == 31 and spec.get('decrypt_slot') == 32
            and all(type(spec.get(key)) is int and 0 < spec[key] < 0x10000000
                    for key in ('encrypt_rva', 'decrypt_rva'))
            and all(type(profile.get(key)) is int and 0 < profile[key] < 0x10000
                    for key in ('opcode_map_offset', 'extended_map_offset'))
            and type(profile.get('opcode_map_count')) is int and 0 < profile['opcode_map_count'] <= 256
            and type(profile.get('extended_map_count')) is int and 0 < profile['extended_map_count'] <= 65536)


def native_folder():
    return ROOT / 'native-tap' if getattr(sys, 'frozen', False) else ROOT / 'build' / 'client-tap'


def _runtime_dll(folder):
    """Pin an immutable content-addressed copy, leaving packaged/build assets replaceable."""
    data = (folder / 'tap_hook_v2.dll').read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    directory = DATA_ROOT / 'cache' / 'client-tap'
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ('tap-' + digest + '.dll')
    try:
        with target.open('xb') as output:
            output.write(data)
    except FileExistsError:
        pass
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise RuntimeError('The cached plaintext capture module does not match its content hash')
    return target


class ClientTap:
    def __init__(self, process, endpoint, profile):
        self.process, self.endpoint, self.profile = dict(process), dict(endpoint), profile
        self._child = None
        self._messages = queue.Queue()
        self._lock = threading.RLock()
        self._last_sequence = 0
        self._stats = dict(active=False, written=0, consumed=0, dropped=0, invalid=0,
                           source='client-plaintext', keys_exported=False)

    def _identity(self):
        current, endpoint = select_process(self.process['pid'])
        if current['create_time'] != self.process['create_time'] or endpoint != self.endpoint:
            raise ValueError('The game connection changed before plaintext capture')

    def _receive_lines(self, child, messages):
        try:
            for line in child.stdout:
                messages.put(line)
        finally:
            messages.put(None)

    def _response(self):
        try:
            line = self._messages.get(timeout=10)
        except queue.Empty as error:
            raise RuntimeError('Native plaintext capture did not respond') from error
        if line is None:
            raise RuntimeError('Native plaintext capture stopped unexpectedly')
        try:
            result = json.loads(line)
        except (TypeError, ValueError) as error:
            raise RuntimeError('Invalid native plaintext capture response') from error
        if not isinstance(result, dict) or result.get('error'):
            raise RuntimeError('Invalid native plaintext capture response')
        return result

    def start(self):
        with self._lock:
            if self._child:
                raise RuntimeError('Plaintext capture is already started')
            if not supports(self.profile):
                raise ValueError('This client build has no verified plaintext capture adapter')
            self._identity()
            spec = self.profile['plaintext_tap']
            live = ClassicLiveState(self.process['pid'], self.process['exe'], self.profile)
            try:
                root = live._u32(live.base + self.profile['root_pointer_rva'])
                if live._u32(root + self.profile['socket_mode_offset']) in (0, 1):
                    raise ValueError('The client has not entered a game connection')
                socket = live._u32(root + self.profile['game_socket_offset'])
                vtable = live.base + self.profile['socket_vtable_rva']
                if (live._u32(socket) != vtable or
                        not live._u32(socket + self.profile['encryption_enabled_offset'])):
                    raise ValueError('The active game socket does not match the verified adapter')
                live._map(socket, self.profile['opcode_map_offset'], 1, self.profile['opcode_map_count'])
                live._map(socket, self.profile['extended_map_offset'], 2, self.profile['extended_map_count'])
                encrypt = live.base + spec['encrypt_rva']
                decrypt = live.base + spec['decrypt_rva']
                actual_encrypt = struct.unpack('<I', live.memory.read(vtable + spec['encrypt_slot'] * 4, 4))[0]
                actual_decrypt = struct.unpack('<I', live.memory.read(vtable + spec['decrypt_slot'] * 4, 4))[0]
                if actual_encrypt != encrypt or actual_decrypt != decrypt:
                    raise ValueError('The client cipher callbacks do not match the verified adapter')
            finally:
                live.close()
            self._identity()
            folder = native_folder()
            dll = _runtime_dll(folder)
            self._messages = queue.Queue()
            self._last_sequence = 0
            self._stats.update(active=False, written=0, consumed=0, dropped=0, invalid=0)
            fields = [socket, vtable, spec['encrypt_slot'], spec['decrypt_slot'], encrypt, decrypt,
                      self.profile['opcode_map_offset'], self.profile['opcode_map_count'],
                      self.profile['extended_map_offset'], self.profile['extended_map_count']]
            self._child = subprocess.Popen([str(folder / 'tap_controller.exe'), str(self.process['pid']),
                str(window_thread(self.process['pid'])), str(dll),
                *[str(value) for value in fields]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1, creationflags=NO_WINDOW)
            threading.Thread(target=self._receive_lines, args=(self._child, self._messages),
                             name='client-plaintext-reader', daemon=True).start()
            try:
                result = self._response()
                if result.get('started') is not True or result.get('exception') or result.get('state') != 2:
                    raise RuntimeError('The client did not accept the plaintext capture adapter')
                self._stats['active'] = True
            except Exception:
                self._child.wait(timeout=8)
                self._child = None
                raise
            return self.snapshot()

    def read(self):
        with self._lock:
            if not self._child or not self._stats['active']:
                raise RuntimeError('Plaintext capture is not active')
            self._child.stdin.write('read\n'); self._child.stdin.flush()
            result = self._response()
            packets = result.get('packets')
            if not isinstance(packets, list) or len(packets) > 128:
                raise RuntimeError('Invalid plaintext capture packet batch')
            validated, last_sequence = [], self._last_sequence
            for item in packets:
                if not isinstance(item, dict):
                    raise RuntimeError('Invalid plaintext capture packet')
                try:
                    raw = bytes.fromhex(item['raw_hex'])
                    sequence, timestamp = item['sequence'], item['timestamp']
                    valid = (item['direction'] in ('client', 'server') and type(sequence) is int
                             and sequence == (last_sequence + 1) & 0xffffffff
                             and isinstance(timestamp, (float, int)) and math.isfinite(timestamp)
                             and 3 <= len(raw) <= 32768 and int.from_bytes(raw[:2], 'little') == len(raw))
                except (KeyError, TypeError, ValueError):
                    valid = False
                if not valid:
                    raise RuntimeError('Invalid plaintext capture packet framing or sequence')
                last_sequence = sequence
                validated.append(dict(direction=item['direction'], raw_hex=raw.hex(),
                                      timestamp=timestamp, sequence=sequence))
            counters = {}
            for field in ('written', 'consumed', 'dropped', 'invalid'):
                value = result.get(field)
                if type(value) is not int or not 0 <= value <= 0xffffffff:
                    raise RuntimeError('Invalid plaintext capture counter')
                counters[field] = value
            self._last_sequence = last_sequence
            self._stats.update(counters)
            self._stats['active'] = result.get('active') is True
            return validated

    def snapshot(self):
        with self._lock:
            return dict(self._stats)

    def close(self):
        with self._lock:
            if not self._child:
                return
            child, self._child = self._child, None
            try:
                child.stdin.write('close\n'); child.stdin.flush()
                result = self._response()
                if result.get('closed') is not True or result.get('exception'):
                    raise RuntimeError('The client did not confirm plaintext capture detachment')
                if child.wait(timeout=8):
                    raise RuntimeError('Plaintext capture controller failed during detachment')
            finally:
                self._stats['active'] = False
                child.stdin.close()
                child.stdout.close()


def check_client_tap():
    """Exercise the exact DLL hook, normalization, overflow and detach on a mock target."""
    import ctypes
    folder = native_folder()
    target = subprocess.Popen([str(folder / 'tap_controller.exe'), '--target'], stdout=subprocess.PIPE,
                              text=True, creationflags=NO_WINDOW)
    controller = None
    try:
        pid, tid, socket, vtable, encrypt, decrypt = target.stdout.readline().split()
        if int(pid) != target.pid:
            raise RuntimeError('Native plaintext mock target identity changed')
        controller = subprocess.Popen([str(folder / 'tap_controller.exe'), pid, tid,
            str(folder / 'tap_hook_v2.dll'), str(int(socket, 16)), str(int(vtable, 16)), '31', '32',
            str(int(encrypt, 16)), str(int(decrypt, 16)), '64', '209', '80', '152'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
        response = json.loads(controller.stdout.readline())
        if not response.get('started'):
            raise RuntimeError('Native plaintext mock adapter did not install')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8001, 0, 0)
        observed = json.loads(target.stdout.readline())
        if observed != dict(passed=True, encrypt_calls=3, decrypt_calls=1):
            raise RuntimeError('Native cipher return value, bytes, key or call count changed')
        controller.stdin.write('read\n'); controller.stdin.flush()
        batch = json.loads(controller.stdout.readline())
        expected = [('client', '04005011'), ('client', '0600d0120022'), ('server', '0500471122')]
        if [(item['direction'], item['raw_hex']) for item in batch['packets']] != expected:
            raise RuntimeError('Native plaintext capture opcode normalization differs')
        if [item['sequence'] for item in batch['packets']] != [1, 2, 3]:
            raise RuntimeError('Native plaintext capture sequence differs')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8004, 0, 0)
        if not json.loads(target.stdout.readline()).get('passed'):
            raise RuntimeError('Native concurrent plaintext capture changed original calls')
        controller.stdin.write('read\n'); controller.stdin.flush()
        concurrent = json.loads(controller.stdout.readline())
        if len(concurrent['packets']) != 100 or concurrent['dropped'] or concurrent['invalid']:
            raise RuntimeError('Native concurrent plaintext capture lost records below capacity')
        counts = dict(client=0, server=0)
        for record in concurrent['packets']:
            raw = bytes.fromhex(record['raw_hex']); counts[record['direction']] += 1
            if raw[:3] != (b'\x00\x80\x50' if record['direction'] == 'client' else b'\x00\x80\x47') or raw[3:] != b'\x11' * 32765:
                raise RuntimeError('Native concurrent plaintext capture published incomplete bytes')
        if counts != dict(client=50, server=50):
            raise RuntimeError('Native concurrent plaintext capture direction counts differ')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8003, 0, 0)
        if not json.loads(target.stdout.readline()).get('passed'):
            raise RuntimeError('Native plaintext overflow changed client calls')
        controller.stdin.write('read\n'); controller.stdin.flush()
        overflow = json.loads(controller.stdout.readline())
        if len(overflow['packets']) != 128 or overflow['dropped'] != 12 or overflow['invalid']:
            raise RuntimeError('Native plaintext bounded ring/drop counters differ')
        controller.stdin.write('close\n'); controller.stdin.flush()
        if not json.loads(controller.stdout.readline()).get('closed') or controller.wait(timeout=8):
            raise RuntimeError('Native plaintext adapter did not detach')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8002, 0, 0)
        if json.loads(target.stdout.readline()) != dict(restored=True, passed=True):
            raise RuntimeError('Native plaintext adapter did not restore original callbacks')
        controller.stdin.close(); controller.stdout.close()
        controller = subprocess.Popen([str(folder / 'tap_controller.exe'), pid, tid,
            str(folder / 'tap_hook_v2.dll'), str(int(socket, 16)), str(int(vtable, 16)), '31', '32',
            str(int(encrypt, 16)), str(int(decrypt, 16)), '64', '209', '80', '152'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
        if not json.loads(controller.stdout.readline()).get('started'):
            raise RuntimeError('Native plaintext adapter could not reattach to the same process')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8001, 0, 0)
        if not json.loads(target.stdout.readline()).get('passed'):
            raise RuntimeError('Native plaintext reattachment changed client calls')
        controller.stdin.write('read\n'); controller.stdin.flush()
        repeated = json.loads(controller.stdout.readline())
        if [(item['direction'], item['raw_hex']) for item in repeated['packets']] != expected or [item['sequence'] for item in repeated['packets']] != [1, 2, 3]:
            raise RuntimeError('Native plaintext reattachment retained stale ring data')
        # Closing stdin exercises controller EOF cleanup without an explicit close command.
        controller.stdin.close()
        if not json.loads(controller.stdout.readline()).get('closed') or controller.wait(timeout=8):
            raise RuntimeError('Native plaintext controller EOF did not detach')
        ctypes.windll.user32.PostThreadMessageW(int(tid), 0x8002, 0, 0)
        if json.loads(target.stdout.readline()) != dict(restored=True, passed=True):
            raise RuntimeError('Native plaintext EOF cleanup did not restore callbacks')
        return True
    finally:
        if controller and controller.poll() is None:
            try:
                controller.stdin.write('close\n'); controller.stdin.flush(); controller.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                controller.terminate(); controller.wait(timeout=8)
        if target.poll() is None:
            target.terminate(); target.wait(timeout=8)
        if target.stdout:
            target.stdout.close()
        if controller:
            if controller.stdin: controller.stdin.close()
            if controller.stdout: controller.stdout.close()
