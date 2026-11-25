"""Replay validated client requests through original handlers; confirm captured bytes."""
import struct
from collections import deque
import threading
import time
from functools import lru_cache
from .live_state import load_profile
from .cipher_profiles import CipherProfiles
from .classic_requests import request_packet


def validate_packet(raw):
    if not 3 <= len(raw) <= 32768:
        raise ValueError('Размер полного пакета должен быть 3..32768 байт')
    if int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Длина u16 не совпадает с буфером; обновите длину в редакторе')
    if raw[2] == 0xd0 and len(raw) < 5:
        raise ValueError('Не хватает расширенного opcode')
    return raw[2:]


@lru_cache(maxsize=16)
def _queue_profile(identifier):
    registry = CipherProfiles()
    entry = next((row for row in registry.profiles if row['id'] == identifier
                  and row['validation'] == 'verified' and row['algorithm'] == 'l2xor16-u64'), None)
    return registry.load_profile(entry['engine_sha256']) if entry else None


class NativeSender:
    def __init__(self, monitor):
        self.monitor = monitor
        self.lock = threading.Lock()
        self.history = deque(maxlen=100)
        self.pending = False

    def status(self):
        status = self.monitor.status()
        classic = status.get('detected_cipher') == 'l2xor16-u64'
        profile = self._profile(status)
        spec = (profile or {}).get('packet_requests') or {}
        generic = (spec.get('sender') == 'list_requests' and spec.get('format') == 'cb') if classic else load_profile().get('native_sender', {}).get('raw_replay_enabled', False)
        supported = generic if classic else status.get('actions_supported') is not False
        available = bool(status.get('running') and status.get('state') == 'live' and supported)
        reason = ('Отправка очереди для этой сборки клиента пока не подключена' if not supported
                  else 'Начните захват и дождитесь подключения к игре')
        return dict(available=available, reason=None if available else reason,
                    transport='client-ui-thread', remote_thread=False, supported_opcodes=['*'] if generic else ['19', '23', '50', '73', '7C'],
                    generic_packets=generic, pending=self.pending, history=list(self.history))

    @staticmethod
    def _profile(status):
        if status.get('detected_cipher') == 'l2xor16-u64':
            return _queue_profile(status.get('profile'))
        return None

    def prepare(self, raw, source=None):
        status = self.monitor.status()
        if status.get('detected_cipher') != 'l2xor16-u64':
            return self.prepare_legacy(raw, source)
        self.validate_source(raw, source)
        profile = self._profile(status)
        spec = (profile or {}).get('packet_requests') or {}
        if spec.get('sender') != 'list_requests' or spec.get('format') != 'cb':
            raise ValueError('Отправка очереди для этой сборки клиента пока не подключена')
        body = raw[2:]
        if len(body) > spec['max_body_bytes'] or body[0] >= profile['opcode_map_count']:
            raise ValueError('Opcode или размер пакета не поддерживается этой сборкой клиента')
        if body[0] == 0xd0 and int.from_bytes(body[1:3], 'little') >= profile['extended_map_count']:
            raise ValueError('Расширенный opcode отсутствует в словаре этой сборки клиента')
        return ('classic_packet', (body,))

    @staticmethod
    def validate_source(raw, source=None):
        if source and source.get('data_layer') == 'tcp-payload':
            raise ValueError('Это данные TCP без расшифровки и сборки пакетов; отправка через очередь недоступна')
        validate_packet(raw)
        if source and source.get('direction') != 'client':
            raise ValueError('Серверный пакет S→C нельзя отправить серверу как клиентский запрос')

    @staticmethod
    def prepare_legacy(raw, source=None):
        NativeSender.validate_source(raw, source)
        op = raw[2]
        if op == 0x50 and len(raw) == 3:
            return ('skill', ('list',))
        if op in (0x73, 0x7c) and len(raw) == 15:
            skill, level, kind = struct.unpack_from('<III', raw, 3)
            if 0 < skill <= 0x7fffffff and 0 < level <= 0x7fffffff and kind in (0, 1, 2):
                return ('skill', ('info' if op == 0x73 else 'learn', skill, level, kind))
        if op == 0x23 and len(raw) >= 5 and (len(raw) - 3) % 2 == 0 and raw[-2:] == b'\0\0':
            try:
                command = raw[3:-2].decode('utf-16le')
            except UnicodeError:
                command = ''
            if command and '\0' not in command and len(raw[3:-2]) <= 510:
                return ('request_bypass', (command,))
        if op == 0x19 and len(raw) == 11:
            oid, control = struct.unpack_from('<II', raw, 3)
            if 0 < oid <= 0x7fffffff and control == 0:
                return ('use_item', (oid,))
        if load_profile().get('native_sender', {}).get('raw_replay_enabled', False):
            return ('send_packet', (raw[2:],))
        raise ValueError(f'Для пакета {op:02X} этой структуры ещё не подключён обработчик клиента; пакет не отправлен')

    def _check(self, initial, cancel):
        current = self.monitor.status()
        if cancel and cancel.is_set():
            raise InterruptedError('Очередь остановлена')
        if not current.get('running') or current.get('state') != 'live' or current.get('session_id') != initial.get('session_id'):
            raise RuntimeError('Игровое подключение изменилось; очередь остановлена')
        if current.get('sync_errors', 0) != initial.get('sync_errors', 0):
            raise RuntimeError('Пропуск захвата; отправка остановлена')
        return current

    def send(self, raw, source=None, cancel=None):
        method, arguments = self.prepare(raw, source)
        available = self.status()
        if not available['available']:
            raise ValueError(available['reason'])
        runner = getattr(self.monitor, 'packet_queue_runner', None)
        own_queue = bool(runner and runner.snapshot()['active'] and threading.current_thread() is runner.thread)
        if runner and runner.snapshot()['active'] and not own_queue:
            raise ValueError('Дождитесь завершения очереди пакетов')
        if not own_queue:
            for name in ('inventory_drop', 'auto_pickup', 'skill_actions', 'newbie_buff'):
                action = getattr(self.monitor, name, None)
                state = action.snapshot() if action and hasattr(action, 'snapshot') else {}
                if state.get('active') or state.get('pending'):
                    raise ValueError('Дождитесь завершения текущего действия клиента')
        if not self.lock.acquire(blocking=False):
            raise ValueError('Предыдущая отправка ещё выполняется')
        self.pending = True
        try:
            initial = self.monitor.status()
            self._check(initial, cancel)
            cursor = self.monitor.store.stats()['total']
            if method == 'classic_packet':
                native = request_packet(initial, self._profile(initial) or {}, *arguments)
            else:
                native = getattr(self.monitor.inventory_drop.transport, method)(initial, *arguments)
            if not native.get('sent'):
                raise RuntimeError('Клиент не подтвердил вызов; очередь остановлена')
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                self._check(initial, cancel)
                # Raw bytes are retained internally; HTTP query deliberately omits them.
                with self.monitor.store.lock:
                    observed = next((p for p in self.monitor.store.items if p['id'] > cursor
                        and p['direction'] == 'client' and p.get('raw_hex', '').lower() == raw.hex()), None)
                    diagnostic = next((p['fields'] for p in self.monitor.store.items if p['id'] > cursor
                        and p['direction'] == 'client' and p.get('fields', {}).get('event') == 'client_diagnostic'
                        and p['fields'].get('diagnostic_format_verified')
                        and p['fields'].get('reported_opcode') == f'0x{raw[2]:02X}'), None)
                if observed:
                    result = dict(opcode=f'{raw[2]:02X}', state='captured', packet_id=observed['id'],
                                  confirmation='client-capture', native=native)
                    self.history.append(result)
                    return result
                if diagnostic:
                    raise RuntimeError('Клиент сообщил ' + diagnostic['message'] + '; отправка не подтверждена, очередь остановлена')
                if cancel:
                    cancel.wait(.05)
                else:
                    time.sleep(.05)
            raise RuntimeError('Отправленный пакет не подтверждён захватом; очередь остановлена без повтора')
        finally:
            self.pending = False
            self.lock.release()
