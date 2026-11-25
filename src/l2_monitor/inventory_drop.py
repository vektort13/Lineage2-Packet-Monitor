"""Inventory actions through the verified client UI handler and server observations."""
import ctypes
import hashlib
import json
import math
import subprocess
import threading
from ctypes import wintypes
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess
from .discovery import NO_WINDOW, select_process
from .live_state import ROOT, load_profile


def native_folder():
    import sys
    return ROOT / 'native-drop' if getattr(sys, 'frozen', False) else ROOT / 'build' / 'inventory-drop'


def check_drop_bridge():
    """Exercise the packaged 32-bit bridge against its own temporary mock process."""
    folder = native_folder()
    target = subprocess.Popen([str(folder / 'drop_controller.exe'), '--target'],
                              stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
    tid = None
    try:
        pid, tid, entry, position, pickup, skill, player_info, heal, manager, packet_entry, packet_root = target.stdout.readline().split()
        if int(pid) != target.pid:
            raise RuntimeError('Native drop test process identity changed')
        result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                 hex(int(entry, 16)), hex(int(position, 16)), '123', '7', '24', '0', '0'],
                                capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
        if result.returncode:
            raise RuntimeError('Native drop bridge test failed: ' + result.stdout)
        native = json.loads(result.stdout)
        if native['thread'] != int(tid) or native['destination'] != [124, 200, 300]:
            raise RuntimeError('Native drop bridge coordinates/thread differ')
        if target.stdout.readline().strip() != f'mock-drop 123 7 124 200 300 {tid}':
            raise RuntimeError('Native drop bridge changed the item or quantity')
        for xyz, sent in ((['124', '200', '300'], True), (['1000', '200', '300'], False)):
            result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                     hex(int(pickup, 16)), hex(int(position, 16)), '456', '1', *xyz, 'pickup', '100'],
                                    capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            if result.returncode or bool(json.loads(result.stdout)['sent']) != sent:
                raise RuntimeError('Native pickup bridge/radius test failed')
            if sent and target.stdout.readline().strip() != 'mock-pickup 456 100 200 300':
                raise RuntimeError('Native pickup bridge changed the target or position')
        for operation, expected in ((2, 'mock-skills list'), (3, 'mock-skills 1204 5 0'), (4, 'mock-skills 1204 5 0')):
            result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                     hex(int(skill, 16)), '0', '1204', '5', '0', '0', '0', 'skill', str(operation)],
                                    capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            if result.returncode or target.stdout.readline().strip() != expected:
                raise RuntimeError('Native skill bridge changed the handler arguments')
        result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                 hex(int(skill, 16)), '0', '0', '10', '0', '0', '0', 'bypass', '01'],
                                capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
        if result.returncode or json.loads(result.stdout)['sent'] != 10:
            raise RuntimeError('Native NPC buff batch count differs')
        if [target.stdout.readline().strip() for _ in range(10)] != ['mock-bypass 01'] * 10:
            raise RuntimeError('Native NPC buff command/Unicode argument differs')
        for threshold, active, hp, sent, healing in ((50, 0, 79, 0, 0), (80, 0, 79, 1, 1), (80, 1, 91, 1, 1), (80, 1, 100, 0, 0)):
            result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                     hex(int(heal, 16)), hex(int(player_info, 16)), '123', str(active),
                                     str(threshold), '0', '0', 'heal', hex(int(manager, 16))],
                                    capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            native = json.loads(result.stdout)
            if result.returncode or (native['hp'], native['sent'], native['healing']) != (hp, sent, healing):
                raise RuntimeError('Native auto-heal HP threshold/stop test failed')
            if sent and target.stdout.readline().strip() != f'mock-heal 123 {hp}':
                raise RuntimeError('Native auto-heal used a different item')
        for body in ('50', '23ff000012340000', *[(bytes([0xd0]) + bytes(i % 256 for i in range(size - 1))).hex()
                                               for size in (3, 255, 256, 257, 4096, 32766)]):
            result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                hex(int(packet_entry, 16)), hex(int(packet_root, 16)), '0', '0', '0', '0', '0', 'packet', '0'],
                input=body + '\n', capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            expected = 'mock-packet ' + body
            if len(body) // 2 > 256:
                digest = 2166136261
                for value in bytes.fromhex(body):
                    digest = ((digest ^ value) * 16777619) & 0xffffffff
                expected = f'mock-packet-size {len(body) // 2} {digest:08x}'
            native = json.loads(result.stdout) if not result.returncode else {}
            if result.returncode or native.get('thread') != int(tid) or native.get('sent') != 1 or target.stdout.readline().strip() != expected:
                raise RuntimeError('Native packet serialization changed the bytes')
        result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
            hex(int(packet_entry, 16)), hex(int(packet_root, 16)), '0', '0', '0', '0', '0', 'packet', '0', '64', '80'],
            input='50\n', capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
        native = json.loads(result.stdout) if not result.returncode else {}
        if (result.returncode or native.get('tx_key_before') != bytes(range(0x30,0x40)).hex()
                or (native.get('tx_wire_after',0)-native.get('tx_wire_before',0)) & 0xffffffff != 3
                or native.get('thread') != int(tid) or target.stdout.readline().strip() != 'mock-packet 50'):
            raise RuntimeError('Native packet checkpoint differs from its actual UI-thread call')
        result = subprocess.run([str(folder / 'drop_controller.exe'), pid, tid, str(folder / 'drop_hook.dll'),
                                 hex(int(heal, 16)), '0', '123', '0', '0', '0', '0', 'use-item', hex(int(manager, 16))],
                                capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
        if result.returncode or json.loads(result.stdout)['sent'] != 1 or target.stdout.readline().strip() != 'mock-heal 123 100':
            raise RuntimeError('Native manual item use unexpectedly applied auto-heal HP gating')
        return True
    finally:
        if target.poll() is None and tid is not None:
            user = ctypes.WinDLL('user32', use_last_error=True)
            user.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user.PostThreadMessageW(int(tid), 0x12, 0, 0)
        try:
            target.wait(timeout=3)
        except subprocess.TimeoutExpired:
            target.terminate()
            target.wait(timeout=3)
        target.stdout.close()


def window_thread(pid):
    user = ctypes.WinDLL('user32', use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback, wintypes.LPARAM]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    threads = set()

    @callback
    def collect(window, _):
        owner = wintypes.DWORD()
        thread = user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window):
            threads.add(thread)
        return True
    user.EnumWindows(collect, 0)
    if len(threads) != 1:
        raise ValueError('Не найден единственный поток игрового окна')
    return threads.pop()


class NativeInventoryDrop:
    def __init__(self):
        self.lock = threading.Lock()
        self.cached = None

    def _resolve(self, process):
        identity = (process['pid'], process['create_time'])
        profile = load_profile()
        definition = profile['inventory_drop']
        expected = bytes.fromhex(definition['code_hex'])
        masks = bytes.fromhex(definition['mask_hex'])
        memory = ReadOnlyProcess(process['pid'])
        try:
            if self.cached and self.cached[0] == identity:
                base, entry = self.cached[1:]
                self._verify(memory, base, entry, expected, masks, definition)
                self._verify(memory, base, base + definition['player_position']['rva'],
                             bytes.fromhex(definition['player_position']['code_hex']),
                             bytes.fromhex(definition['player_position']['mask_hex']), definition)
                return entry, base + definition['player_position']['rva']
            engine = Path(process['exe']).parent / 'Engine.dll'
            if hashlib.sha256(engine.read_bytes()).hexdigest() != profile['engine_sha256']:
                raise ValueError('Сборка клиента изменилась: требуется профиль выброса')
            allocations, address = set(), 0
            while address < 0x100000000:
                region = memory.query(address)
                address = (region.base or 0) + region.size
                if region.state == 0x1000 and region.protect & 0xf0 and not region.protect & 0x100:
                    allocations.add(region.allocation)
            matches = []
            for base in allocations:
                entry = base + definition['rva']
                if entry >= 0x100000000:
                    continue
                try:
                    if memory.query(entry).allocation != base:
                        continue
                    self._verify(memory, base, entry, expected, masks, definition)
                except (OSError, ValueError):
                    continue
                matches.append((base, entry))
            if len(matches) != 1:
                raise ValueError('Штатный обработчик выброса не совпал с проверенным профилем')
            base, entry = matches[0]
            self._verify(memory, base, base + definition['player_position']['rva'],
                         bytes.fromhex(definition['player_position']['code_hex']),
                         bytes.fromhex(definition['player_position']['mask_hex']), definition)
            self.cached = (identity, base, entry)
            return entry, base + definition['player_position']['rva']
        finally:
            memory.close()

    @staticmethod
    def _verify(memory, base, entry, expected, masks, definition):
        relocated = bytearray(expected)
        original = int(definition['module_allocation_at_verification'], 16)
        offset = 0
        while offset < len(masks):
            if masks[offset] == 0:
                pointer = int.from_bytes(expected[offset:offset + 4], 'little')
                relocated[offset:offset + 4] = ((pointer - original + base) & 0xffffffff).to_bytes(4, 'little')
                offset += 4
            else:
                offset += 1
        if memory.read(entry, len(expected)) != relocated:
            raise ValueError('Код обработчика клиента изменился')

    def send(self, status, object_id, amount, offset=(24, 0, 0)):
        if not 0 < object_id <= 0xffffffff or not 0 < amount <= 0x7fffffffffffffff:
            raise ValueError('Неверный объект или количество')
        if len(offset) != 3 or any(not math.isfinite(v) for v in offset) or math.hypot(*offset[:2]) > 50 or offset[2] != 0:
            raise ValueError('Место выброса должно быть рядом с персонажем')
        return self._send(status, object_id, amount, offset)

    def pickup(self, status, object_id, xyz, radius):
        if not 0 < object_id <= 0xffffffff or len(xyz) != 3 or not 50 <= radius <= 1500:
            raise ValueError('Неверный предмет или радиус подбора')
        if any(not math.isfinite(v) or abs(v) > 10000000 for v in xyz):
            raise ValueError('Неизвестны координаты предмета')
        return self._send(status, object_id, 1, xyz, radius)

    def skill(self, status, operation, skill_id=0, level=0, list_type=0):
        if operation not in ('list', 'info', 'learn') or type(skill_id) is not int or type(level) is not int:
            raise ValueError('Неверный запрос скилла')
        if operation != 'list' and (not 0 < skill_id <= 0x7fffffff or not 0 < level <= 0x7fffffff or list_type not in (0, 1, 2)):
            raise ValueError('Неверный ID или уровень скилла')
        return self._send(status, skill_id, level, (list_type, 0, 0), skill_operation=operation)

    def newbie_buff(self, status, count):
        if type(count) is not int or not 1 <= count <= 1000:
            raise ValueError('Количество повторов: от 1 до 1000')
        return self._send(status, 0, count, (0, 0, 0), bypass=load_profile()['npc_buffs']['command'])

    def request_bypass(self, status, command):
        if not isinstance(command, str) or not command or '\0' in command or len(command.encode('utf-16le')) > 510:
            raise ValueError('Команда NPC должна содержать от 1 до 255 символов UTF-16')
        return self._send(status, 0, 1, (0, 0, 0), bypass=command)

    def use_item(self, status, object_id):
        if type(object_id) is not int or not 0 < object_id <= 0x7fffffff:
            raise ValueError('Некорректный object ID предмета')
        return self._send(status, object_id, 0, (0, 0, 0), use_item=True)

    def send_packet(self, status, body):
        if not isinstance(body, bytes) or not 1 <= len(body) <= 32766:
            raise ValueError('Некорректный буфер клиентского пакета')
        return self._send(status, 0, 0, (0, 0, 0), packet=body)

    def heal(self, status, object_id, threshold, active):
        if type(object_id) is not int or not 0 < object_id <= 0x7fffffff or type(threshold) is not int or not 1 <= threshold <= 99 or type(active) is not bool:
            raise ValueError('Неверная хилка или порог HP')
        return self._send(status, object_id, int(active), (threshold, 0, 0), heal=True)

    def _send(self, status, object_id, amount, position, radius=None, skill_operation=None, bypass=None, heal=False, use_item=False, packet=None):
        with self.lock:
            selected = status['process']
            process, endpoint = select_process(selected['pid'])
            if process['create_time'] != selected['create_time'] or endpoint != status['endpoint']:
                raise ValueError('Игровое подключение изменилось')
            entry, position_entry = self._resolve(process)
            if radius is not None:
                definition = load_profile()['inventory_drop']
                base = entry - definition['rva']
                pickup = definition['pickup']
                memory = ReadOnlyProcess(process['pid'])
                try:
                    self._verify(memory, base, base + pickup['rva'], bytes.fromhex(pickup['code_hex']),
                                 bytes.fromhex(pickup['mask_hex']), definition)
                finally:
                    memory.close()
                entry = base + pickup['rva']
            if skill_operation or bypass:
                definition = load_profile()['inventory_drop']
                base = entry - definition['rva']
                handler = definition['bypass'] if bypass else definition['skills'][skill_operation]
                memory = ReadOnlyProcess(process['pid'])
                try:
                    self._verify(memory, base, base + handler['rva'], bytes.fromhex(handler['code_hex']),
                                 bytes.fromhex(handler['mask_hex']), definition)
                finally:
                    memory.close()
                entry, position_entry = base + handler['rva'], 0
            if heal or use_item:
                profile = load_profile()
                definition = profile['inventory_drop']
                base = entry - definition['rva']
                memory = ReadOnlyProcess(process['pid'])
                try:
                    for handler in (definition['use_item'], definition['player_info'], profile['client_data']['ui_stats_copy']):
                        self._verify(memory, base, base + handler['rva'], bytes.fromhex(handler['code_hex']),
                                     bytes.fromhex(handler['mask_hex']), definition)
                finally:
                    memory.close()
                entry, position_entry = base + definition['use_item']['rva'], base + definition['player_info']['rva']
                manager_global = base + definition['manager_global_rva']
            if packet is not None:
                profile = load_profile()
                native = profile['native_sender']
                memory = ReadOnlyProcess(process['pid'])
                try:
                    for fingerprint in native['fingerprints']:
                        if hashlib.sha256(memory.read(fingerprint['address'], fingerprint['size'])).hexdigest() != fingerprint['sha256']:
                            raise ValueError('Код отправителя клиента изменился')
                    root = int.from_bytes(memory.read(profile['root_pointer'], 4), 'little')
                    socket = int.from_bytes(memory.read(root + profile['socket_offset'], 4), 'little')
                    if int.from_bytes(memory.read(socket, 4), 'little') != profile['socket_vtable']:
                        raise ValueError('Игровое подключение изменилось')
                finally:
                    memory.close()
                entry, position_entry = native['entry'], profile['root_pointer']
            folder = native_folder()
            args = [str(folder / 'drop_controller.exe'), str(process['pid']), str(window_thread(process['pid'])),
                    str(folder / 'drop_hook.dll'), hex(entry), hex(position_entry), str(object_id), str(amount),
                    *[str(v) for v in position]]
            if radius is not None:
                args.extend(['pickup', str(radius)])
            if skill_operation:
                args.extend(['skill', str({'list': 2, 'info': 3, 'learn': 4}[skill_operation])])
            if bypass:
                args.extend(['bypass', bypass])
            if heal:
                args.extend(['heal', hex(manager_global)])
            if use_item:
                args.extend(['use-item', hex(manager_global)])
            if packet is not None:
                args.extend(['packet', str(profile['socket_offset'])])
            result = subprocess.run(args, input=packet.hex() + '\n' if packet is not None else None,
                                    capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            if result.returncode:
                raise RuntimeError('Вызов клиента не подтверждён; автоматический повтор отменён: ' + result.stdout.strip())
            return json.loads(result.stdout)
