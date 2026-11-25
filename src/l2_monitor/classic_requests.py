"""Build-matched list and skill requests through the original UI-thread sender."""
import json
import collections
import re
import struct
import subprocess
import threading
import time

from .classic_cipher import ClassicLiveState
from .cipher_profiles import CipherProfiles
from .ciphers import xor_encrypt
from .discovery import NO_WINDOW, select_process
from .inventory_drop import native_folder, window_thread

_dispatch_lock = threading.Lock()
_anchor_lock = threading.Lock()
_anchors = collections.OrderedDict()


def _identity(process, endpoint):
    return (process['pid'], process['create_time'], *[endpoint[key] for key in
            ('local_ip','local_port','remote_ip','remote_port')])


def clear_client_anchors(process, endpoint):
    with _anchor_lock:
        _anchors.pop(_identity(process, endpoint), None)


def client_anchors(process, endpoint):
    with _anchor_lock:
        return [dict(item) for item in _anchors.get(_identity(process, endpoint), ())]


def request_list(status, profile, opcode):
    if opcode not in (0x14, 0x50):
        raise ValueError('Only inventory and skill list requests are supported here')
    with _dispatch_lock:
        return _dispatch(status, profile, bytes([opcode]))


def request_packet(status, profile, body):
    """Replay an exact normalized C→S body through the build's original sender."""
    spec = profile.get('packet_requests') or {}
    if spec.get('sender') != 'list_requests' or spec.get('format') != 'cb':
        raise ValueError('Отправка очереди для этой сборки клиента пока не подключена')
    if not isinstance(body, bytes) or not 1 <= len(body) <= spec.get('max_body_bytes', 0):
        raise ValueError('Недопустимый размер тела пакета для этой сборки')
    if body[0] >= profile.get('opcode_map_count', 0):
        raise ValueError('Opcode отсутствует в словаре этой сборки клиента')
    if body[0] == 0xd0 and (len(body) < 3 or
            int.from_bytes(body[1:3], 'little') >= profile.get('extended_map_count', 0)):
        raise ValueError('Расширенный opcode отсутствует в словаре этой сборки клиента')
    with _dispatch_lock:
        return _dispatch(status, profile, body)


def _wire_body(body, checkpoint):
    """Invert both native opcode permutations before constructing a TX proof."""
    mapped = bytearray(body)
    try:
        mapped[0] = checkpoint['opcode_map'].index(body[0])
        if body[0] == 0xd0:
            if len(body) < 3:
                raise ValueError('Неполный расширенный opcode')
            extended = int.from_bytes(body[1:3], 'little')
            mapped[1:3] = checkpoint['extended_map'].index(extended).to_bytes(2, 'little')
    except (KeyError, ValueError) as error:
        raise ValueError('Opcode отсутствует в словаре этой сборки клиента') from error
    return bytes(mapped)


def request_skill(status, profile, operation, skill_id=0, level=0, list_type=0):
    spec = profile.get('skill_requests') or {}
    opcodes = {'list': 0x50, 'info': 0x73, 'learn': 0x7c}
    if operation not in opcodes or spec.get('opcodes', {}).get(operation) != opcodes[operation]:
        raise ValueError('Обучение скиллов для этой сборки клиента пока не подключено')
    if operation == 'list':
        return request_list(status, profile, 0x50)
    if (type(skill_id) is not int or type(level) is not int or type(list_type) is not int
            or not 0 < skill_id <= 0x7fffffff or not 0 < level <= 0x7fffffff or list_type != 0):
        raise ValueError('Неверный ID, уровень или тип обучения скилла')
    body = struct.pack('<BIII', opcodes[operation], skill_id, level, list_type)
    with _dispatch_lock:
        return _dispatch(status, profile, body)


def request_skill_menu(status, profile, command):
    from .classic_skill_menu import parse_learn_command
    spec = (profile.get('skill_requests') or {}).get('community_menu') or {}
    root, prefix = spec.get('root'), spec.get('search_prefix')
    if not isinstance(command, str) or not root or not prefix:
        raise ValueError('Меню обучения для этой сборки клиента пока не подключено')
    search = command[len(prefix):] if command.startswith(prefix) else ''
    if command != root and not (search and re.fullmatch(r'[^\x00-\x1f;]{1,100}', search)) and not parse_learn_command(command):
        raise ValueError('Неподдерживаемая команда меню скиллов')
    if len(command.encode('utf-16le')) > 510:
        raise ValueError('Слишком длинная команда меню скиллов')
    with _dispatch_lock:
        return _dispatch(status, profile, b'\x23' + command.encode('utf-16le') + b'\0\0')


class SkillTransport:
    """Route only skill operations; other automations keep their existing guards."""
    def __init__(self, fallback, monitor=None):
        self.fallback, self.monitor = fallback, monitor

    def skill(self, status, operation, skill_id=0, level=0, list_type=0):
        if status.get('detected_cipher') != 'l2xor16-u64':
            return self.fallback.skill(status, operation, skill_id, level, list_type)
        registry = CipherProfiles()
        entry = next((entry for entry in registry.profiles if entry['id'] == status.get('profile')
                      and entry['validation'] == 'verified'), None)
        if not entry:
            raise ValueError('Обучение скиллов для этой сборки клиента пока не подключено')
        profile = registry.load_profile(entry['engine_sha256'])
        if operation == 'learn' and self.monitor and profile.get('skill_requests', {}).get('community_menu'):
            return self._menu_learn(status, profile, skill_id, level, list_type)
        return request_skill(status, profile, operation, skill_id, level, list_type)

    def _current(self, initial):
        current = self.monitor.status()
        if (not current.get('running') or current.get('state') != 'live'
                or current.get('session_id') != initial.get('session_id')):
            raise ValueError('Игровое подключение изменилось во время обучения')
        return current

    def _menu_query(self, initial, profile, command):
        revision = self.monitor.skill_menu.snapshot()['completed_revision']
        request_skill_menu(self._current(initial), profile, command)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self._current(initial)
            if self.monitor.skill_menu.snapshot()['completed_revision'] > revision:
                return True
            if self.monitor.stop_event.wait(.1):
                break
        return False

    def _menu_learn(self, status, profile, skill_id, level, list_type):
        if (type(skill_id) is not int or type(level) is not int or type(list_type) is not int
                or not 0 < skill_id <= 0x7fffffff or not 0 < level <= 0x7fffffff or list_type != 0):
            raise ValueError('Неверный ID, уровень или тип обучения скилла')
        menu = self.monitor.skill_menu
        if menu.snapshot()['session_id'] != status.get('session_id'):
            raise ValueError('Список предложений относится к другому подключению')
        spec = profile['skill_requests']['community_menu']
        if not menu.snapshot()['search_available']:
            self._menu_query(status, profile, spec['root'])
        if not menu.snapshot()['search_available']:
            return request_skill(self._current(status), profile, 'learn', skill_id, level, list_type)
        offer = menu.find(skill_id, level)
        if not offer:
            name = self.monitor.auto_heal.catalog.skill_name(skill_id, level)
            if not name:
                name = self.monitor.auto_heal.catalog.skill_name(skill_id, 1)
            query = name or str(skill_id)
            if not self._menu_query(status, profile, spec['search_prefix'] + query):
                raise ValueError('Сервер не ответил на поиск скилла')
            offer = menu.find(skill_id, level)
        if not offer:
            raise ValueError(f'Меню сервера не предлагает скилл {skill_id} уровня {level}')
        return request_skill_menu(self._current(status), profile, offer['command'])


def _dispatch(status, profile, body):
    selected = status['process']
    process, endpoint = select_process(selected['pid'])
    if process['create_time'] != selected['create_time'] or endpoint != status['endpoint']:
        raise ValueError('The game connection changed before the list request')
    live = ClassicLiveState(process['pid'], process['exe'], profile)
    try:
        checkpoint = live.snapshot()
        spec = profile['list_requests']
        actual = live.memory.read(live.base + spec['entry_rva'], len(bytes.fromhex(spec['code_hex'])))
        expected, mask = bytes.fromhex(spec['code_hex']), bytes.fromhex(spec['mask_hex'])
        if (len(actual) != len(expected) or len(mask) != len(expected)
                or any((a ^ b) & m for a, b, m in zip(actual, expected, mask))):
            raise ValueError('The client list-request sender changed')
        entry = live.base + spec['entry_rva']
        root = live.base + profile['root_pointer_rva']
        anchored = 'outgoing_bytes_offset' in profile and 'outgoing_key_offset' in profile
        mapped = _wire_body(body, checkpoint) if anchored else None
    finally:
        live.close()
    folder = native_folder()
    arguments = [str(folder/'drop_controller.exe'), str(process['pid']),
                             str(window_thread(process['pid'])), str(folder/'drop_hook.dll'),
                             hex(entry), hex(root), '0','0','0','0','0','packet',
                             str(profile['game_socket_offset'])]
    if anchored:
        arguments.extend([str(profile['outgoing_bytes_offset']), str(profile['outgoing_key_offset'])])
    result = subprocess.run(arguments,
                            input=body.hex()+'\n', capture_output=True, text=True,
                            timeout=8, creationflags=NO_WINDOW)
    if result.returncode:
        raise RuntimeError('Клиент не подтвердил запрос; код обработчика: ' + str(result.returncode))
    outcome = json.loads(result.stdout)
    if outcome.get('sent') != 1 or outcome.get('exception', 0):
        raise RuntimeError('The list-request handler did not confirm its call')
    key = outcome.pop('tx_key_before', None)
    if anchored:
        if not isinstance(key, str) or len(bytes.fromhex(key)) != 16:
            raise RuntimeError('Клиент не подтвердил состояние отправленного пакета')
        before, after = outcome.get('tx_wire_before'), outcome.get('tx_wire_after')
        if (type(before) is not int or type(after) is not int
                or (after-before) & 0xffffffff != len(body)+2):
            raise RuntimeError('Счётчик клиента не подтвердил длину отправленного пакета')
        wire = (len(body)+2).to_bytes(2,'little') + xor_encrypt(mapped, bytes.fromhex(key))
        with _anchor_lock:
            history = _anchors.setdefault(_identity(process, endpoint), collections.deque(maxlen=256))
            history.append(dict(client_wire_after=after, wire_hex=wire.hex()))
            while len(_anchors) > 16:
                _anchors.popitem(last=False)
    return outcome
