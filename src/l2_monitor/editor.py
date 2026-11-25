"""Lossless escaped text conversion and local editable packet copies."""
import codecs
import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone

from .live_state import DATA_ROOT


ENCODINGS = {'utf-8', 'utf-16le', 'cp1251', 'latin-1'}
MAX_BYTES = 65535


def raw_byte_error(error):
    return ''.join(chr(0xdc00 + b) for b in error.object[error.start:error.end]), error.end


codecs.register_error('l2_raw_bytes', raw_byte_error)


def to_text(data, encoding):
    text = data.decode(encoding, 'l2_raw_bytes')
    result = []
    escapes = {'\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\0': '\\0'}
    for character in text:
        value = ord(character)
        if 0xdc00 <= value <= 0xdcff:
            result.append(f'\\x{value - 0xdc00:02X}')
        elif character in escapes:
            result.append(escapes[character])
        elif value < 32 or value == 127:
            result.append(f'\\u{value:04X}')
        else:
            result.append(character)
    return ''.join(result)


def from_text(text, encoding):
    result, chunk, index = bytearray(), [], 0

    def flush():
        result.extend(''.join(chunk).encode(encoding))
        chunk.clear()

    escapes = {'n': '\n', 'r': '\r', 't': '\t', '0': '\0', '\\': '\\'}
    while index < len(text):
        if text[index] != '\\':
            chunk.append(text[index])
            index += 1
            continue
        if index + 1 == len(text):
            raise ValueError('Незавершённая escape-последовательность')
        code = text[index + 1]
        if code in escapes:
            chunk.append(escapes[code])
            index += 2
        elif code in ('x', 'u', 'U'):
            width = {'x': 2, 'u': 4, 'U': 8}[code]
            value = text[index + 2:index + 2 + width]
            if len(value) != width or not re.fullmatch('[0-9a-fA-F]+', value):
                raise ValueError(f'После \\{code} нужно {width} шестнадцатеричных цифр')
            if code == 'x':
                flush()
                result.append(int(value, 16))
            else:
                chunk.append(chr(int(value, 16)))
            index += 2 + width
        else:
            raise ValueError('Неизвестная escape-последовательность; для обратной косой черты используйте \\\\')
    flush()
    return bytes(result)


def parse_hex(value):
    if not isinstance(value, str):
        raise ValueError('Ожидается строка HEX')
    value = re.sub(r'(?i)0x(?=[0-9a-f]{2}(?:\s|$))', '', value)
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('HEX должен содержать пары цифр 00–FF') from error
    if len(data) > MAX_BYTES:
        raise ValueError('Буфер ограничен 65535 байтами')
    return data


def convert(body):
    encoding = body.get('encoding', 'utf-8')
    if encoding not in ENCODINGS:
        raise ValueError('Кодировка: utf-8, utf-16le, cp1251 или latin-1')
    mode = body.get('mode', 'hex-to-text')
    if mode == 'hex-to-text':
        data = parse_hex(body.get('hex', ''))
    elif mode == 'text-to-hex':
        text = body.get('text', '')
        if not isinstance(text, str):
            raise ValueError('Ожидается строка текста')
        data = from_text(text, encoding)
    else:
        raise ValueError('mode: hex-to-text или text-to-hex')
    if len(data) > MAX_BYTES:
        raise ValueError('Буфер ограничен 65535 байтами')
    if body.get('update_length'):
        if len(data) < 3:
            raise ValueError('Для заголовка пакета нужно не менее трёх байт')
        data = len(data).to_bytes(2, 'little') + data[2:]
    text = to_text(data, encoding)
    if from_text(text, encoding) != data:
        raise ValueError('Преобразование кодировки не сохранило исходные байты')
    declared = int.from_bytes(data[:2], 'little') if len(data) >= 2 else None
    return dict(hex=data.hex(' ').upper(), text=text, encoding=encoding, length=len(data),
                sha256=hashlib.sha256(data).hexdigest(), declared_length=declared,
                length_matches=declared == len(data), lossless=True)


class Drafts:
    def __init__(self, root=None):
        self.root = root or DATA_ROOT / 'reports/monitor-drafts'
        self.lock = threading.RLock()

    def save(self, body, original=None):
        converted = convert(dict(body, mode='hex-to-text'))
        data = bytes.fromhex(converted['hex'])
        original_data = bytes.fromhex(original['raw_hex']) if original else b''
        differences = sum(a != b for a, b in zip(data, original_data)) + abs(len(data) - len(original_data))
        draft_id = uuid.uuid4().hex
        result = dict(id=draft_id, created_at=datetime.now(timezone.utc).isoformat(),
                      source_packet_id=original['id'] if original else None,
                      source_sha256=original['sha256'] if original else None,
                      changed_bytes=differences if original else None, **converted)
        with self.lock:
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / (draft_id + '.bin')).write_bytes(data)
            (self.root / (draft_id + '.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
        return result

    def get(self, draft_id):
        if not re.fullmatch('[a-f0-9]{32}', draft_id):
            raise ValueError('Invalid draft ID')
        path = self.root / (draft_id + '.json')
        return json.loads(path.read_text('utf-8')) if path.exists() else None
