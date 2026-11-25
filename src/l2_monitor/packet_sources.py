"""Common plaintext packet decoding for native and server-side capture sources."""
import hashlib
import struct
from datetime import datetime, timezone

from .character import parse_classic_character
from .classic_inventory import parse_classic_inventory
from .classic_skills import parse_classic_skills
from .classic_skill_menu import parse_classic_skill_menu
from .protocol import CATEGORIES

SOURCE_MODES = ('auto', 'network', 'client', 'server')
PROTOCOLS = (
    dict(id='classic-h5', name='High Five / проверенная сборка', fields=True),
    dict(id='asterios-448', name='Asterios / протокол 448', fields=True),
    dict(id='raw', name='Открытые байты / неизвестный протокол', fields=False),
)


def decode_packet(catalog, direction, raw, timestamp, sequence, session_id, protocol, **extra):
    if direction not in ('client', 'server'):
        raise ValueError('Неизвестное направление пакета')
    if not 3 <= len(raw) <= 32768 or int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Длина полного пакета не совпадает с u16')
    if protocol not in {item['id'] for item in PROTOCOLS}:
        raise ValueError('Неизвестное описание протокола')
    if protocol == 'raw':
        group = 'unknown'
        return dict(direction=direction, opcode=f'{raw[2]:02X}', name='Unknown', category=group,
                    category_label=CATEGORIES[group][0], color=CATEGORIES[group][1],
                    length=len(raw), ts_epoch=str(timestamp),
                    time=datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat(timespec='milliseconds'),
                    frame=sequence, session_id=session_id, status='decoded', fields={},
                    schema_status='raw', schema_error=None, sha256=hashlib.sha256(raw).hexdigest(),
                    raw_hex=raw.hex(), protocol=protocol, **extra)
    packet = catalog.packet(direction, raw, timestamp, sequence, session_id, protocol=protocol, **extra)
    if protocol == 'classic-h5':
        try:
            fields = None
            if direction == 'server':
                for parser in (parse_classic_character, parse_classic_inventory, parse_classic_skills):
                    fields = parser(raw)
                    if fields is not None:
                        break
            if fields is None:
                fields = parse_classic_skill_menu(raw, direction)
            if fields is not None:
                packet.update(fields=fields, schema_status='partial', schema_error=None)
        except (ValueError, struct.error, UnicodeError) as error:
            packet.update(fields={}, schema_status='reference-only', schema_error=str(error))
    return packet
