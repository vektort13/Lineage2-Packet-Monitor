"""Verified window decoding, native dictionary continuation and packet colors."""
import collections
import csv
import hashlib
import struct
import zlib
from datetime import datetime, timezone

from analyze_prime_timeline import parse_fields
from decode_online_probe import decode_client, decode_server, interval_bytes
from reference_xor import split_records
from .live_state import ROOT
from .ciphers import alternative, server_variant
from .alignment import wire_slice, record_prefix
from .semantics import extra_fields


CATEGORIES = {
    'movement': ('Движение', '#58a6ff'),
    'appearance': ('Появление / объект', '#3fb950'),
    'removal': ('Удаление', '#ff7b72'),
    'combat': ('Бой / умения', '#f0883e'),
    'skill_learning': ('Обучение / список умений', '#a89bff'),
    'target': ('Цель', '#d2a8ff'),
    'inventory': ('Предметы', '#e3b341'),
    'exchange': ('Обмен / магазин', '#f4cc6b'),
    'item_drop': ('Выбрасывание', '#e9ae48'),
    'item_pickup': ('Поднятие', '#f2a6d7'),
    'item_spawn': ('Предмет рядом', '#d5d97b'),
    'item_action': ('Действие с предметом', '#dcb986'),
    'session': ('Сеанс', '#56d4dd'),
    'dialogue': ('Диалог / команда', '#b4a6ff'),
    'state': ('Состояние', '#a3b5c7'),
    'service': ('Служебный', '#8b949e'),
    'compressed': ('Сжатый блок', '#f6b44e'),
    'unknown': ('Неизвестный', '#6e7681'),
    'error': ('Ошибка / отказ', '#ff5964'),
}


def category(direction, opcode, name):
    op = opcode.split(' ')[0]
    if (direction == 'client' and op in ('73','7C')) or (direction == 'server' and
            (op in ('5F','90','91','94') or opcode in ('FE F9 00','FE FB 00'))):
        return 'skill_learning'
    if direction == 'client' and op == 'B0':
        return 'exchange'
    if (direction == 'server' and op == '16') or (direction == 'client' and op == '17'):
        return 'item_drop'
    if direction == 'server' and op == '17':
        return 'item_pickup'
    if direction == 'server' and op == '05':
        return 'item_spawn'
    maps = {
        'server': {'movement': {'2F', '79', '47', '22', '72'},
                   'appearance': {'0C', '31', '32'}, 'removal': {'08'},
                   'combat': {'00', '01', '25', '26', '48', '54'},
                   'target': {'23', '24', 'B9'}, 'inventory': {'05', '11', '16', '17', '21'},
                   'session': {'09', '0B', '2E'}, 'dialogue': {'19', '4A'},
                   'state': {'18', '27'}, 'service': {'7D'}, 'error': {'1F'}},
        'client': {'movement': {'0F', '59'}, 'target': {'1F'},
                   'session': {'0E', '11', '12', '2B', '46'},
                   'inventory': {'14', '27'}, 'dialogue': {'23', '38'},
                   'combat': {'2F', '39'}, 'state': {'A6'}}}
    for key, values in maps[direction].items():
        if op in values:
            return key
    lower = name.lower()
    for words, key in [(('move', 'location', 'teleport'), 'movement'),
                       (('skill', 'attack', 'magic'), 'combat'),
                       (('item', 'inventory', 'warehouse'), 'inventory'),
                       (('target',), 'target'), (('html', 'chat', 'say', 'bypass'), 'dialogue'),
                       (('login', 'characterselect', 'protocol', 'enterworld'), 'session'),
                       (('status', 'userinfo', 'stat'), 'state'), (('dummy',), 'service')]:
        if any(word in lower for word in words):
            return key
    return 'unknown' if not name else 'service'


class Catalog:
    def __init__(self):
        with (ROOT / 'config/opcodes-448.csv').open(encoding='utf-8-sig', newline='') as source:
            self.names = {(r['direction'], r['opcode']): r['name'] for r in csv.DictReader(source)}

    def packet(self, direction, raw, timestamp, frame, session_id, **extra):
        opcode = f'{raw[2]:02X}'
        if raw[2] == (0xd0 if direction == 'client' else 0xfe) and len(raw) >= 5:
            opcode += f' {raw[3]:02X} {raw[4]:02X}'
        name = self.names.get((direction, opcode), 'Unknown')
        try:
            fields = extra_fields(direction, raw)
            if fields is None:
                fields = parse_fields(direction, raw)
            schema_error = None
        except (ValueError, struct.error, UnicodeError) as error:
            fields, schema_error = {}, str(error)
        if fields.get('event') == 'client_diagnostic':
            name, group = 'ClientDiagnostic', 'error'
        else:
            group = category(direction, opcode, '' if name == 'Unknown' else name)
        return dict(direction=direction, opcode=opcode, name=name, category=group,
                    category_label=CATEGORIES[group][0], color=CATEGORIES[group][1],
                    length=len(raw), ts_epoch=str(timestamp),
                    time=datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat(timespec='milliseconds'),
                    frame=frame, session_id=session_id, status='decoded', fields=fields,
                    schema_status='partial' if fields else 'reference-only', schema_error=schema_error,
                    sha256=hashlib.sha256(raw).hexdigest(), raw_hex=raw.hex(), **extra)


def _decode_window(rows, before, after, oracle, server, catalog, session_id, mode, cursors=None):
    """Publish only if both cipher end states AND the inflater window match."""
    raw_sets, frames, integrity, starts = {}, {}, {}, {}
    cursors = cursors or {}
    for direction in ('server', 'client'):
        delta = (after[direction + '_counter'] - before[direction + '_counter']) & 0xffffffff
        if delta > 10000:
            raise ValueError('Счётчик сеанса сброшен или окно наблюдения потеряно')
        raw_sets[direction], frames[direction], integrity[direction], starts[direction] = wire_slice(
            rows, direction, server, before, after, cursors.get(direction))
        if cursors.get(direction) is not None and (direction == 'server' or mode != 'asterios'):
            raw_sets[direction] = record_prefix(raw_sets[direction], delta)
    if mode == 'asterios':
        outer, _, server_index = decode_server(raw_sets['server'], frames['server'], before, after)
        if cursors.get('client') is not None:
            client, client_index, consumed = decode_client(raw_sets['client'], frames['client'], before, after, oracle, True)
            raw_sets['client'] = raw_sets['client'][:consumed]
        else:
            client, client_index = decode_client(raw_sets['client'], frames['client'], before, after, oracle)
    else:
        outer, server_index = alternative('server', mode, raw_sets['server'], frames['server'], before, after)
        client, client_index = alternative('client', mode, raw_sets['client'], frames['client'], before, after)
    inflater = zlib.decompressobj(-15, zdict=before['dictionary'])
    dictionary = before['dictionary']
    expanded_bytes, compressed_blocks, packets = 0, 0, []
    timestamps = {int(r['frame.number']): r['frame.time_epoch'] for r in rows}
    for raw, row in zip(outer, server_index):
        if row['compressed']:
            compressed_blocks += 1
            expanded = inflater.decompress(raw[3:], 131073)
            if len(expanded) > 131072 or inflater.unconsumed_tail or inflater.unused_data or inflater.eof:
                raise ValueError('Неожиданная граница или размер DEFLATE')
            dictionary = (dictionary + expanded)[-32768:]
            expanded_bytes += len(expanded)
            decoded = split_records(expanded)
        else:
            decoded = [raw]
        for inner, packet in enumerate(decoded):
            packets.append(catalog.packet('server', packet, timestamps[row['completion_frame']],
                           row['completion_frame'], session_id, compressed=row['compressed'],
                           outer_ordinal=row['ordinal'], inner_index=inner,
                           cipher=mode, cipher_variant=server_variant(len(raw) - 2,
                               (before['server_counter'] + row['ordinal']) & 0xffffffff) if mode == 'asterios' else mode))
    if dictionary != after['dictionary']:
        raise ValueError('Конечный словарь DEFLATE не совпал с работающим клиентом')
    if (after['inflate_total'] - before['inflate_total']) & 0xffffffff != expanded_bytes:
        raise ValueError('Число распакованных байтов не совпало с работающим клиентом')
    for packet, row in zip(client, client_index):
        packets.append(catalog.packet('client', packet, timestamps[row['completion_frame']],
                       row['completion_frame'], session_id, compressed=False,
                       ciphertext_reproduced=True, cipher=mode, cipher_variant=row['mode']))
    packets.sort(key=lambda p: (p['frame'], p['direction'], p.get('outer_ordinal', 0), p.get('inner_index', 0)))
    return packets, dict(server_blocks=len(outer), client_packets=len(client),
                         server_packets=sum(p['direction'] == 'server' for p in packets),
                         compressed_blocks=compressed_blocks, expanded_bytes=expanded_bytes,
                         cipher_states_verified=True, dictionary_verified=True, integrity=integrity,
                         cipher=mode,
                         wire_cursors={direction: ((starts[direction] + len(raw_sets[direction])) & 0xffffffff)
                           if starts[direction] is not None else cursors.get(direction)
                           for direction in ('server', 'client')})


def decode_window(rows, before, after, oracle, server, catalog, session_id, mode='auto', cursors=None):
    choices = ('asterios', 'l2xor16', 'plain') if mode == 'auto' else (mode,)
    first_error = None
    for candidate in choices:
        try:
            return _decode_window(rows, before, after, oracle, server, catalog, session_id, candidate, cursors)
        except (ValueError, IndexError, struct.error, zlib.error) as error:
            if first_error is None:
                first_error = error
    raise ValueError(str(first_error)) from first_error
