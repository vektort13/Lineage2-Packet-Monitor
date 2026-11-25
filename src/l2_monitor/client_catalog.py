"""Complete client item and skill/buff name catalogs, read without game calls."""
import json
import struct
import threading
from datetime import datetime, timezone

from .live_state import ROOT


class CachedMemory:
    def __init__(self, memory):
        self.memory, self.pages = memory, {}

    def read(self, address, size):
        result = bytearray()
        while size:
            page, offset = address & ~4095, address & 4095
            length = min(size, 4096 - offset)
            if page not in self.pages:
                try:
                    self.pages[page] = self.memory.read(page, 4096)
                except OSError:
                    return bytes(result) + self.memory.read(address, size)
            result.extend(self.pages[page][offset:offset + length])
            address, size = address + length, size - length
        return bytes(result)


def table_entries(memory, table):
    header = memory.read(table, 20)
    array, count, capacity, buckets, size = struct.unpack('<5I', header)
    if not 0 <= count <= capacity <= 2000000 or not size or size > 2000000 or size & (size - 1):
        raise ValueError('Таблица базы клиента изменилась')
    raw = memory.read(array, count * 12)
    if getattr(memory, 'memory', memory).read(table, 20) != header:
        raise ValueError('База клиента обновляется; чтение будет повторено')
    return [(key, value) for _, key, value in struct.iter_unpack('<3I', raw)]


def extract_catalog(memory, engine, core, spec):
    memory = CachedMemory(memory)
    def u(address):
        return struct.unpack('<I', memory.read(address, 4))[0]
    def text(address, count):
        if not 0 < count <= 32768:
            return ''
        raw = memory.read(address, count * 2)
        end = next((i for i in range(0, len(raw), 2) if raw[i:i + 2] == b'\0\0'), None)
        if end is None:
            raise ValueError('Не прочитана строка базы клиента')
        return raw[:end].decode('utf-16le')
    names, name_count = u(core + spec['name_array_rva']), u(core + spec['name_count_rva'])
    decoded = {}
    def fname(index):
        if index == 0:
            return ''
        if not 0 < index < name_count:
            raise ValueError('Неверный индекс названия в базе клиента')
        if index not in decoded:
            entry = u(names + index * 4)
            decoded[index] = text(entry + 12, 1024)
        return decoded[index]
    items, skills = [], []
    root = engine + spec['item_root_rva']
    for item_id, record in table_entries(memory, u(root + spec['item_map_offset'])):
        items.append(dict(id=item_id, name=fname(u(record + spec['name_index_offset']))))
    for skill_id, record in table_entries(memory, u(root + spec['skill_map_offset'])):
        data = memory.read(record, 0x20)
        pointer, count, capacity = struct.unpack_from('<3I', data)
        actual_id, level = struct.unpack_from('<2I', data, 0x18)
        if actual_id != skill_id or not 0 <= count <= capacity <= 32768:
            raise ValueError('Формат записи скилла изменился')
        desc_pointer, desc_count, desc_capacity = struct.unpack_from('<3I', data, 12)
        if not 0 <= desc_count <= desc_capacity <= 32768:
            raise ValueError('Формат описания скилла изменился')
        skills.append(dict(id=skill_id, level=level, name=text(pointer, count),
                           description=text(desc_pointer, desc_count)))
    items.sort(key=lambda row: row['id'])
    skills.sort(key=lambda row: (row['id'], row['level']))
    if not items or not skills:
        raise ValueError('База клиента ещё загружается')
    return dict(schema=1, source='client', extracted_at=datetime.now(timezone.utc).isoformat(),
                items=items, skills=skills)


class ClientCatalog:
    def __init__(self):
        self.lock = threading.RLock()
        self.revision = 0
        self.data = dict(items=[], skills=[])
        self.items, self.skills = {}, {}
        path = ROOT / 'config/client-catalog.json'
        if path.is_file():
            self.replace(json.loads(path.read_text('utf-8')))

    def replace(self, data):
        items = {row['id']: row['name'] for row in data['items']}
        skills = {(row['id'], row['level']): row['name'] for row in data['skills']}
        with self.lock:
            self.data, self.items, self.skills = data, items, skills
            self.revision += 1

    def item_name(self, item_id):
        with self.lock:
            return self.items.get(item_id, '')

    def skill_name(self, skill_id, level):
        with self.lock:
            return self.skills.get((skill_id, level), '')

    def summary(self):
        with self.lock:
            return dict(revision=self.revision, items=len(self.data['items']), skills=len(self.data['skills']),
                        extracted_at=self.data.get('extracted_at'), source=self.data.get('source'))

    def query(self, kind='items', search='', offset=0, limit=1000):
        if kind not in ('items', 'skills') or offset < 0 or not 1 <= limit <= 10000:
            raise ValueError('Неверные параметры базы клиента')
        with self.lock:
            rows = self.data[kind]
            term = search.strip().casefold()
            if term:
                rows = [row for row in rows if term in row['name'].casefold() or term == str(row['id'])
                        or term in row.get('description', '').casefold()]
            return dict(rows=rows[offset:offset + limit], total=len(rows), **self.summary())
