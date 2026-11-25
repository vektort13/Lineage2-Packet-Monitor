"""Verified, read-only client item names and current character health."""
import struct

from emulate_capture_function import ReadOnlyProcess
from .discovery import select_process
from .live_state import load_profile
from .client_catalog import ClientCatalog, extract_catalog


class ClientData:
    def __init__(self, transport):
        self.transport = transport
        self.cache = None
        self.names = {}
        self.catalog = ClientCatalog()
        self.catalog_identity = None

    @staticmethod
    def _u(memory, address):
        return struct.unpack('<I', memory.read(address, 4))[0]

    def _lookup(self, memory, table, key):
        array, count, capacity, buckets, size = struct.unpack('<5I', memory.read(table, 20))
        if not 0 <= count <= capacity <= 2000000 or not size or size > 2000000 or size & (size - 1):
            raise ValueError('Таблица клиента изменилась')
        index = self._u(memory, buckets + (key & (size - 1)) * 4)
        seen = set()
        while index != 0xffffffff:
            if index in seen or index >= count:
                raise ValueError('Повреждена цепочка таблицы клиента')
            seen.add(index)
            link, candidate, value = struct.unpack('<3I', memory.read(array + index * 12, 12))
            if candidate == key:
                return value
            index = link
        return None

    def _module(self, memory, spec):
        candidates = [int(spec['module_allocation_at_verification'], 16)]
        fingerprint = spec['fingerprint']
        def check(base):
            self.transport._verify(memory, base, base + fingerprint['rva'], bytes.fromhex(fingerprint['code_hex']),
                                   bytes.fromhex(fingerprint['mask_hex']), spec)
            return base
        try:
            return check(candidates[0])
        except (OSError, ValueError):
            pass
        address, allocations = 0, set()
        while address < 0x100000000:
            region = memory.query(address)
            address = (region.base or 0) + region.size
            if region.state == 0x1000 and region.protect & 0xf0 and not region.protect & 0x100:
                allocations.add(region.allocation)
        found = []
        for base in allocations:
            if base + fingerprint['rva'] >= 0x100000000:
                continue
            try:
                found.append(check(base))
            except (OSError, ValueError):
                pass
        if len(found) != 1:
            raise ValueError('Модуль данных клиента не совпал с профилем')
        return found[0]

    def read(self, status, item_ids=()):
        with self.transport.lock:
            selected = status['process']
            process, endpoint = select_process(selected['pid'])
            if process['create_time'] != selected['create_time'] or endpoint != status['endpoint']:
                raise ValueError('Игровое подключение изменилось')
            root = load_profile()
            spec = root['client_data']
            ui_definition = root['inventory_drop']
            entry, _ = self.transport._resolve(process)
            ui = entry - ui_definition['rva']
            memory = ReadOnlyProcess(process['pid'])
            try:
                identity = (process['pid'], process['create_time'])
                if self.cache and self.cache[0] == identity:
                    engine, core = self.cache[1:]
                else:
                    engine, core = self._module(memory, spec['engine']), self._module(memory, spec['core'])
                    self.names.clear()
                    self.cache = (identity, engine, core)
                for key in ('ui_item_getter', 'ui_stats_copy', 'ui_skill_getter'):
                    handler = spec[key]
                    self.transport._verify(memory, ui, ui + handler['rva'], bytes.fromhex(handler['code_hex']),
                                           bytes.fromhex(handler['mask_hex']), ui_definition)
                manager = self._u(memory, ui + ui_definition['manager_global_rva'])
                actor = manager
                for offset in spec['actor_chain']:
                    actor = self._u(memory, actor + offset)
                    if not actor:
                        raise ValueError('Персонаж ещё не появился в мире')
                oid = self._u(memory, actor + spec['actor_id_offset'])
                context = self._u(memory, engine + spec['player_context_rva'])
                value = self._lookup(memory, context + spec['player_map_offset'], oid)
                if not value or self._u(memory, value) != 1:
                    raise ValueError('Не найдена запись здоровья персонажа')
                record = self._u(memory, value + 4)
                if self._u(memory, record + spec['record_id_offset']) != oid:
                    raise ValueError('Запись здоровья относится к другому объекту')
                hp, maximum = self._u(memory, record + spec['hp_offset']), self._u(memory, record + spec['max_hp_offset'])
                if not 0 < maximum <= 1000000000 or hp > maximum:
                    raise ValueError('Некорректные значения HP')
                raw_name = memory.read(record + spec['record_name_offset'], spec['record_name_bytes'])
                end = next((i for i in range(0, len(raw_name), 2) if raw_name[i:i+2] == b'\0\0'), None)
                if end is None:
                    raise ValueError('Не прочитан ник персонажа')
                character = raw_name[:end].decode('utf-16le')
                level = self._u(memory, record + spec['record_level_offset'])
                if not character or not 1 <= level <= 65535:
                    raise ValueError('Не прочитан уровень персонажа')
                if self.catalog_identity != identity:
                    handler = spec['engine_skill_lookup']
                    self.transport._verify(memory, engine, engine + handler['rva'], bytes.fromhex(handler['code_hex']),
                                           bytes.fromhex(handler['mask_hex']), spec['engine'])
                    self.catalog.replace(extract_catalog(memory, engine, core, spec))
                    self.catalog_identity = identity
                table = self._u(memory, engine + spec['item_root_rva'] + spec['item_map_offset'])
                names = self._u(memory, core + spec['name_array_rva'])
                name_count = self._u(memory, core + spec['name_count_rva'])
                for item_id in set(item_ids) - self.names.keys():
                    known = self.catalog.item_name(item_id)
                    if known:
                        self.names[item_id] = known
                        continue
                    value = self._lookup(memory, table, item_id)
                    if not value:
                        continue
                    index = self._u(memory, value + spec['name_index_offset'])
                    if not 0 < index < name_count:
                        continue
                    name_entry = self._u(memory, names + index * 4)
                    data = memory.read(name_entry + 12, 512)
                    end = next((i for i in range(0, 512, 2) if data[i:i+2] == b'\0\0'), None)
                    if end is not None:
                        self.names[item_id] = data[:end].decode('utf-16le')
                return dict(object_id=oid, character=character, level=level, hp=hp, max_hp=maximum, hp_percent=100 * hp / maximum,
                            names={item: self.names[item] for item in item_ids if item in self.names})
            finally:
                memory.close()
