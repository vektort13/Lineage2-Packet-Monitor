"""Own-character observations from complete UserInfo and StatusUpdate packets."""
import math
import struct
import threading


STATUS_FIELDS = {1:'level', 2:'exp_low32', 3:'str', 4:'dex', 5:'con', 6:'int', 7:'wit', 8:'men',
                 9:'hp', 10:'max_hp', 11:'mp', 12:'max_mp', 13:'sp', 14:'load', 15:'max_load',
                 17:'p_atk', 18:'attack_speed', 19:'p_def', 20:'evasion', 21:'accuracy',
                 22:'critical', 23:'m_atk', 24:'casting_speed', 25:'m_def',
                 26:'pvp_flag', 27:'karma', 33:'cp', 34:'max_cp'}


class _Reader:
    def __init__(self, data, offset=3):
        self.data, self.offset = data, offset

    def take(self, count):
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError('Truncated High Five character record')
        result = self.data[self.offset:self.offset+count]
        self.offset += count
        return result

    def number(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize('<' + fmt)))[0]

    def string(self):
        value = bytearray()
        for _ in range(4096):
            pair = self.take(2)
            if pair == b'\0\0':
                return value.decode('utf-16le')
            value.extend(pair)
        raise ValueError('Unterminated High Five character string')


def parse_classic_character(raw):
    if len(raw) < 3 or raw[2] not in (0x18, 0x32):
        return None
    if int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Character packet length mismatch')
    reader = _Reader(raw)
    if raw[2] == 0x18:
        object_id, count = reader.number('I'), reader.number('I')
        if count > 256 or len(raw) != 11 + count * 8:
            raise ValueError('StatusUpdate attribute count does not match packet length')
        attributes, values = [], {}
        for _ in range(count):
            kind, value = reader.number('I'), reader.number('I')
            attributes.append(dict(attribute_id=kind, value=value))
            if kind in STATUS_FIELDS:
                values[STATUS_FIELDS[kind]] = value
        return dict(event='status_update', object_id=object_id, attributes=attributes, values=values)
    result = dict(event='self_info', xyz=[reader.number('i') for _ in range(3)],
                  vehicle_id=reader.number('I'), object_id=reader.number('I'), character=reader.string())
    for name in ('race', 'sex', 'base_class_id', 'level'):
        result[name] = reader.number('I')
    result['exp'] = reader.number('Q')
    result['exp_fraction'] = reader.number('d')
    if not result['character'] or not 0 < result['level'] <= 1000000 or not math.isfinite(result['exp_fraction']):
        raise ValueError('Invalid High Five UserInfo identity')
    for name in ('str','dex','con','int','wit','men','max_hp','hp','max_mp','mp','sp','load','max_load'):
        result[name] = reader.number('I')
    reader.take(4)  # Armed/unarmed flag.
    reader.take(26 * 4 * 3)  # Object, item and augmentation IDs in the 26 paperdoll slots.
    reader.take(8)  # Talisman slots and cloak availability.
    for name in ('p_atk','attack_speed','p_def','evasion','accuracy','critical','m_atk',
                 'casting_speed','attack_speed_repeat','m_def'):
        result[name] = reader.number('I')
    result['pvp_flag'], result['karma'] = reader.number('I'), reader.number('I')
    for name in ('run_speed','walk_speed','swim_run_speed','swim_walk_speed',
                 'fly_run_speed','fly_walk_speed','fly_run_speed_2','fly_walk_speed_2'):
        result[name] = reader.number('I')
    reader.take(32)  # Move/attack multipliers and collision radius/height.
    reader.take(16)  # Hair, face, builder level.
    result['title'] = reader.string()
    reader.take(20 + 3 + 8)  # Clan, relation, mount/store/craft, PK/PvP kills.
    cubics = reader.number('H')
    if cubics > 256:
        raise ValueError('Too many cubics in UserInfo')
    reader.take(cubics * 2)
    reader.take(1 + 4 + 1 + 4 + 2 + 2 + 4)
    result['inventory_limit'] = reader.number('H')
    result['class_id'] = reader.number('I')
    reader.take(4)
    result['max_cp'], result['cp'] = reader.number('I'), reader.number('I')
    result['parsed_prefix_bytes'] = reader.offset
    return result


class CharacterState:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id, self.data, self.coverage_gap = session_id, None, False

    def gap(self):
        with self.lock:
            self.coverage_gap = True

    def apply(self, packets):
        with self.lock:
            for packet in packets:
                if packet.get('direction') != 'server':
                    continue
                fields = packet.get('fields') or {}
                if fields.get('event') == 'self_info' and all(key in fields for key in ('level','hp','max_hp','character')):
                    self.data = {key:value for key,value in fields.items() if key not in ('event','parsed_prefix_bytes')}
                    self.coverage_gap = False
                elif (self.data and fields.get('event') == 'status_update'
                      and fields.get('object_id') == self.data['object_id']):
                    self.data.update(fields['values'])
                else:
                    continue
                self.data.update(session_id=self.session_id, updated_at=packet.get('time'), source='server-packets')

    def snapshot(self):
        with self.lock:
            if self.data is None or self.coverage_gap or not self.data.get('max_hp'):
                return None
            result = dict(self.data)
            result['hp_percent'] = 100 * result['hp'] / result['max_hp']
            return result
