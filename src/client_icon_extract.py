"""Offline extraction helpers for this client's UE2 texture and group files."""
import struct
import io
import re
import zlib
from pathlib import Path


def decode_group(path):
    """RSA framing reference: acmi/L2crypt (MIT), see third_party/LICENSE-L2crypt.txt."""
    raw = Path(path).read_bytes()
    if raw[:28].decode('utf-16le') != 'Lineage2Ver413':
        raise ValueError('Unsupported group encryption')
    modulus = int('75b4d6de5c016544068a1acf125869f43d2e09fc55b8b1e289556daf9b875763'
                  '5593446288b3653da1ce91c87bb1a5c18f16323495c55d7d72c0890a83f69bfd'
                  '1fd9434eb1c02f3e4679edfa43309319070129c267c85604d87bb65bae205de3'
                  '707af1d2108881abb567c3b3d069ae67c3a4c6a3aa93d26413d4c66094ae2039', 16)
    chunks = []
    for offset in range(28, len(raw) - 127, 128):
        block = pow(int.from_bytes(raw[offset:offset + 128], 'big'), 0x1d, modulus).to_bytes(128, 'big')
        length = block[3]
        if length > 124:
            raise ValueError('Invalid RSA group block')
        start = 128 - length - ((124 - length) % 4)
        chunks.append(block[start:start + length])
    compressed = b''.join(chunks)
    size = struct.unpack_from('<I', compressed)[0]
    if not 0 < size <= 256 * 1024 * 1024:
        raise ValueError('Invalid group size')
    inflater = zlib.decompressobj()
    result = inflater.decompress(compressed[4:], size + 1)
    if len(result) != size or not inflater.eof:
        raise ValueError('Group decompression mismatch')
    return result


class Reader:
    def __init__(self, data, offset=0):
        self.data, self.pos = data, offset

    def read(self, length):
        if length < 0 or self.pos + length > len(self.data):
            raise ValueError('Truncated client asset')
        result = self.data[self.pos:self.pos + length]
        self.pos += length
        return result

    def u32(self):
        return struct.unpack('<I', self.read(4))[0]

    def i32(self):
        return struct.unpack('<i', self.read(4))[0]

    def compact(self):
        first = self.read(1)[0]
        value, shift, more = first & 63, 6, first & 64
        for _ in range(4):
            if not more:
                return -value if first & 128 else value
            byte = self.read(1)[0]
            value |= (byte & 127) << shift
            shift, more = shift + 7, byte & 128
        if more:
            raise ValueError('Invalid compact index')
        return -value if first & 128 else value

    def string(self):
        size = self.compact()
        if abs(size) > 32768:
            raise ValueError('Invalid client string length')
        raw = self.read(abs(size) * (2 if size < 0 else 1))
        return raw.decode('utf-16le' if size < 0 else 'latin1').rstrip('\0')

    def unicode(self):
        size = self.u32()
        if size > 32768 or size % 2:
            raise ValueError('Invalid group string length')
        return self.read(size).decode('utf-16le').rstrip('\0')


def decode_xor_package(path):
    raw = Path(path).read_bytes()
    if raw[:4] == b'\xc1\x83\x2a\x9e':
        return raw
    header = raw[:28].decode('utf-16le')
    if header == 'Lineage2Ver121':
        key = sum(Path(path).name.lower().encode('ascii')) & 255
    elif header == 'Lineage2Ver111':
        key = 0xac
    else:
        raise ValueError('Unsupported package encryption: ' + header)
    data = raw[28:].translate(bytes(i ^ key for i in range(256)))
    if data[:4] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Invalid Unreal package signature')
    return data


class TexturePackage:
    def __init__(self, path):
        self.path = Path(path)
        self.data = decode_xor_package(path)
        r = Reader(self.data)
        magic, versions, flags, name_count, name_offset, export_count, export_offset, import_count, import_offset = struct.unpack('<9I', r.read(36))
        self.version, self.license = versions & 65535, versions >> 16
        self.names = []
        r.pos = name_offset
        for _ in range(name_count):
            self.names.append(r.string())
            r.u32()
        self.imports = []
        r.pos = import_offset
        for _ in range(import_count):
            self.imports.append(dict(package=r.compact(), cls=r.compact(), outer=r.i32(), name=r.compact()))
        self.exports = []
        r.pos = export_offset
        for _ in range(export_count):
            entry = dict(cls=r.compact(), super=r.compact(), outer=r.i32(), name=r.compact(), flags=r.u32())
            entry['size'] = r.compact()
            entry['offset'] = r.compact() if entry['size'] else 0
            self.exports.append(entry)

    def object_name(self, index):
        if not index:
            return ''
        entry = self.exports[index - 1] if index > 0 else self.imports[-index - 1]
        outer = self.object_name(entry['outer'])
        return (outer + '.' if outer else '') + self.names[entry['name']]

    def properties(self, entry):
        r = Reader(self.data, entry['offset'])
        result = {}
        while True:
            name = self.names[r.compact()]
            if name == 'None':
                break
            info = r.read(1)[0]
            kind, size_code = info & 15, (info >> 4) & 7
            if kind == 10:
                r.compact()
            size = (1, 2, 4, 12, 16)[size_code] if size_code < 5 else (
                r.read(1)[0] if size_code == 5 else struct.unpack('<H', r.read(2))[0] if size_code == 6 else r.u32())
            if kind == 3:
                result[name] = bool(info & 128)
                continue
            if info & 128:
                byte = r.read(1)[0]
                if byte >= 128:
                    r.read(1 if byte < 192 else 3)
            result[name] = r.read(size)
        return result, r

    def texture(self, entry):
        from PIL import Image
        props, r = self.properties(entry)
        if not (123 <= self.version <= 130 and self.license >= 37):
            raise ValueError('Unsupported Lineage material version')
        r.read(2)
        r.read(14 if self.version < 129 else 70)
        r.read(20)
        stages = r.compact()
        if not 0 <= stages <= 64:
            raise ValueError('Invalid material stage count')
        for _ in range(stages):
            r.string()
            strings = r.compact()
            if not 0 <= strings <= 1024:
                raise ValueError('Invalid material stage strings')
            for _ in range(strings):
                r.string()
        r.string()
        r.read(4)
        count = r.compact()
        if not 1 <= count <= 32:
            raise ValueError('Invalid mipmap count')
        mips = []
        for _ in range(count):
            end = r.u32()
            size = r.compact()
            if not 0 < size <= 16777216:
                raise ValueError('Invalid mipmap size')
            payload = r.read(size)
            if end != r.pos:
                raise ValueError('Mipmap offset mismatch')
            width, height = r.u32(), r.u32()
            bits = r.read(2)
            if not 1 <= width <= 4096 or not 1 <= height <= 4096 or bits != bytes(((width - 1).bit_length(), (height - 1).bit_length())):
                raise ValueError('Mipmap dimensions mismatch')
            mips.append((width, height, payload))
        if r.pos != entry['offset'] + entry['size']:
            raise ValueError('Unparsed texture tail')
        width, height, payload = mips[0]
        if struct.unpack('<I', props['USize'])[0] != width or struct.unpack('<I', props['VSize'])[0] != height:
            raise ValueError('Texture dimensions mismatch')
        fmt = props.get('Format', b'\0')[0]
        if fmt in (3, 7, 8):
            expected = ((width + 3) // 4) * ((height + 3) // 4) * (8 if fmt == 3 else 16)
            if len(payload) != expected:
                raise ValueError('DXT size mismatch')
            fourcc = {3: b'DXT1', 7: b'DXT3', 8: b'DXT5'}[fmt]
            header = (struct.pack('<7I', 124, 0x81007, height, width, len(payload), 0, 0) + bytes(44)
                      + struct.pack('<II4s5I', 32, 4, fourcc, 0, 0, 0, 0, 0) + struct.pack('<5I', 0x1000, 0, 0, 0, 0))
            return Image.open(io.BytesIO(b'DDS ' + header + payload)).convert('RGBA')
        if fmt == 5 and len(payload) == width * height * 4:
            return Image.frombytes('RGBA', (width, height), payload, 'raw', 'BGRA')
        raise ValueError('Unsupported texture pixel format: ' + str(fmt))


def skill_icons(data):
    r = Reader(data)
    count = r.u32()
    result = {}
    for _ in range(count):
        skill, level = r.u32(), r.u32()
        r.read(28)
        r.unicode()
        r.unicode()
        icon = r.unicode()
        r.unicode()
        r.read(12)
        r.string()
        r.read(16)
        r.string()
        if icon:
            result[(skill, level)] = icon.lower()
    if data[r.pos:] not in (b'', b'\x0cSafePackage\0'):
        raise ValueError('Unparsed skill group tail')
    return result


def item_icons(data, tag, strict=True, expected_ids=None):
    """Find complete shared group prefixes; require declared count and unique IDs."""
    count = struct.unpack_from('<I', data)[0]
    result, offsets, conflicts = {}, [], set()
    marker = struct.pack('<I', tag)
    offset = 4
    while offset < len(data):
        offset = data.find(marker, offset)
        if offset < 0:
            break
        r = Reader(data, offset)
        offset += 1
        try:
            fields = struct.unpack('<7I', r.read(28))
            if not 0 < fields[1] < 1000000 or any(v > 100000 for v in fields[2:]):
                continue
            if expected_ids is not None and fields[1] not in expected_ids:
                continue
            paths = [r.unicode() for _ in range(7)]
            if any(path and not re.fullmatch(r"[\w.\-' ()\[\]]+", path) for path in paths):
                continue
            r.read(32)
            icons = [r.unicode().lower() for _ in range(5)]
            if icons[0] and icons[0] != 'none' and not re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_ '\-()\[\]]+)+", icons[0]):
                continue
            if any(path and path != 'none' and not re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_ '\-()\[\]]+)+", path) for path in icons[1:]):
                continue
            if expected_ids is None and not icons[0] and not any('.' in path for path in paths):
                continue
            if result.get(fields[1]) and icons[0] and result[fields[1]] != icons[0]:
                conflicts.add(fields[1])
            if icons[0] or fields[1] not in result:
                result[fields[1]] = icons[0]
            offsets.append(r.pos)
        except (UnicodeError, struct.error, ValueError):
            continue
    if conflicts:
        raise ValueError('Conflicting item icon references')
    if strict and len(result) != count:
        raise ValueError(f'Group prefix count mismatch: {len(result)} != {count}')
    return result
