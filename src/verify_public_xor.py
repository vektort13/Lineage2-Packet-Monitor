"""Run the unmodified published xor.lua under Lua 5.4 and compare captured bodies."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from reference_xor import (ReferenceXor, extract_rows, reassemble_direction,
                           split_records)

# A small adapter for the ByteArray/Struct API used by xor.lua; not a dissector.
ADAPTER = r'''
ByteArray = {}
local methods = {}
local meta = {__index = methods}
function ByteArray.new(data, raw)
    local b = setmetatable({bytes = {}}, meta)
    if data then
        if not raw then
            data = data:gsub('%s', ''):gsub('..', function(h)
                return string.char(tonumber(h, 16))
            end)
        end
        for i = 1, #data do b.bytes[i] = data:byte(i) end
    end
    return b
end
function methods:len() return #self.bytes end
function methods:get_index(i) return assert(self.bytes[i+1]) end
function methods:set_index(i, v)
    assert(i >= 0 and i < #self.bytes and v >= 0 and v <= 255)
    self.bytes[i+1] = v
end
function methods:set_size(n)
    local size = #self.bytes
    for i = size+1, n do self.bytes[i] = 0 end
    for i = size, n+1, -1 do self.bytes[i] = nil end
end
function methods:le_uint(pos, size)
    return string.unpack('<I'..size, self:raw():sub(pos+1, pos+size))
end
function methods:raw() return string.char(table.unpack(self.bytes)) end
function meta.__concat(a, b) return ByteArray.new(a:raw()..b:raw(), true) end
function meta.__call(a, pos, size)
    return ByteArray.new(a:raw():sub(pos+1, pos+size), true)
end
Struct = {pack = string.pack}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--xor-lua', type=Path, required=True)
    parser.add_argument('--runtime-path', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    parser.add_argument('--server', default='146.59.110.40')
    args = parser.parse_args()
    if args.runtime_path:
        sys.path.insert(0, str(args.runtime_path.resolve()))
    from lupa.lua54 import LuaRuntime
    lua = LuaRuntime(encoding=None, unpack_returned_tuples=True)
    lua.execute(ADAPTER.encode())
    source = args.xor_lua.read_bytes()
    public = lua.execute(source)
    new_array = lua.globals().ByteArray.new
    data, integrity = reassemble_direction(extract_rows(args.capture, args.tshark), 0, args.server, True)
    records = split_records(data)
    first = records[0]
    assert first[2:4] == b'\x2e\x01' and len(first) >= 20
    key = first[4:20]
    lua_key = new_array(key, True)
    python = ReferenceXor(key)
    output_digest = hashlib.sha256()
    mismatch_indices = []
    nickname_matches = []
    for i, record in enumerate(records[1:], 2):
        body = record[2:]
        actual = public.decrypt(new_array(body, True), lua_key)
        candidate = actual.raw(actual)
        expected = python.decrypt(body)
        lua_key = public.next_key(lua_key, len(body))
        if candidate != expected or lua_key.raw(lua_key) != bytes(python.key):
            mismatch_indices.append(i)
        output_digest.update(len(candidate).to_bytes(4, 'little'))
        output_digest.update(candidate)
        if b'X\x005\x000\x001\x00' in candidate:
            nickname_matches.append(i)
    # A fixed multi-record oracle vector tests byte chaining and counter carry.
    synthetic_key = bytes.fromhex('0011223344556677feff0000a16c3197')
    synthetic = [bytes.fromhex(x) for x in ['0958003500300031000000', '000102030405060708090a0b0c0d0e0f10111213']]
    vector_key = new_array(synthetic_key, True)
    vectors = []
    for plain in synthetic:
        encrypted = public.encrypt(new_array(plain, True), vector_key)
        vectors.append({'plaintext': plain.hex(), 'ciphertext': encrypted.raw(encrypted).hex()})
        vector_key = public.next_key(vector_key, len(plain))
    report = {
        'source_url': 'https://raw.githubusercontent.com/eldarkg/lineage2wireshark/master/decrypt/xor.lua',
        'source_sha256': hashlib.sha256(source).hexdigest(),
        'capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
        'execution': 'Unmodified published xor.lua under Lua 5.4 with a ByteArray adapter; not the complete Wireshark dissector',
        'lua_version': lua.eval(b'_VERSION').decode(),
        'server_integrity': integrity,
        'compared_message_count': len(records) - 1,
        'mismatch_message_indices': mismatch_indices,
        'candidate_character_utf16le_matches': nickname_matches,
        'candidate_bodies_length_prefixed_sha256': output_digest.hexdigest(),
        'validated_asterios_decryption': False,
        'oracle_vectors': {'initial_key': synthetic_key.hex(), 'messages': vectors},
        'scope': 'Agreement validates implementation equivalence for the chosen key/framing hypothesis; it does not validate that hypothesis for Asterios',
    }
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'Compared {len(records)-1} bodies; mismatches={len(mismatch_indices)}; semantic validation=false')


if __name__ == '__main__':
    main()
