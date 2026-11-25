import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from reference_xor import ReferenceXor, reassemble_direction, split_records


class ReferenceXorTests(unittest.TestCase):
    def test_independent_public_lua_oracle_with_counter_carry(self):
        # Produced by unchanged eldarkg/lineage2wireshark decrypt/xor.lua.
        # Source SHA256: 140b9f04b86a67d1f75edabeda7dc207f5ba944cddad26c0ba4611640a90601a
        cipher = ReferenceXor(bytes.fromhex('0011223344556677feff0000a16c3197'))
        self.assertEqual(cipher.decrypt(bytes.fromhex('09406264204523659b6464')),
                         bytes.fromhex('0958003500300031000000'))
        self.assertEqual(cipher.decrypt(bytes.fromhex('001030004010700001080308a5c4fb6373734363')),
                         bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213'))

    def test_counter_wraps_as_unsigned_32bit(self):
        key = bytearray(16)
        key[8:12] = bytes.fromhex('feffffff')
        cipher = ReferenceXor(key)
        cipher.decrypt(bytes(4))
        self.assertEqual(bytes(cipher.key[8:12]), bytes.fromhex('02000000'))

    def test_framing_does_not_accept_partial_or_empty_messages(self):
        self.assertEqual(split_records(b'\x03\x00a\x04\x00bc'), [b'\x03\x00a', b'\x04\x00bc'])
        for data in [b'\x02\x00', b'\x06\x00abc', b'\x03\x00a\x04']:
            with self.assertRaises(ValueError):
                split_records(data)

    def test_probe_rejects_missing_tcp_bytes(self):
        rows = [{'tcp.stream': '0', 'ip.src': 'server', 'tcp.seq_raw': str(seq),
                 'tcp.payload': data.hex()} for seq, data in [(10, b'ab'), (14, b'cd')]]
        with self.assertRaises(ValueError):
            reassemble_direction(rows, 0, 'server', True)


if __name__ == '__main__':
    unittest.main()
