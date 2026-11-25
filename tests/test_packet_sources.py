"""Shared source decoding keeps bytes and source evidence separate from schemas."""
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.packet_sources import PROTOCOLS, SOURCE_MODES, decode_packet
from l2_monitor.protocol import Catalog

FIXTURES = Path(__file__).parent / 'fixtures'


def fixture(path):
    value = json.loads((FIXTURES / path).read_text('utf-8'))
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != value['length'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('retained packet fixture identity mismatch')
    return raw


def packet(opcode, body=b''):
    return struct.pack('<HB', len(body) + 3, opcode) + body


class PacketSourceTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()

    def decode(self, raw, direction='server', protocol='classic-h5', **metadata):
        return decode_packet(self.catalog, direction, raw, 1795337000.125, 42,
                             'source-test-session', protocol, **metadata)

    def test_available_modes_and_protocols_are_explicit(self):
        self.assertEqual(SOURCE_MODES, ('auto', 'network', 'client', 'server'))
        self.assertEqual({item['id']: item['fields'] for item in PROTOCOLS},
                         {'classic-h5': True, 'asterios-448': True, 'raw': False})

    def test_retained_classic_character_packet_exposes_real_identity_health_and_stats(self):
        raw = fixture('classic-character/2703-userinfo.json')
        decoded = self.decode(raw, source='server', cipher_verified=False)
        fields = decoded['fields']
        self.assertEqual((fields['event'], fields['character'], fields['level']), ('self_info', 'X501', 38))
        self.assertEqual((fields['hp'], fields['max_hp']), (11037362, 11037362))
        self.assertEqual([fields[key] for key in ('str', 'dex', 'con', 'int', 'wit', 'men')],
                         [35, 23, 46, 36, 22, 43])
        self.assertEqual(decoded['schema_status'], 'partial')
        self.assertIsNone(decoded['schema_error'])

    def test_retained_classic_inventory_has_22_positions_and_uint64_amounts(self):
        fields = self.decode(fixture('classic-character/20795-ItemList.json'))['fields']
        self.assertEqual(fields['event'], 'inventory_update')
        self.assertTrue(fields['full_list'])
        self.assertEqual(len(fields['items']), 22)
        self.assertEqual(fields['record_size'], 68)
        self.assertEqual(fields['items'][0]['amount'], 1000)

    def test_retained_classic_skill_list_has_exact_14_byte_records(self):
        fields = self.decode(fixture('classic-character/40-SkillList.json'))['fields']
        self.assertEqual(fields['event'], 'skill_list')
        self.assertEqual(len(fields['skills']), 31)
        self.assertEqual(fields['record_size'], 14)
        self.assertEqual(fields['skills'][0],
                         dict(skill_id=118, skill_level=1, passive=1, disabled=0, enchantable=0))

    def test_retained_classic_board_request_is_parsed_only_as_client_request(self):
        raw = fixture('classic-skill-menu/manual-learn.json')
        client = self.decode(raw, direction='client')
        self.assertEqual((client['fields']['skill_id'], client['fields']['skill_level']), (486, 1))
        self.assertEqual(client['fields']['method'], 'community-board')
        server = self.decode(raw, direction='server')
        self.assertNotEqual(server['fields'].get('event'), 'skill_learn_request')

    def test_source_and_cipher_verification_metadata_are_preserved_without_promotion(self):
        raw = fixture('classic-character/40-SkillList.json')
        for protocol, verified in (('classic-h5', False), ('classic-h5', True), ('raw', False)):
            with self.subTest(protocol=protocol, cipher_verified=verified):
                decoded = self.decode(raw, protocol=protocol, source='server', cipher_verified=verified,
                                      source_session='producer-A', captured_direction='outgoing')
                self.assertEqual(decoded['source'], 'server')
                self.assertIs(decoded['cipher_verified'], verified)
                self.assertEqual(decoded['protocol'], protocol)
                self.assertEqual(decoded['source_session'], 'producer-A')
                self.assertEqual(decoded['captured_direction'], 'outgoing')
                self.assertEqual(decoded['frame'], 42)
                self.assertEqual(decoded['session_id'], 'source-test-session')

    def test_unknown_protocol_raw_does_not_consult_legacy_catalog_or_guess_fields(self):
        catalog = Mock()
        catalog.packet.side_effect = AssertionError('Raw source must never enter a known-protocol parser')
        raw = fixture('classic-character/2703-userinfo.json')
        decoded = decode_packet(catalog, 'server', raw, 1795337000.125, 7, 'raw-session', 'raw',
                                source='client', cipher_verified=False)
        self.assertEqual((decoded['name'], decoded['category'], decoded['schema_status']),
                         ('Unknown', 'unknown', 'raw'))
        self.assertEqual(decoded['fields'], {})
        self.assertEqual(decoded['raw_hex'], raw.hex())
        self.assertEqual(decoded['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(decoded['length'], len(raw))
        self.assertIsNone(decoded['schema_error'])
        catalog.packet.assert_not_called()

    def test_bad_classic_schema_does_not_publish_partial_or_legacy_fields(self):
        raw = bytearray(fixture('classic-character/40-SkillList.json'))
        struct.pack_into('<I', raw, 3, 9999)
        decoded = self.decode(bytes(raw))
        self.assertEqual(decoded['fields'], {})
        self.assertEqual(decoded['schema_status'], 'reference-only')
        self.assertIn('count', decoded['schema_error'])
        self.assertEqual(decoded['raw_hex'], raw.hex())

    def test_asterios_decoder_retains_existing_catalog_fields_and_metadata(self):
        raw = packet(0xA5, b'\x01\x02\x03')
        catalog = Mock()
        catalog.packet.return_value = dict(name='ExistingProtocol', fields={'value': 123})
        decoded = decode_packet(catalog, 'client', raw, 1795337000.125, 5, 's', 'asterios-448',
                                source='network', cipher_verified=True)
        self.assertEqual(decoded['fields'], {'value': 123})
        catalog.packet.assert_called_once_with('client', raw, 1795337000.125, 5, 's',
                                              protocol='asterios-448', source='network', cipher_verified=True)

    def test_bad_complete_lengths_are_rejected_for_every_source_protocol(self):
        for protocol in ('classic-h5', 'asterios-448', 'raw'):
            for raw in (b'', b'\x02\x00', b'\x04\x00\x5f', b'\x03\x00\x5f\x00',
                        struct.pack('<H', 32769) + b'\x00' * 32767):
                with self.subTest(protocol=protocol, length=len(raw)), self.assertRaises(ValueError):
                    self.decode(raw, protocol=protocol)

    def test_bad_direction_or_unknown_protocol_is_rejected_without_guessing(self):
        raw = packet(0x5F)
        for direction in ('incoming', 'outgoing', 'S→C', '', None):
            with self.subTest(direction=direction), self.assertRaises(ValueError):
                self.decode(raw, direction=direction)
        for protocol in ('auto', 'h5', 'unknown', '', None):
            with self.subTest(protocol=protocol), self.assertRaises(ValueError):
                self.decode(raw, protocol=protocol)


if __name__ == '__main__':
    unittest.main()
