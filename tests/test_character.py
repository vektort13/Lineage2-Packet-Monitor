"""Character parsing/state from retained packets and isolated status fixtures."""
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.character import CharacterState, parse_classic_character


FIXTURES = Path(__file__).parent / 'fixtures/classic-character'
OWN_ID = 268555792


def fixture(name):
    value = json.loads((FIXTURES / name).read_text('utf-8'))
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != value['length'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('retained character fixture identity mismatch')
    return raw


def packet(opcode, payload):
    return struct.pack('<HB', len(payload) + 3, opcode) + payload


def status(attributes, object_id=OWN_ID):
    return packet(0x18, struct.pack('<II', object_id, len(attributes)) +
                  b''.join(struct.pack('<II', kind, value) for kind, value in attributes))


def observation(raw, *, direction='server', time='2026-11-22T08:46:57Z'):
    return dict(direction=direction, time=time, fields=parse_classic_character(raw))


class CharacterParsingTests(unittest.TestCase):
    def test_retained_user_info_identity_health_six_stats_and_combat_values(self):
        fields = parse_classic_character(fixture('2703-userinfo.json'))
        self.assertEqual(fields['event'], 'self_info')
        self.assertEqual((fields['object_id'], fields['character'], fields['level']), (OWN_ID, 'X501', 38))
        self.assertEqual((fields['hp'], fields['max_hp']), (11037362, 11037362))
        self.assertEqual((fields['mp'], fields['max_mp']), (1017669, 1017669))
        self.assertEqual((fields['cp'], fields['max_cp']), (1000819, 1000819))
        self.assertEqual([fields[key] for key in ('str', 'dex', 'con', 'int', 'wit', 'men')],
                         [35, 23, 46, 36, 22, 43])
        combat = dict(p_atk=1298741, attack_speed=1614, p_def=11204692, evasion=63,
                      accuracy=100, critical=404, m_atk=5256619, casting_speed=2073,
                      attack_speed_repeat=1614, m_def=1426602)
        self.assertEqual({key: fields[key] for key in combat}, combat)
        self.assertEqual(fields['xyz'], [-14903, -174910, -10664])
        self.assertEqual((fields['exp'], fields['sp'], fields['load'], fields['max_load']),
                         (12513089, 20966314, 7064, 3085680))
        self.assertEqual((fields['title'], fields['class_id'], fields['inventory_limit']),
                         ('~New Legend~', 25, 250))

    def test_user_info_rejects_truncated_frame_and_every_incomplete_required_prefix(self):
        raw = fixture('2703-userinfo.json')
        for end in (3, 22, 31, 100, 500, 663, 745):
            with self.subTest(end=end), self.assertRaises(ValueError):
                parse_classic_character(raw[:end])
        # Reframe to eliminate the outer length check and exercise reader bounds.
        for end in (3, 15, 22, 23, 31, 32, 47, 55, 99, 160, 450, 550, 620, 650, 663):
            with self.subTest(reframed_end=end), self.assertRaises(ValueError):
                parse_classic_character(packet(0x32, raw[3:end]))

    def test_unterminated_and_empty_character_names_are_rejected(self):
        raw = fixture('2703-userinfo.json')
        identity = raw[3:23]
        for name in (b'', 'A'.encode('utf-16le') * 4096, bytes(2)):
            with self.subTest(name_length=len(name)), self.assertRaises(ValueError):
                parse_classic_character(packet(0x32, identity + name))

    def test_status_update_keeps_unknown_attributes_and_maps_known_fields(self):
        fields = parse_classic_character(status([(1, 39), (9, 77), (10, 100), (33, 50),
                                                 (34, 80), (0xffff, 123)]))
        self.assertEqual(fields['object_id'], OWN_ID)
        self.assertEqual(fields['values'], dict(level=39, hp=77, max_hp=100, cp=50, max_cp=80))
        self.assertEqual(fields['attributes'][-1], dict(attribute_id=0xffff, value=123))

    def test_status_count_length_truncation_and_excess_attributes_are_strict(self):
        raw = status([(9, 50)])
        for bad in (raw[:3], raw[:10], raw[:-1], raw + b'\0',
                    packet(0x18, struct.pack('<II', OWN_ID, 2) + raw[11:]),
                    packet(0x18, struct.pack('<II', OWN_ID, 257) + bytes(257 * 8))):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                parse_classic_character(bad)

    def test_real_status_packets_match_their_observed_attributes(self):
        self.assertEqual(parse_classic_character(fixture('5297-StatusUpdate.json'))['values'], dict(load=7064))
        self.assertEqual(parse_classic_character(fixture('5304-StatusUpdate.json'))['values'], dict(sp=21769489))

    def test_unhandled_packets_are_returned_to_other_schemas(self):
        for raw in (b'', b'\1', packet(0x5f, bytes(4))):
            self.assertIsNone(parse_classic_character(raw))


class CharacterStateTests(unittest.TestCase):
    def setUp(self):
        self.state = CharacterState()
        self.state.reset('session-one')
        self.user_info = fixture('2703-userinfo.json')

    def initialize(self):
        self.state.apply([observation(self.user_info)])

    def test_whole_user_info_establishes_identity_and_health_percentage(self):
        self.assertIsNone(self.state.snapshot())
        self.initialize()
        value = self.state.snapshot()
        self.assertEqual(value['session_id'], 'session-one')
        self.assertEqual(value['source'], 'server-packets')
        self.assertEqual(value['hp_percent'], 100)
        self.assertNotIn('parsed_prefix_bytes', value)

    def test_status_only_applies_to_own_object_and_preserves_other_known_fields(self):
        self.initialize()
        known = self.state.snapshot()
        self.state.apply([observation(status([(9, 7)], OWN_ID + 1), time='other-character')])
        self.assertEqual(self.state.snapshot(), known)
        self.state.apply([observation(status([(9, 5518681), (13, 21769489)]), time='own-update')])
        updated = self.state.snapshot()
        self.assertEqual(updated['hp_percent'], 50)
        self.assertEqual(updated['sp'], 21769489)
        self.assertEqual(updated['updated_at'], 'own-update')
        for key in ('character', 'level', 'max_hp', 'mp', 'max_mp', 'cp', 'max_cp',
                    'str', 'dex', 'con', 'int', 'wit', 'men', 'p_atk', 'm_atk'):
            self.assertEqual(updated[key], known[key])

    def test_status_before_identity_and_client_direction_never_create_character(self):
        self.state.apply([observation(status([(1, 38), (9, 100), (10, 100)])),
                          observation(self.user_info, direction='client')])
        self.assertIsNone(self.state.snapshot())
        self.initialize()
        known = self.state.snapshot()
        self.state.apply([observation(status([(9, 1)]), direction='client')])
        self.assertEqual(self.state.snapshot(), known)

    def test_coverage_gap_waits_for_user_info_even_after_own_status_updates(self):
        self.initialize()
        self.state.gap()
        self.assertIsNone(self.state.snapshot())
        self.state.apply([observation(status([(9, 100), (10, 100)]))])
        self.assertIsNone(self.state.snapshot())
        self.initialize()
        self.assertEqual(self.state.snapshot()['hp'], 11037362)
        self.assertFalse(self.state.coverage_gap)

    def test_session_reset_drops_identity_and_old_status_cannot_restore_it(self):
        self.initialize()
        self.state.reset('session-two')
        self.assertIsNone(self.state.snapshot())
        self.state.apply([observation(status([(9, 1)]))])
        self.assertIsNone(self.state.snapshot())
        self.initialize()
        self.assertEqual(self.state.snapshot()['session_id'], 'session-two')


if __name__ == '__main__':
    unittest.main()
