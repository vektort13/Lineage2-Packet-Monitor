import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.classic_inventory import parse_classic_inventory
from l2_monitor.classic_skills import parse_classic_skills
from l2_monitor.inventory import Inventory
from l2_monitor.skills import Skills


FIXTURES = Path(__file__).parent / 'fixtures/classic-character'


def packet(opcode, payload):
    return struct.pack('<HB', len(payload) + 3, opcode) + payload


def fixture(name):
    value = json.loads((FIXTURES / name).read_text('utf-8'))
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != value['length'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('retained fixture identity mismatch')
    return raw


def item_bodies():
    raw = fixture('4627-InventoryUpdate.json')
    return [raw[7:75], raw[77:145]]


class ClassicSkillSchemaTests(unittest.TestCase):
    def test_real_owned_skill_list_has_31_exact_records_and_boolean_flags(self):
        fields = parse_classic_skills(fixture('40-SkillList.json'))
        self.assertEqual(fields['event'], 'skill_list')
        self.assertEqual(fields['confirmation'], 'server-list')
        rows = fields['skills']
        self.assertEqual(len(rows), 31)
        self.assertEqual((rows[0]['skill_id'], rows[0]['skill_level']), (118, 1))
        self.assertEqual((rows[-1]['skill_id'], rows[-1]['skill_level']), (5491, 1))
        self.assertEqual(sum(row['passive'] for row in rows), 24)
        self.assertTrue(all(row['disabled'] == row['enchantable'] == 0 for row in rows))
        self.assertTrue(all('cooldown_group' not in row for row in rows))

    def test_server_list_populates_existing_owned_skill_state(self):
        state = Skills()
        state.reset('fixture')
        state.apply([dict(direction='server', time='2026-11-22T00:00:00Z',
                          fields=parse_classic_skills(fixture('40-SkillList.json')))])
        snapshot = state.snapshot()
        self.assertTrue(snapshot['full_list_received'])
        self.assertEqual(len(snapshot['skills']), 31)
        self.assertEqual(next(row for row in snapshot['skills'] if row['skill_id'] == 146)['skill_level'], 4)

    def test_passive_disabled_enchantable_are_separate_boolean_fields(self):
        raw = packet(0x5f, struct.pack('<I', 1) + struct.pack('<IIIBB', 0, 320, 12345, 1, 1))
        self.assertEqual(parse_classic_skills(raw)['skills'],
                         [dict(skill_id=12345, skill_level=320, passive=0, disabled=1, enchantable=1)])

    def test_nonboolean_flags_are_rejected_instead_of_interpreted_as_bitsets(self):
        for values in ((2, 1, 10, 0, 0), (0, 1, 10, 2, 0), (0, 1, 10, 0, 2)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                parse_classic_skills(packet(0x5f, struct.pack('<I', 1) + struct.pack('<IIIBB', *values)))

    def test_skill_count_and_all_byte_boundaries_are_strict(self):
        raw = fixture('40-SkillList.json')
        for truncated in (raw[:3], raw[:6], raw[:-1], raw + b'\x00'):
            with self.subTest(size=len(truncated)), self.assertRaises(ValueError):
                parse_classic_skills(truncated)
        with self.assertRaises(ValueError):
            parse_classic_skills(packet(0x5f, struct.pack('<I', 0xffffffff)))
        with self.assertRaises(ValueError):
            parse_classic_skills(packet(0x5f, raw[3:] + b'\0\0\0\0'))

    def test_empty_skill_list_is_valid_and_other_opcodes_are_unhandled(self):
        self.assertEqual(parse_classic_skills(packet(0x5f, bytes(4)))['skills'], [])
        for raw in (b'', b'\1', packet(0x21, bytes(2))):
            self.assertIsNone(parse_classic_skills(raw))


class ClassicInventorySchemaTests(unittest.TestCase):
    def test_real_update_ids_slots_u64_amounts_and_signed_sentinels(self):
        fields = parse_classic_inventory(fixture('4627-InventoryUpdate.json'))
        self.assertEqual(fields['event'], 'inventory_update')
        self.assertFalse(fields['full_list'])
        self.assertEqual(fields['record_size'], 70)
        self.assertEqual([(row['object_id'], row['item_id'], row['slot'], row['amount']) for row in fields['items']],
                         [(268555853, 3493, 6, 4858), (268555854, 57, 7, 9190763)])
        for row in fields['items']:
            self.assertEqual(row['action_name'], 'modified')
            self.assertEqual(row['mana'], -1)
            self.assertEqual(row['remaining_time'], -9999)
            self.assertEqual(row['attack_element_type'], -2)
            self.assertEqual(row['defense_elements'], [0] * 6)
            self.assertEqual(row['enchant_options'], [0] * 3)

    def test_all_three_real_updates_populate_existing_inventory_state(self):
        state = Inventory()
        state.reset('fixture')
        fixtures = [('4627-InventoryUpdate.json', 4858, 9190763),
                    ('5154-InventoryUpdate.json', 4984, 9265763),
                    ('5340-InventoryUpdate.json', 5032, 9285763)]
        for index, (filename, expected_item, expected_adena) in enumerate(fixtures, 1):
            fields = parse_classic_inventory(fixture(filename))
            state.apply([dict(direction='server', frame=index, fields=fields)])
            rows = state.snapshot()['items']
            self.assertEqual([(row['item_id'], row['amount']) for row in rows],
                             [(3493, expected_item), (57, expected_adena)])
            self.assertFalse(state.snapshot()['full_list_received'])

    def test_item_list_reuses_real_68_byte_records_and_marks_full_coverage(self):
        raw = packet(0x11, struct.pack('<HH', 1, 2) + b''.join(item_bodies()) + bytes(2))
        fields = parse_classic_inventory(raw)
        self.assertTrue(fields['full_list'])
        self.assertEqual(fields['record_size'], 68)
        self.assertEqual(fields['list_type'], 1)
        self.assertEqual([row['item_id'] for row in fields['items']], [3493, 57])
        self.assertTrue(all(row['action_name'] == 'present' for row in fields['items']))
        self.assertIsNone(fields['inventory_block_mode'])
        self.assertEqual(fields['blocked_item_ids'], [])

    def test_actual_full_item_list_has_22_items_with_real_ids_and_amounts(self):
        raw = fixture('20795-ItemList.json')
        self.assertEqual(len(raw), 1505)
        fields = parse_classic_inventory(raw)
        self.assertTrue(fields['full_list'])
        self.assertEqual(len(fields['items']), 22)
        by_object = {row['object_id']: row for row in fields['items']}
        self.assertEqual((by_object[268555853]['item_id'], by_object[268555853]['amount']), (3493, 7355))
        self.assertEqual((by_object[268555854]['item_id'], by_object[268555854]['amount']), (57, 14315313))
        self.assertEqual((by_object[268555796]['item_id'], by_object[268555796]['amount']), (1539, 1000))
        self.assertEqual([row['amount'] for row in fields['items'] if row['item_id'] == 728], [1000])
        self.assertEqual(sum(row['item_id'] == 889 for row in fields['items']), 2)
        self.assertEqual(fields['blocked_item_ids'], [])

    def test_actual_full_list_replaces_stale_inventory_and_closes_coverage_gap(self):
        state = Inventory()
        state.reset('full-fixture')
        state.apply([dict(direction='server', fields=dict(event='inventory_update', items=[
            dict(object_id=1, item_id=999, slot=1, amount=1, action=1)]))])
        state.gap()
        fields = parse_classic_inventory(fixture('20795-ItemList.json'))
        state.apply([dict(direction='server', frame=20795, fields=fields)])
        result = state.snapshot()
        self.assertEqual(len(result['items']), 22)
        self.assertNotIn(1, {row['object_id'] for row in result['items']})
        self.assertTrue(result['full_list_received'])
        self.assertFalse(result['coverage_gap'])
        self.assertEqual(result['revision'], 1)
        state.apply([dict(direction='server', fields=parse_classic_inventory(fixture('4627-InventoryUpdate.json')))])
        self.assertEqual(state.snapshot()['revision'], 1)
        state.apply([dict(direction='server', fields=fields)])
        self.assertEqual(state.snapshot()['revision'], 2)
        state.reset('next-session')
        self.assertEqual(state.snapshot()['revision'], 0)

    def test_item_list_block_mode_and_ids_follow_primary_serializer(self):
        tail = struct.pack('<HBII', 2, 1, 57, 3493)
        raw = packet(0x11, struct.pack('<HH', 0, 1) + item_bodies()[0] + tail)
        fields = parse_classic_inventory(raw)
        self.assertEqual(fields['inventory_block_mode'], 1)
        self.assertEqual(fields['blocked_item_ids'], [57, 3493])
        self.assertEqual(fields['items'][0]['amount'], 4858)

    def test_u64_amount_and_nonzero_item_tail_fields_are_preserved(self):
        body = bytearray(item_bodies()[0])
        struct.pack_into('<Q', body, 12, (1 << 40) + 3)
        struct.pack_into('<HHH', body, 20, 1, 2, 1)
        struct.pack_into('<IHHIii', body, 26, 0x8000, 16, 5, 0xdeadbeef, 120, 3600)
        struct.pack_into('<hH6H3H', body, 46, 3, 150, 1, 2, 3, 4, 5, 6, 100, 200, 300)
        fields = parse_classic_inventory(packet(0x21, struct.pack('<HH', 1, 1) + body))
        row = fields['items'][0]
        self.assertEqual(row['amount'], (1 << 40) + 3)
        self.assertEqual((row['body_part'], row['enchant_level'], row['custom_type2']), (0x8000, 16, 5))
        self.assertEqual((row['augmentation_id'], row['mana'], row['remaining_time']), (0xdeadbeef, 120, 3600))
        self.assertEqual((row['attack_element_type'], row['attack_element_power']), (3, 150))
        self.assertEqual(row['defense_elements'], [1, 2, 3, 4, 5, 6])
        self.assertEqual(row['enchant_options'], [100, 200, 300])

    def test_add_modify_remove_and_unknown_action_keep_the_actual_wire_code(self):
        for action, name in ((1, 'added'), (2, 'modified'), (3, 'removed'), (0, 'unknown')):
            with self.subTest(action=action):
                raw = packet(0x21, struct.pack('<HH', 1, action) + item_bodies()[0])
                row = parse_classic_inventory(raw)['items'][0]
                self.assertEqual((row['action'], row['action_name']), (action, name))

    def test_update_rejects_wrong_count_truncation_extra_tail_and_wrong_declared_length(self):
        raw = fixture('4627-InventoryUpdate.json')
        for bad in (raw[:3], raw[:4], raw[:-1], raw + b'\0',
                    packet(0x21, struct.pack('<H', 3) + raw[5:]),
                    packet(0x21, raw[3:] + b'\0')):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                parse_classic_inventory(bad)

    def test_item_list_rejects_missing_or_inconsistent_block_and_wrong_count(self):
        bodies = b''.join(item_bodies())
        for payload in (struct.pack('<HH', 1, 2) + bodies,
                        struct.pack('<HH', 1, 3) + bodies + bytes(2),
                        struct.pack('<HH', 1, 2) + bodies + struct.pack('<H', 1),
                        struct.pack('<HH', 1, 2) + bodies + struct.pack('<HB', 1, 0),
                        struct.pack('<HH', 1, 2) + bodies + bytes(3)):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                parse_classic_inventory(packet(0x11, payload))

    def test_empty_full_list_and_empty_update_are_distinct(self):
        full = parse_classic_inventory(packet(0x11, bytes(6)))
        partial = parse_classic_inventory(packet(0x21, bytes(2)))
        self.assertTrue(full['full_list'])
        self.assertFalse(partial['full_list'])
        self.assertEqual(full['items'], partial['items'])

    def test_other_opcodes_are_unhandled(self):
        for raw in (b'', b'\1\0', packet(0x5f, bytes(4))):
            self.assertIsNone(parse_classic_inventory(raw))


if __name__ == '__main__':
    unittest.main()
