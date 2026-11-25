import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.classic_skill_menu import SkillMenu, parse_classic_skill_menu, parse_learn_command


FIXTURES = Path(__file__).parent / 'fixtures/classic-skill-menu'
CLASS_COMMAND = '_bbslearnSkills;learn;129;486;1;2;;ALL;ALL'
SEARCH_COMMAND = '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_Wind Walk'


def fixture(name):
    value = json.loads((FIXTURES / (name + '.json')).read_text('utf-8'))
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != value['length'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('community-board fixture identity mismatch')
    return value, raw


def board(fragment, number=101):
    text = '\0'.join(['bypass _bbshome'] * 8 + [str(number) + '\x08' + fragment, ''])
    body = b'\x7b\x01' + text.encode('utf-16le')
    return struct.pack('<H', len(body) + 2) + body


def bypass(command):
    body = b'\x23' + (command + '\0').encode('utf-16le')
    return struct.pack('<H', len(body) + 2) + body


def parsed_observation(raw, direction='server'):
    return dict(direction=direction, time='fixture-time', fields=parse_classic_skill_menu(raw, direction))


class SkillMenuParsingTests(unittest.TestCase):
    def test_real_manual_learn_command_is_standard_request_confirmation(self):
        value, raw = fixture('manual-learn')
        fields = parse_classic_skill_menu(raw, value['direction'])
        self.assertEqual(fields['event'], 'skill_learn_request')
        self.assertEqual((fields['skill_id'], fields['skill_level'], fields['class_id']), (486, 1, 129))
        self.assertEqual(fields['command'], CLASS_COMMAND)
        self.assertEqual(fields['list_type'], 0)
        self.assertEqual(fields['method'], 'community-board')

    def test_real_class_board_contains_exact_offers_in_action_attributes(self):
        _, raw = fixture('manual-board101')
        fields = parse_classic_skill_menu(raw, 'server')
        self.assertEqual(len(fields['offers']), 10)
        self.assertEqual(fields['offers'][0], dict(skill_id=1433, skill_level=1, class_id=129,
                         command='_bbslearnSkills;learn;129;1433;1;2;;ALL;ALL'))
        self.assertEqual(fields['board_id'], 101)

    def test_search_route_preserves_spaces_and_underscores_in_query(self):
        for query in ('Wind Walk', 'Wind_Walk', 'Wind Walk_test'):
            command = '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_' + query
            fields = parse_learn_command(command)
            self.assertEqual((fields['class_id'], fields['skill_id'], fields['skill_level']), (15, 1204, 1))
            self.assertEqual(fields['query'], query)
            self.assertEqual(fields['command'], command)
            self.assertEqual(parse_classic_skill_menu(bypass(command), 'client')['command'], command)

    def test_root_advertises_name_search_and_numeric_search_does_not_invent_offers(self):
        _, raw = fixture('root-101')
        fields = parse_classic_skill_menu(raw, 'server')
        self.assertTrue(fields['search_available'])
        self.assertIn('_bbslearnSkills_search_ $skillsearch', fields['commands'])
        _, raw = fixture('id-search-101')
        self.assertEqual(parse_classic_skill_menu(raw, 'server')['offers'], [])

    def test_actual_wind_walk_fragments_combine_to_eighteen_server_offered_commands(self):
        fragments = []
        for page in (101, 102, 103):
            _, raw = fixture('wind-walk-' + str(page))
            fragments.append(parse_classic_skill_menu(raw, 'server')['fragment'])
        offers = parse_classic_skill_menu(board(''.join(fragments)), 'server')['offers']
        self.assertEqual(len(offers), 18)
        self.assertIn(dict(skill_id=1204, skill_level=1, class_id=15, command=SEARCH_COMMAND), offers)
        self.assertEqual({row['skill_id'] for row in offers}, {1144, 1204})

    def test_html_escaped_apostrophe_is_retained_as_command_data(self):
        command = '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_Warrior\'s Spirit'
        html = '<button action="bypass ' + command.replace("'", '&#39;') + '">Learn</button>'
        fields = parse_classic_skill_menu(board(html), 'server')
        self.assertEqual(fields['offers'][0]['command'], command)
        self.assertEqual(parse_learn_command(command)['query'], "Warrior's Spirit")
        self.assertEqual(parse_classic_skill_menu(bypass(command), 'client')['command'], command)

    def test_invalid_learn_routes_are_not_normalized_or_generated(self):
        for command in ('bypass ' + CLASS_COMMAND, CLASS_COMMAND + ';extra', CLASS_COMMAND.replace(';;', ';x;'),
                        CLASS_COMMAND.replace(';486;', ';-1;'), CLASS_COMMAND.replace(';1;2;', ';0;2;'),
                        CLASS_COMMAND.replace(';ALL;ALL', ';OTHER;ALL'),
                        '_bbslearnSkills_learnFromSearch_15_1204_1_ACTIVE_ALL_Wind Walk',
                        '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_',
                        SEARCH_COMMAND + '\0bad', '_bbslearnSkills;class;15;1'):
            with self.subTest(command=command):
                self.assertIsNone(parse_learn_command(command))
                if '\0' not in command:
                    self.assertIsNone(parse_classic_skill_menu(bypass(command), 'client'))

    def test_only_complete_action_attributes_provide_offers_not_text_or_comments(self):
        text = '<html>' + CLASS_COMMAND + '<!-- <button action="bypass ' + CLASS_COMMAND + '"> -->'
        self.assertEqual(parse_classic_skill_menu(board(text), 'server')['offers'], [])
        incomplete = '<button action="bypass ' + CLASS_COMMAND
        self.assertEqual(parse_classic_skill_menu(board(incomplete), 'server')['offers'], [])

    def test_malformed_unicode_bounds_terminator_flag_and_navigation_are_rejected(self):
        _, raw = fixture('root-101')
        for bad in (raw[:-1], raw[:-2], raw + b'\0\0', raw[:3]):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                parse_classic_skill_menu(bad, 'server')
        for content in (b'\x7b\x00' + raw[4:], b'\x7b\x01\x00\xd8\0\0',
                        b'\x7b\x01' + '101\x08null\0'.encode('utf-16le')):
            with self.assertRaises(ValueError):
                parse_classic_skill_menu(struct.pack('<H', len(content) + 2) + content, 'server')
        with self.assertRaises(ValueError):
            parse_classic_skill_menu(bypass(CLASS_COMMAND + '\0hidden'), 'client')
        with self.assertRaises(ValueError):
            parse_classic_skill_menu(board('null', number=999), 'server')

    def test_wrong_directions_and_normal_bypasses_remain_unhandled(self):
        _, raw = fixture('manual-board101')
        self.assertIsNone(parse_classic_skill_menu(raw, 'client'))
        self.assertIsNone(parse_classic_skill_menu(bypass(CLASS_COMMAND), 'server'))
        self.assertIsNone(parse_classic_skill_menu(bypass('_bbshome'), 'client'))
        self.assertIsNone(parse_classic_skill_menu(b'', 'server'))


class SkillMenuStateTests(unittest.TestCase):
    def setUp(self):
        self.model = SkillMenu()
        self.model.reset('session-one')

    def apply_fixture(self, name):
        value, raw = fixture(name)
        self.model.apply([dict(value, fields=parse_classic_skill_menu(raw, value['direction']))])

    def test_completed_revision_requires_full_cycle_and_null_pages_preserve_offers(self):
        self.apply_fixture('manual-board101')
        self.assertEqual(self.model.snapshot()['completed_revision'], 0)
        offered = self.model.find(1433, 1)
        self.apply_fixture('root-102')
        self.assertEqual(self.model.snapshot()['completed_revision'], 0)
        self.apply_fixture('root-103')
        self.assertEqual(self.model.snapshot()['completed_revision'], 1)
        self.assertEqual(self.model.find(1433, 1), offered)

    def test_actual_search_merges_fragments_and_keeps_first_offer_for_same_skill_level(self):
        for prefix in ('root', 'wind-walk'):
            for page in (101, 102, 103):
                self.apply_fixture(prefix + '-' + str(page))
        snapshot = self.model.snapshot()
        self.assertEqual(snapshot['completed_revision'], 2)
        self.assertEqual(snapshot['revision'], 6)
        self.assertTrue(snapshot['search_available'])
        self.assertEqual(len(snapshot['offers']), 2)
        self.assertEqual(self.model.find(1204, 1)['command'], SEARCH_COMMAND)
        self.assertIsNone(self.model.find(1204, 2))
        self.assertIsNone(self.model.find(4683, 1))

    def test_action_split_inside_command_is_not_lost_or_fabricated(self):
        command = '_bbslearnSkills;learn;15;9999;1;1;;ALL;ALL'
        html = '<html><button action="bypass ' + command + '">Learn</button></html>'
        split = html.index('9999') + 2
        self.model.apply([parsed_observation(board(html[:split], 101))])
        self.assertIsNone(self.model.find(9999, 1))
        self.model.apply([parsed_observation(board(html[split:], 102)), parsed_observation(board('null', 103))])
        self.assertEqual(self.model.find(9999, 1)['command'], command)
        self.assertEqual(self.model.snapshot()['completed_revision'], 1)

    def test_client_packets_and_mismatched_offer_fields_cannot_create_offers(self):
        _, raw = fixture('manual-board101')
        self.model.apply([dict(direction='client', fields=parse_classic_skill_menu(raw, 'server'))])
        self.model.apply([dict(direction='server', fields=dict(event='skill_menu', offers=[
            dict(skill_id=9999, skill_level=1, class_id=129, command=CLASS_COMMAND)]))])
        self.assertEqual(self.model.snapshot()['offers'], [])

    def test_gap_and_session_reset_clear_offers_search_and_completion(self):
        for page in (101, 102, 103):
            self.apply_fixture('root-' + str(page))
        self.apply_fixture('manual-board101')
        self.model.gap()
        self.assertEqual(self.model.snapshot()['offers'], [])
        self.assertEqual(self.model.snapshot()['completed_revision'], 0)
        self.assertFalse(self.model.snapshot()['search_available'])
        self.assertTrue(self.model.snapshot()['coverage_gap'])
        self.model.reset('session-two')
        self.assertEqual(self.model.snapshot()['session_id'], 'session-two')
        self.assertEqual(self.model.snapshot()['revision'], 0)
        self.assertIsNone(self.model.snapshot()['last_board_time'])

    def test_missing_first_page_cannot_complete_cycle_or_supply_fragment_offers(self):
        self.apply_fixture('wind-walk-102')
        self.apply_fixture('wind-walk-103')
        self.assertEqual(self.model.snapshot()['completed_revision'], 0)
        self.assertEqual(self.model.snapshot()['offers'], [])

    def test_cache_is_bounded_and_snapshot_find_are_detached(self):
        offers = [dict(skill_id=skill, skill_level=1, class_id=15,
                       command=f'_bbslearnSkills;learn;15;{skill};1;1;;ALL;ALL')
                  for skill in range(1, 10002)]
        self.model.apply([dict(direction='server', fields=dict(event='skill_menu', offers=offers))])
        self.assertEqual(len(self.model.snapshot()['offers']), 10000)
        self.assertIsNone(self.model.find(1, 1))
        self.model.find(2, 1)['command'] = 'changed'
        self.model.snapshot()['offers'][0]['command'] = 'changed'
        self.assertIn(';2;1;', self.model.find(2, 1)['command'])


if __name__ == '__main__':
    unittest.main()
