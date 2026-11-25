"""Real authenticated HTTP ingress reaches the same monitor store and models."""
import hashlib
import json
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.engine import Monitor

FIXTURES = Path(__file__).parent / 'fixtures/classic-character'


def fixture(name):
    value = json.loads((FIXTURES / name).read_text('utf-8'))
    raw = bytes.fromhex(value['raw_hex'])
    if len(raw) != value['length'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('retained monitor fixture identity mismatch')
    return raw


class SourceMonitorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.patchers = [
            patch('l2_monitor.engine.DATA_ROOT', self.root),
            patch('l2_monitor.cipher_profiles.USER_PROFILE_ROOT', self.root / 'profiles'),
            patch('l2_monitor.engine.select_process', side_effect=AssertionError('Server source must not inspect the game')),
            patch('l2_monitor.engine.NativeCapture', side_effect=AssertionError('Server source must not start Npcap')),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.monitor = Monitor(interval=.1, library_path=self.root / 'library.json')
        self.addCleanup(self.close_monitor)
        self.config = None
        self.userinfo = fixture('2703-userinfo.json')
        self.inventory = fixture('20795-ItemList.json')
        self.skills = fixture('40-SkillList.json')

    def close_monitor(self):
        self.monitor.stop()
        self.monitor.bridge.close()
        for worker in (self.monitor.packet_queue_runner, self.monitor.skill_actions,
                       self.monitor.auto_heal, self.monitor.auto_pickup,
                       self.monitor.newbie_buff, self.monitor.inventory_drop):
            worker.close()

    def wait_for(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.01)
        self.fail('Monitor source did not reach the expected state: ' + repr(self.monitor.status()))

    def start_server(self):
        self.assertTrue(self.monitor.start(source='server'))
        self.wait_for(lambda: self.monitor.status().get('active_source') == 'server'
                      and self.monitor.status().get('session_id', '').startswith('server-wait:'))
        self.config = self.monitor.bridge_start()
        self.assertTrue(self.config['endpoint'].startswith('http://127.0.0.1:'))
        self.assertTrue(self.config['token'])

    def payload(self, raws, *, first=1, session='publisher-A', protocol='classic-h5'):
        return dict(schema=1, session_id=session, protocol=protocol, packets=[
            dict(sequence=first + index, direction='server', hex=raw.hex(), timestamp=1795337000.125 + index)
            for index, raw in enumerate(raws)])

    def post(self, payload, expected=200):
        request = urllib.request.Request(self.config['endpoint'], json.dumps(payload).encode('utf-8'),
                                         headers={'Content-Type': 'application/json',
                                                  self.config['token_header']: self.config['token']}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                status, body = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            status, body = error.code, json.load(error)
        self.assertEqual(status, expected, body)
        return body

    def test_real_server_ingress_populates_shared_character_inventory_skills_and_packet_store(self):
        self.start_server()
        result = self.post(self.payload([self.userinfo, self.inventory, self.skills]))
        self.assertEqual((result['accepted'], result['last_sequence'], result['gap']), (3, 3, False))
        status = self.monitor.status()
        self.assertEqual((status['active_source'], status['state'], status['protocol']), ('server', 'live', 'classic-h5'))
        self.assertFalse(status['actions_supported'])
        self.assertFalse(status['skill_actions_supported'])
        self.assertEqual((status['captured_frames'], status['validated_windows'], status['sync_errors']), (3, 1, 0))
        self.assertEqual(self.monitor.store.stats()['total'], 3)
        character = self.monitor.character_status()
        self.assertEqual((character['character'], character['level'], character['hp_percent']), ('X501', 38, 100))
        inventory = self.monitor.inventory.snapshot()
        skills = self.monitor.skills.snapshot()
        self.assertEqual((len(inventory['items']), inventory['full_list_received']), (22, True))
        self.assertEqual((len(skills['skills']), skills['full_list_received']), (31, True))
        self.assertEqual({character['session_id'], inventory['session_id'], skills['session_id']}, {status['session_id']})
        for record in self.monitor.store.export():
            self.assertEqual(record['capture_source'], 'server')
            self.assertTrue(record['source_authenticated'])
            self.assertFalse(record['cipher_end_state_verified'])
            self.assertFalse(record['plaintext_verified'])
            self.assertFalse(record['actions_supported'])
        self.assertFalse(status['verification']['cipher_end_states_verified'])

    def test_raw_source_preserves_bytes_without_guessing_classic_fields_or_model_state(self):
        self.start_server()
        self.post(self.payload([self.userinfo, self.inventory, self.skills], protocol='raw'))
        self.assertEqual(self.monitor.status()['protocol'], 'raw')
        self.assertIsNone(self.monitor.character_status())
        self.assertEqual(self.monitor.inventory.snapshot()['items'], [])
        self.assertEqual(self.monitor.skills.snapshot()['skills'], [])
        for record, raw in zip(self.monitor.store.export(), (self.userinfo, self.inventory, self.skills)):
            self.assertEqual(record['fields'], {})
            self.assertEqual(record['schema_status'], 'raw')
            self.assertEqual(record['raw_hex'], raw.hex())
            self.assertEqual(record['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertTrue(record['source_authenticated'])
            self.assertFalse(record['cipher_end_state_verified'])

    def test_a_different_publisher_cannot_mix_models_until_capture_restart(self):
        self.start_server()
        self.post(self.payload([self.userinfo]))
        first_session = self.monitor.status()['session_id']
        self.post(self.payload([self.skills], session='publisher-B'), expected=409)
        self.assertEqual(self.monitor.store.stats()['total'], 1)
        self.assertEqual(self.monitor.status()['session_id'], first_session)
        self.assertEqual(self.monitor.bridge.snapshot()['sessions'], 1)
        self.monitor.stop()
        self.start_server()
        self.post(self.payload([self.skills], session='publisher-B'))
        self.assertNotEqual(self.monitor.status()['session_id'], first_session)
        self.assertIsNone(self.monitor.character_status())
        self.assertEqual(self.monitor.inventory.snapshot()['items'], [])
        self.assertEqual(len(self.monitor.skills.snapshot()['skills']), 31)
        self.assertEqual(self.monitor.store.stats()['total'], 2)
        self.assertEqual(self.monitor.bridge.snapshot()['sessions'], 2)

    def test_duplicate_sequence_rejects_without_publication_or_model_changes(self):
        self.start_server()
        payload = self.payload([self.userinfo, self.inventory, self.skills])
        self.post(payload)
        inventory, skills = self.monitor.inventory.snapshot(), self.monitor.skills.snapshot()
        self.post(payload, expected=409)
        self.assertEqual(self.monitor.store.stats()['total'], 3)
        self.assertEqual(self.monitor.inventory.snapshot(), inventory)
        self.assertEqual(self.monitor.skills.snapshot(), skills)
        self.assertEqual(self.monitor.status()['sync_errors'], 0)
        self.assertEqual(self.monitor.bridge.snapshot()['accepted_packets'], 3)

    def test_sequence_gap_marks_models_and_requires_fresh_complete_state_to_recover(self):
        self.start_server()
        self.post(self.payload([self.userinfo, self.inventory, self.skills]))
        result = self.post(self.payload([b'\x03\x00\xa5'], first=5))
        self.assertTrue(result['gap'])
        self.assertEqual(self.monitor.status()['sync_errors'], 1)
        self.assertTrue(self.monitor.status()['verification']['sequence_gap'])
        self.assertTrue(self.monitor.inventory.snapshot()['coverage_gap'])
        self.assertTrue(self.monitor.skills.snapshot()['coverage_gap'])
        self.assertIsNone(self.monitor.character_status())
        self.post(self.payload([self.userinfo, self.inventory, self.skills], first=6))
        self.assertFalse(self.monitor.inventory.snapshot()['coverage_gap'])
        self.assertFalse(self.monitor.skills.snapshot()['coverage_gap'])
        self.assertIsNotNone(self.monitor.character_status())
        self.assertEqual(self.monitor.status()['sync_errors'], 1)

    def test_stopped_monitor_rejects_ingress_and_restart_preserves_bridge_sequence_history(self):
        self.start_server()
        self.post(self.payload([self.userinfo]))
        old_session = self.monitor.status()['session_id']
        endpoint, token = self.config['endpoint'], self.config['token']
        self.monitor.stop()
        self.post(self.payload([self.skills], first=2), expected=409)
        self.assertEqual(self.monitor.store.stats()['total'], 1)
        self.assertEqual(self.monitor.bridge.snapshot()['accepted_packets'], 1)
        self.start_server()
        self.assertEqual((self.config['endpoint'], self.config['token']), (endpoint, token))
        self.post(self.payload([self.skills], first=2))
        self.assertNotEqual(self.monitor.status()['session_id'], old_session)
        self.assertEqual(self.monitor.status()['sync_errors'], 0)
        self.assertEqual(self.monitor.store.stats()['total'], 2)
        self.assertIsNone(self.monitor.character_status())
        self.assertEqual(self.monitor.bridge.snapshot()['accepted_packets'], 2)

    def test_malformed_http_batch_is_atomic_and_does_not_consume_sequence(self):
        self.start_server()
        invalid = self.payload([self.userinfo, self.skills])
        invalid['packets'][1]['hex'] = '04005f'
        self.post(invalid, expected=400)
        self.assertEqual(self.monitor.store.stats()['total'], 0)
        self.assertEqual(self.monitor.bridge.snapshot()['sessions'], 0)
        self.post(self.payload([self.userinfo]))
        self.assertEqual(self.monitor.store.stats()['total'], 1)
        self.assertEqual(self.monitor.status()['sync_errors'], 0)

    def test_source_configuration_validates_mode_and_rejects_changes_during_capture(self):
        for mode in ('unknown', 'native', '', None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.monitor.configure_source(mode)
        self.monitor.configure_source('server')
        self.assertEqual(self.monitor.source_status()['mode'], 'server')
        self.start_server()
        with self.assertRaisesRegex(ValueError, 'Остановите захват'):
            self.monitor.configure_source('network')
        self.assertFalse(self.monitor.start(source='network'))
        self.assertEqual(self.monitor.source_status()['mode'], 'server')

    def test_public_source_status_has_no_secret_but_explicit_bridge_configuration_does(self):
        self.start_server()
        status = self.monitor.source_status()
        serialized = json.dumps(status, ensure_ascii=False)
        self.assertNotIn(self.config['token'], serialized)
        self.assertNotIn('"token":', serialized)
        self.assertEqual(self.monitor.bridge_configuration()['token'], self.config['token'])
        self.assertEqual(status['bridge']['endpoint'], self.config['endpoint'])
        self.assertGreaterEqual(len(status['profiles']), 2)
        self.assertEqual({row['algorithm'] for row in status['profiles']}, {'asterios', 'l2xor16-u64'})
        self.assertEqual({row['id'] for row in status['protocols']}, {'classic-h5', 'asterios-448', 'raw'})

    def test_auto_prefers_a_supported_plaintext_adapter_without_starting_network_capture(self):
        engine = self.root / 'fixture-client' / 'Engine.dll'
        engine.parent.mkdir()
        engine.write_bytes(b'fixture-build-bytes')
        process = dict(pid=12345, create_time=1, exe=str(engine.parent / 'l2.exe'))
        profile = dict(id='fixture-build', algorithm='l2xor16-u64')
        with patch('l2_monitor.engine.select_process', return_value=(process, {'remote_port': 7777})), \
                patch('l2_monitor.engine.CipherProfiles') as registry, \
                patch('l2_monitor.engine.supports_tap', return_value=True), \
                patch('l2_monitor.engine.select_interface') as interface, \
                patch.object(self.monitor, '_plaintext_session', side_effect=lambda *_: self.monitor.stop_event.set()) as tap:
            registry.return_value.load_profile.return_value = profile
            self.assertTrue(self.monitor.start(source='auto'))
            self.wait_for(lambda: not self.monitor.status()['running'])
            tap.assert_called_once_with(process, {'remote_port': 7777}, profile)
            registry.return_value.load_profile.assert_called_once_with(hashlib.sha256(engine.read_bytes()).hexdigest())
            interface.assert_not_called()

    def test_auto_uses_network_profile_if_supported_plaintext_adapter_cannot_attach(self):
        engine = self.root / 'fixture-client' / 'Engine.dll'
        engine.parent.mkdir()
        engine.write_bytes(b'fixture-build-bytes')
        process = dict(pid=12345, create_time=1, exe=str(engine.parent / 'l2.exe'))
        endpoint = dict(remote_port=7777)
        profile = dict(id='fixture-build', algorithm='l2xor16-u64')
        with patch('l2_monitor.engine.select_process', return_value=(process, endpoint)), \
                patch('l2_monitor.engine.CipherProfiles') as registry, \
                patch('l2_monitor.engine.supports_tap', return_value=True), \
                patch('l2_monitor.engine.select_interface', return_value={'device': 'fixture-device'}), \
                patch.object(self.monitor, '_plaintext_session', side_effect=ValueError('fixture-adapter-unavailable')), \
                patch.object(self.monitor, '_session', side_effect=lambda *_: self.monitor.stop_event.set()) as network:
            registry.return_value.load_profile.return_value = profile
            self.assertTrue(self.monitor.start(source='auto'))
            self.wait_for(lambda: not self.monitor.status()['running'])
            network.assert_called_once_with(process, endpoint, {'device': 'fixture-device'}, profile)
            self.assertIn('fixture-adapter-unavailable', self.monitor.status()['source_fallback'])


if __name__ == '__main__':
    unittest.main()
