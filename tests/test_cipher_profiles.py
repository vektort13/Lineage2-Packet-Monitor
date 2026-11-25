import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.cipher_profiles import CipherProfiles, load_registry, register_profile, validate_registry


ROOT = Path(__file__).resolve().parents[1]
ASTERIOS = 'f9632145da8b27fcff5c22257c0a2b909e25e02825ba7e82f61a5dfd68c9b665'


def entry(checksum='a' * 64, **changes):
    value = dict(id='test-client', engine_sha256=checksum, algorithm='l2xor16',
                 profile='config/profiles/test.json', evidence=['reports/test/check.json'],
                 validation='candidate')
    value.update(changes)
    return value


class CipherProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'cipher-profiles.json'
        self.original = load_registry(ROOT / 'config/cipher-profiles.json')
        self.path.write_text(json.dumps(self.original), encoding='utf-8')

    def test_existing_asterios_is_verified_with_matching_local_profile(self):
        registry = CipherProfiles()
        found = registry.find(ASTERIOS.upper())
        self.assertEqual(found['algorithm'], 'asterios')
        self.assertEqual(found['validation'], 'verified')
        self.assertEqual(registry.load_profile(ASTERIOS)['engine_sha256'], ASTERIOS)
        self.assertEqual({item['id'] for item in registry.algorithms},
                         {'asterios', 'l2xor16', 'l2xor16-u64', 'plain'})

    def test_available_algorithms_do_not_claim_unknown_engine_support(self):
        registry = CipherProfiles(self.path, root=self.root)
        self.assertIsNone(registry.find('b' * 64))
        self.assertIsNone(registry.resolve_profile('b' * 64))
        self.assertIsNone(registry.load_profile('b' * 64))

    def test_candidate_and_rejected_profiles_are_not_automatic_matches(self):
        for status in ('candidate', 'rejected'):
            with self.subTest(status=status):
                register_profile(entry(validation=status), self.path)
                registry = CipherProfiles(self.path)
                self.assertIsNone(registry.find('a' * 64))
                self.assertEqual(registry.find('a' * 64, verified_only=False)['validation'], status)

    def test_upsert_same_checksum_preserves_unrelated_profiles_and_algorithms(self):
        register_profile(entry(), self.path)
        register_profile(entry('b' * 64, id='other'), self.path)
        before = load_registry(self.path)
        register_profile(entry('A' * 64, validation='verified', notes='retained validation'), self.path)
        after = load_registry(self.path)
        self.assertEqual(len(after['profiles']), len(before['profiles']))
        self.assertEqual(after['algorithms'], before['algorithms'])
        previous = {item['engine_sha256']: item for item in before['profiles']}
        current = {item['engine_sha256']: item for item in after['profiles']}
        for checksum in previous.keys() - {'a' * 64}:
            self.assertEqual(current[checksum], previous[checksum])
        self.assertEqual(current['a' * 64]['validation'], 'verified')
        self.assertEqual(current['a' * 64]['notes'], 'retained validation')

    def test_runtime_read_is_detached_and_does_not_rewrite_registry(self):
        original = self.path.read_bytes()
        registry = CipherProfiles(self.path)
        registry.find(ASTERIOS)['algorithm'] = 'plain'
        registry.profiles.clear()
        registry.algorithms[0]['name'] = 'changed'
        self.assertEqual(registry.find(ASTERIOS)['algorithm'], 'asterios')
        self.assertEqual(self.path.read_bytes(), original)

    def test_operator_rejects_session_state_unknown_algorithms_and_malformed_values(self):
        original = self.path.read_bytes()
        invalid = [entry(incoming_key='00' * 16), entry(session_keys={}),
                   entry(algorithm='auto'), entry(algorithm='unimplemented'),
                   entry(algorithm=[]), entry(engine_sha256='bad'), entry(validation='live'),
                   entry(validation={}), entry(evidence='reports/test'),
                   entry(validation='verified', evidence=[])]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    register_profile(value, self.path)
                self.assertEqual(self.path.read_bytes(), original)

    def test_paths_must_be_local_relative_and_cannot_escape_root(self):
        for path in ('../outside.json', 'config/../../outside.json', 'C:\\outside.json',
                     '\\\\host\\share\\file', '/outside.json', 'https://host/file',
                     'config\\..\\outside.json', '', '.'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    register_profile(entry(profile=path), self.path)
        with self.assertRaises(ValueError):
            register_profile(entry(evidence=['../outside']), self.path)

    def test_atomic_replacement_failure_leaves_old_file_and_no_temporary_files(self):
        original = self.path.read_bytes()
        with patch('l2_monitor.cipher_profiles.os.replace', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError):
                register_profile(entry(), self.path)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_corrupt_existing_registry_is_preserved_instead_of_replaced(self):
        self.path.write_text('{broken', encoding='utf-8')
        original = self.path.read_bytes()
        with self.assertRaises(ValueError):
            register_profile(entry(), self.path)
        self.assertEqual(self.path.read_bytes(), original)

    def test_duplicate_checksum_and_unknown_algorithm_definition_are_rejected(self):
        value = copy.deepcopy(self.original)
        value['profiles'].append(copy.deepcopy(value['profiles'][0]))
        with self.assertRaises(ValueError):
            validate_registry(value)
        value = copy.deepcopy(self.original)
        value['algorithms'].append(dict(id='future', name='Future', implementation='src/future.py'))
        with self.assertRaises(ValueError):
            validate_registry(value)
        value = copy.deepcopy(self.original)
        value['schema'] = True
        with self.assertRaises(ValueError):
            validate_registry(value)

    def test_profile_load_checks_declared_checksum_and_resolves_root(self):
        profile = self.root / 'config/profiles/test.json'
        profile.parent.mkdir(parents=True)
        profile.write_text(json.dumps(dict(engine_sha256='b' * 64)), encoding='utf-8')
        register_profile(entry(validation='verified'), self.path)
        registry = CipherProfiles(self.path, root=self.root)
        self.assertEqual(registry.resolve_profile('a' * 64), profile)
        with self.assertRaises(ValueError):
            registry.load_profile('a' * 64)
        profile.write_text(json.dumps(dict(engine_sha256='a' * 64, layout='saved')), encoding='utf-8')
        self.assertEqual(registry.load_profile('a' * 64)['layout'], 'saved')

    def test_validation_does_not_mutate_input_and_operator_return_is_detached(self):
        value = entry('A' * 64)
        saved = register_profile(value, self.path)
        self.assertEqual(value['engine_sha256'], 'A' * 64)
        saved['evidence'].clear()
        loaded = CipherProfiles(self.path).find('a' * 64, verified_only=False)
        self.assertEqual(loaded['evidence'], ['reports/test/check.json'])


if __name__ == '__main__':
    unittest.main()
