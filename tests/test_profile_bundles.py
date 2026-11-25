"""Portable profile bundles preserve built-ins and reject invalid imports atomically."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor import cipher_profiles
from l2_monitor.cipher_profiles import CipherProfiles
from l2_monitor.profile_bundles import FORBIDDEN, export_profiles, import_profiles


class ProfileBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / 'installed-profiles'
        self.patch = patch.object(cipher_profiles, 'USER_PROFILE_ROOT', self.destination)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.base = CipherProfiles()
        self.zip_path = self.root / 'profiles.zip'

    def manifest(self, checksum='a' * 64, identifier='new-build'):
        entry = dict(id=identifier, engine_sha256=checksum, algorithm='l2xor16-u64',
                     profile='clients/' + checksum + '.json', evidence=['docs/new-build.md'], validation='candidate')
        body = dict(id=identifier, engine_sha256=checksum, algorithm='l2xor16-u64',
                    root_pointer_rva=1234, outgoing_key_offset=64,
                    fingerprints=[dict(rva=42, bytes='aabb')])
        return dict(schema=1, algorithms=self.base.algorithms, profiles=[entry]), {entry['profile']: body}

    def write_zip(self, manifest, bodies, extra=None):
        with zipfile.ZipFile(self.zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('registry.json', json.dumps(manifest))
            for name, body in bodies.items():
                archive.writestr(name, json.dumps(body))
            for name, data in (extra or {}).items():
                archive.writestr(name, data)

    def snapshot(self):
        return {str(path.relative_to(self.destination)): path.read_bytes()
                for path in self.destination.rglob('*') if path.is_file()}

    def reject_unchanged(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            import_profiles(self.zip_path, destination=self.destination, existing=self.base)
        self.assertEqual(self.snapshot(), before)

    def test_export_roundtrip_skips_both_builtins_without_changing_registry_or_sources(self):
        entries = self.base.profiles
        paths = [self.base.path] + [self.base.resolve_profile(e['engine_sha256'], verified_only=False) for e in entries]
        before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        result = export_profiles(self.zip_path, self.base)
        self.assertGreaterEqual(result['profiles'], 2)
        self.assertEqual(self.base.profiles, entries)
        imported = import_profiles(self.zip_path, destination=self.destination, existing=self.base)
        self.assertEqual(imported, dict(imported=0, skipped=len(entries)))
        self.assertFalse(self.destination.exists())
        self.assertEqual({str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}, before)
        with zipfile.ZipFile(self.zip_path) as archive:
            self.assertTrue(all(name == 'registry.json' or name.startswith('clients/') and name.endswith('.json')
                                for name in archive.namelist()))

    def test_new_profile_survives_reload_from_external_overlay_and_can_be_reexported(self):
        manifest, bodies = self.manifest()
        expected = copy.deepcopy(next(iter(bodies.values())))
        self.write_zip(manifest, bodies)
        self.assertEqual(import_profiles(self.zip_path, destination=self.destination, existing=self.base),
                         dict(imported=1, skipped=0))
        loaded = CipherProfiles()
        checksum = expected['engine_sha256']
        self.assertIsNone(loaded.find(checksum))  # Import does not promote a candidate to verified.
        self.assertEqual(loaded.load_profile(checksum, verified_only=False), expected)
        self.assertTrue(loaded.resolve_profile(checksum, verified_only=False).is_relative_to(self.destination.resolve()))
        self.assertEqual(len(loaded.profiles), len(self.base.profiles) + 1)
        export_profiles(self.root / 'again.zip', loaded)
        self.assertEqual(import_profiles(self.zip_path, destination=self.destination, existing=loaded),
                         dict(imported=0, skipped=1))

    def test_archive_extra_executable_is_rejected_without_installing_first_valid_profile(self):
        manifest, bodies = self.manifest()
        self.write_zip(manifest, bodies, {'helper.exe': b'MZ'})
        self.reject_unchanged()

    def test_archive_missing_profile_is_rejected(self):
        manifest, _ = self.manifest()
        self.write_zip(manifest, {})
        self.reject_unchanged()

    def test_archive_missing_manifest_has_consistent_validation_error(self):
        with zipfile.ZipFile(self.zip_path, 'w') as archive:
            archive.writestr('clients/example.json', '{}')
        self.reject_unchanged()

    def test_duplicate_archive_names_are_rejected(self):
        manifest, bodies = self.manifest()
        self.write_zip(manifest, bodies)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.zip_path, 'a') as archive:
                archive.writestr('registry.json', json.dumps(manifest))
        self.reject_unchanged()

    def test_absolute_and_parent_traversal_profile_paths_are_rejected(self):
        for path in ('../outside.json', 'clients/../../outside.json', r'..\outside.json',
                     'C:/outside.json', '/outside.json', r'\\host\share\outside.json'):
            with self.subTest(path=path):
                manifest, bodies = self.manifest()
                body = next(iter(bodies.values()))
                manifest['profiles'][0]['profile'] = path
                self.write_zip(manifest, {path: body})
                self.reject_unchanged()
        self.assertFalse((self.root / 'outside.json').exists())

    def test_nested_session_keys_and_counters_are_rejected_atomically(self):
        for forbidden in sorted(FORBIDDEN):
            with self.subTest(field=forbidden):
                manifest, bodies = self.manifest()
                next(iter(bodies.values()))['nested'] = [{'state': {forbidden: 'private-session-data'}}]
                self.write_zip(manifest, bodies)
                self.reject_unchanged()

    def test_profile_identity_algorithm_or_checksum_mismatch_is_rejected(self):
        for field, value in (('id', 'other'), ('engine_sha256', 'b' * 64), ('algorithm', 'plain')):
            with self.subTest(field=field):
                manifest, bodies = self.manifest()
                next(iter(bodies.values()))[field] = value
                self.write_zip(manifest, bodies)
                self.reject_unchanged()

    def test_later_invalid_profile_rejects_entire_bundle_without_partial_install(self):
        manifest, bodies = self.manifest()
        second_manifest, second_bodies = self.manifest('b' * 64, 'second-build')
        next(iter(second_bodies.values()))['nested'] = dict(incoming_key='private')
        manifest['profiles'].extend(second_manifest['profiles'])
        bodies.update(second_bodies)
        self.write_zip(manifest, bodies)
        self.reject_unchanged()
        self.assertFalse((self.destination / 'installed').exists())

    def test_duplicate_profile_id_or_checksum_is_rejected(self):
        for checksum, identifier in (('b' * 64, 'new-build'), ('a' * 64, 'second-build')):
            with self.subTest(checksum=checksum, identifier=identifier):
                manifest, bodies = self.manifest()
                second, extra = self.manifest(checksum, identifier)
                manifest['profiles'].extend(second['profiles'])
                bodies.update(extra)
                self.write_zip(manifest, bodies)
                self.reject_unchanged()

    def test_conflicting_builtin_id_cannot_replace_existing_profile(self):
        manifest, bodies = self.manifest(identifier=self.base.profiles[0]['id'])
        self.write_zip(manifest, bodies)
        self.reject_unchanged()

    def test_oversized_profile_is_rejected_before_install(self):
        manifest, bodies = self.manifest()
        next(iter(bodies.values()))['padding'] = 'x' * (2 * 1024 * 1024)
        self.write_zip(manifest, bodies)
        self.reject_unchanged()

    def test_export_rejects_session_state_before_replacing_existing_destination(self):
        manifest, bodies = self.manifest()
        registry = Mock()
        registry.algorithms = manifest['algorithms']
        registry.profiles = manifest['profiles']
        profile = next(iter(bodies.values()))
        profile['checkpoint'] = dict(outgoing_key='private')
        registry.load_profile.return_value = profile
        self.zip_path.write_bytes(b'existing-export')
        with self.assertRaises(ValueError):
            export_profiles(self.zip_path, registry)
        self.assertEqual(self.zip_path.read_bytes(), b'existing-export')


if __name__ == '__main__':
    unittest.main()
