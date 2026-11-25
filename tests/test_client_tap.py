"""Plaintext capture validation and actual native callback contract."""
import copy
import io
import json
import struct
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.client_tap import ClientTap, supports, check_client_tap, native_folder, _runtime_dll


class ClientTapTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.select = self.stack.enter_context(patch('l2_monitor.client_tap.select_process'))
        self.live_type = self.stack.enter_context(patch('l2_monitor.client_tap.ClassicLiveState'))
        self.popen = self.stack.enter_context(patch('l2_monitor.client_tap.subprocess.Popen'))
        self.stack.enter_context(patch('l2_monitor.client_tap.window_thread', return_value=616))
        self.stack.enter_context(patch('l2_monitor.client_tap._runtime_dll', return_value=Path('C:/verified-cache/tap.dll')))
        self.process = dict(pid=123, create_time=456, exe='C:/test/l2.exe')
        self.endpoint = dict(local_ip='192.0.2.1', local_port=4000, remote_ip='198.51.100.1', remote_port=7777)
        self.select.return_value = (self.process, self.endpoint)
        self.profile = dict(plaintext_tap=dict(kind='xor64-vtable', encrypt_rva=0x3da5b0,
            decrypt_rva=0x3da520, encrypt_slot=31, decrypt_slot=32), root_pointer_rva=0x77cd78,
            socket_mode_offset=80, game_socket_offset=72, encryption_enabled_offset=37192,
            socket_vtable_rva=0x5219bc, opcode_map_offset=0xa0d8, extended_map_offset=0xa0e8,
            opcode_map_count=209, extended_map_count=152)
        self.live = self.live_type.return_value; self.live.base = 0x20000000
        self.live._u32.side_effect = [0x1000, 2, 0x2000, 0x205219bc, 1]
        self.live.memory.read.side_effect = [struct.pack('<I', 0x203da5b0), struct.pack('<I', 0x203da520)]
        self.child = MagicMock(); self.child.stdin = io.StringIO(); self.child.wait.return_value = 0
        self.popen.return_value = self.child
        self.tap = ClientTap(self.process, self.endpoint, self.profile)

    def prepare(self, *messages):
        self.child.stdout = io.StringIO('\n'.join(json.dumps(item) for item in messages) + '\n')

    def start(self, *extra):
        self.prepare(dict(started=True, state=2, exception=0), *extra)
        return self.tap.start()

    def batch(self, raw='04005011', direction='client', sequence=1, **extra):
        return dict(packets=[dict(raw_hex=raw, direction=direction, sequence=sequence, timestamp=1795300000.25)],
                    written=sequence, consumed=sequence, dropped=0, invalid=0, active=True, **extra)

    def test_unsupported_adapter_rejected_before_any_process_work(self):
        for field, value in [('kind', 'unknown'), ('encrypt_slot', 30), ('decrypt_rva', -1)]:
            with self.subTest(field=field):
                profile = copy.deepcopy(self.profile); profile['plaintext_tap'][field] = value
                with self.assertRaises(ValueError): ClientTap(self.process, self.endpoint, profile).start()
        self.select.assert_not_called(); self.popen.assert_not_called()

    def test_endpoint_and_process_reuse_never_attach(self):
        for process, endpoint in [(dict(self.process, create_time=457), self.endpoint),
                                  (self.process, dict(self.endpoint, remote_port=7778))]:
            self.select.return_value = (process, endpoint)
            with self.assertRaisesRegex(ValueError, 'connection changed'): self.tap.start()
        self.live_type.assert_not_called(); self.popen.assert_not_called()

    def test_fingerprint_verified_reader_closed_if_callback_changed(self):
        self.live.memory.read.side_effect = [struct.pack('<I', 0x203da5b1), struct.pack('<I', 0x203da520)]
        with self.assertRaisesRegex(ValueError, 'callbacks'): self.tap.start()
        self.live.close.assert_called_once(); self.popen.assert_not_called()

    def test_not_in_game_connection_never_attaches(self):
        self.live._u32.side_effect = [0x1000, 1]
        with self.assertRaisesRegex(ValueError, 'game connection'): self.tap.start()
        self.live.close.assert_called_once(); self.popen.assert_not_called()

    def test_start_verifies_maps_and_does_not_read_or_pass_session_keys(self):
        self.start(dict(closed=True, state=2, exception=0))
        self.live.snapshot.assert_not_called()
        self.assertEqual(self.live._map.call_count, 2)
        arguments = self.popen.call_args.args[0]
        self.assertEqual(arguments[4:], ['8192', str(0x205219bc), '31', '32', str(0x203da5b0),
            str(0x203da520), str(0xa0d8), '209', str(0xa0e8), '152'])
        self.assertFalse(self.tap.snapshot()['keys_exported'])
        self.tap.close(); self.assertFalse(self.tap.snapshot()['active'])

    def test_failed_native_install_does_not_report_active(self):
        self.prepare(dict(started=False, state=-1, exception=1306))
        with self.assertRaisesRegex(RuntimeError, 'did not accept'): self.tap.start()
        self.assertFalse(self.tap.snapshot()['active'])

    def test_validated_batch_preserves_direction_timestamp_and_opcode(self):
        batch = self.batch(); batch['dropped'] = 9
        self.start(batch, dict(closed=True, state=2, exception=0))
        self.assertEqual(self.tap.read(), batch['packets'])
        self.assertEqual(self.tap.snapshot()['dropped'], 9)
        self.tap.close()

    def test_bad_framing_direction_and_nonmonotonic_sequences_rejected(self):
        for changes in [dict(raw='05005011'), dict(direction='peer'), dict(sequence=2), dict(raw='zz')]:
            with self.subTest(changes=changes):
                tap = ClientTap(self.process, self.endpoint, self.profile)
                tap._child = self.child; tap._stats['active'] = True
                tap._messages.put(json.dumps(self.batch(**changes)))
                with self.assertRaisesRegex(RuntimeError, 'framing or sequence'): tap.read()

    def test_bad_counters_and_nonfinite_time_rejected(self):
        for counter, value in [('dropped', -1), ('invalid', '0')]:
            tap = ClientTap(self.process, self.endpoint, self.profile); tap._child = self.child; tap._stats['active'] = True
            batch = self.batch(); batch[counter] = value; tap._messages.put(json.dumps(batch))
            with self.assertRaisesRegex(RuntimeError, 'counter'): tap.read()
        batch = self.batch(); batch['packets'][0]['timestamp'] = float('nan')
        tap = ClientTap(self.process, self.endpoint, self.profile); tap._child = self.child; tap._stats['active'] = True
        tap._messages.put(json.dumps(batch))
        with self.assertRaisesRegex(RuntimeError, 'framing or sequence'): tap.read()

    def test_unconfirmed_detach_is_reported(self):
        self.start(dict(closed=False, state=-1, exception=1306))
        with self.assertRaisesRegex(RuntimeError, 'detachment'): self.tap.close()
        self.assertFalse(self.tap.snapshot()['active'])

    def test_rejected_batch_does_not_commit_valid_prefix_or_counters(self):
        self.tap._child = self.child; self.tap._stats['active'] = True
        batch = self.batch(); batch['packets'].append(dict(batch['packets'][0], sequence=3))
        self.tap._messages.put(json.dumps(batch))
        before = self.tap.snapshot()
        with self.assertRaises(RuntimeError): self.tap.read()
        self.assertEqual(self.tap._last_sequence, 0)
        self.assertEqual(self.tap.snapshot(), before)
        batch = self.batch(); batch['invalid'] = -1
        self.tap._messages.put(json.dumps(batch))
        with self.assertRaises(RuntimeError): self.tap.read()
        self.assertEqual(self.tap._last_sequence, 0)
        self.assertEqual(self.tap.snapshot(), before)

    def test_malformed_profile_types_are_not_supported(self):
        for profile in [None, [], dict(self.profile, plaintext_tap=[]),
                        dict(self.profile, opcode_map_count=True), dict(self.profile, extended_map_count='152')]:
            with self.subTest(profile=profile): self.assertFalse(supports(profile))

    def test_same_wrapper_object_can_restart_without_stale_reader_or_sequence(self):
        self.start(self.batch(), dict(closed=True, state=2, exception=0))
        self.assertEqual(self.tap.read()[0]['sequence'], 1)
        self.tap.close()
        self.live._u32.side_effect = [0x1000, 2, 0x2000, 0x205219bc, 1]
        self.live.memory.read.side_effect = [struct.pack('<I', 0x203da5b0), struct.pack('<I', 0x203da520)]
        self.child = MagicMock(); self.child.stdin = io.StringIO(); self.child.wait.return_value = 0
        self.popen.return_value = self.child
        self.start(self.batch(), dict(closed=True, state=2, exception=0))
        self.assertEqual(self.tap.read()[0]['sequence'], 1)
        self.tap.close()


class NativeClientTapTests(unittest.TestCase):
    @unittest.skipUnless((native_folder() / 'tap_controller.exe').is_file(), 'native tap is not built')
    def test_real_native_hooks_preserve_originals_normalize_and_detach(self):
        self.assertTrue(check_client_tap())


class ClientTapCacheTests(unittest.TestCase):
    def test_loaded_module_is_immutable_and_new_build_gets_another_path(self):
        with tempfile.TemporaryDirectory() as directory, patch('l2_monitor.client_tap.DATA_ROOT', Path(directory)):
            folder = Path(directory) / 'build'; folder.mkdir()
            source = folder / 'tap_hook_v2.dll'; source.write_bytes(b'MZ-first-build')
            first = _runtime_dll(folder); before = first.stat().st_mtime_ns
            self.assertEqual(_runtime_dll(folder), first)
            self.assertEqual(first.stat().st_mtime_ns, before)
            source.write_bytes(b'MZ-next-build')
            second = _runtime_dll(folder)
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_bytes(), b'MZ-first-build')
            self.assertEqual(second.read_bytes(), b'MZ-next-build')

    def test_tampered_cached_module_is_rejected_before_loading(self):
        with tempfile.TemporaryDirectory() as directory, patch('l2_monitor.client_tap.DATA_ROOT', Path(directory)):
            folder = Path(directory) / 'build'; folder.mkdir()
            (folder / 'tap_hook_v2.dll').write_bytes(b'MZ-verified-build')
            cached = _runtime_dll(folder); cached.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'content hash'): _runtime_dll(folder)


if __name__ == '__main__': unittest.main()
