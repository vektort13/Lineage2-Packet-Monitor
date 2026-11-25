"""List-request dispatch guards with no processes, hooks, UI or network."""
import copy
import json
import struct
import threading
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.classic_requests import request_list, request_packet, request_skill, request_skill_menu, SkillTransport, client_anchors, clear_client_anchors
from l2_monitor.ciphers import xor_encrypt


class ClassicListRequestTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.select = self.stack.enter_context(patch('l2_monitor.classic_requests.select_process'))
        self.live_type = self.stack.enter_context(patch('l2_monitor.classic_requests.ClassicLiveState'))
        self.folder = self.stack.enter_context(patch('l2_monitor.classic_requests.native_folder'))
        self.thread = self.stack.enter_context(patch('l2_monitor.classic_requests.window_thread'))
        self.run = self.stack.enter_context(patch('l2_monitor.classic_requests.subprocess.run'))
        self.process = dict(pid=321, exe='C:/test/l2.exe', create_time=123456)
        self.endpoint = dict(local_ip='192.0.2.1', local_port=50000,
                             remote_ip='198.51.100.2', remote_port=7777)
        self.status = dict(process=copy.deepcopy(self.process), endpoint=copy.deepcopy(self.endpoint))
        self.profile = dict(root_pointer_rva=0x5678, game_socket_offset=72,
                            list_requests=dict(entry_rva=0x1234, code_hex='558bec', mask_hex='ffffff'))
        self.select.return_value = (self.process, self.endpoint)
        self.live = self.live_type.return_value
        self.live.base = 0x20000000
        self.live.memory.read.return_value = bytes.fromhex('558bec')
        self.folder.return_value = Path('C:/isolated-native')
        self.thread.return_value = 616
        self.outcome = dict(sent=1, exception=0, thread_id=616)
        self.run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(self.outcome))

    def test_unsupported_opcode_never_opens_process_or_calls_native_sender(self):
        for opcode in (0x00, 0x19, 0x51, 0xd0, -1):
            with self.subTest(opcode=opcode), self.assertRaises(ValueError):
                request_list(self.status, self.profile, opcode)
        self.select.assert_not_called()
        self.live_type.assert_not_called()
        self.run.assert_not_called()

    def test_changed_endpoint_or_reused_process_identity_is_rejected(self):
        changed = dict(self.endpoint, remote_port=7778)
        self.select.return_value = (self.process, changed)
        with self.assertRaisesRegex(ValueError, 'connection changed'):
            request_list(self.status, self.profile, 0x14)
        self.select.return_value = (dict(self.process, create_time=123457), self.endpoint)
        with self.assertRaisesRegex(ValueError, 'connection changed'):
            request_list(self.status, self.profile, 0x50)
        self.live_type.assert_not_called()
        self.run.assert_not_called()

    def test_sender_fingerprint_mismatch_closes_live_reader_without_dispatch(self):
        self.live.memory.read.return_value = bytes.fromhex('548bec')
        with self.assertRaisesRegex(ValueError, 'sender changed'):
            request_list(self.status, self.profile, 0x14)
        self.live.snapshot.assert_called_once_with()
        self.live.memory.read.assert_called_once_with(0x20001234, 3)
        self.live.close.assert_called_once_with()
        self.run.assert_not_called()

    def test_success_dispatches_exact_original_sender_entry_root_offsets_and_request_body(self):
        for opcode, body in ((0x14, '14\n'), (0x50, '50\n')):
            with self.subTest(opcode=opcode):
                self.live.reset_mock()
                self.run.reset_mock()
                result = request_list(self.status, self.profile, opcode)
                self.assertEqual(result, self.outcome)
                self.live_type.assert_called_with(321, 'C:/test/l2.exe', self.profile)
                self.live.close.assert_called_once_with()
                self.thread.assert_called_with(321)
                arguments = self.run.call_args.args[0]
                self.assertEqual(arguments,
                                 [str(self.folder.return_value / 'drop_controller.exe'), '321', '616',
                                  str(self.folder.return_value / 'drop_hook.dll'),
                                  '0x20001234', '0x20005678', '0', '0', '0', '0', '0', 'packet', '72'])
                self.assertEqual(self.run.call_args.kwargs['input'], body)
                self.assertTrue(self.run.call_args.kwargs['capture_output'])
                self.assertTrue(self.run.call_args.kwargs['text'])
                self.assertEqual(self.run.call_args.kwargs['timeout'], 8)
                self.run.assert_called_once()

    def test_native_failure_and_unconfirmed_sent_count_do_not_retry(self):
        for outcome in (SimpleNamespace(returncode=1, stdout='native failure'),
                        SimpleNamespace(returncode=0, stdout='{"sent":0}'),
                        SimpleNamespace(returncode=0, stdout='{"sent":2}')):
            with self.subTest(outcome=outcome):
                self.run.reset_mock()
                self.run.return_value = outcome
                with self.assertRaises(RuntimeError):
                    request_list(self.status, self.profile, 0x14)
                self.run.assert_called_once()

    def test_unstable_live_checkpoint_is_closed_and_never_dispatches(self):
        self.live.snapshot.side_effect = ValueError('incomplete receive state')
        with self.assertRaisesRegex(ValueError, 'incomplete receive'):
            request_list(self.status, self.profile, 0x50)
        self.live.close.assert_called_once_with()
        self.live.memory.read.assert_not_called()
        self.run.assert_not_called()

    def test_skill_request_uses_exact_13_byte_class_learning_body(self):
        self.profile['skill_requests'] = dict(opcodes=dict(list=0x50, info=0x73, learn=0x7c))
        for operation, opcode in (('learn', 0x7c), ('info', 0x73)):
            self.run.reset_mock()
            outcome = request_skill(self.status, self.profile, operation, 4683, 1, 0)
            self.assertEqual(outcome['sent'], 1)
            self.assertEqual(self.run.call_args.kwargs['input'], struct.pack('<BIII', opcode, 4683, 1, 0).hex()+'\n')
            self.run.assert_called_once()

    def test_invalid_or_unprofiled_skill_never_opens_the_client(self):
        with self.assertRaises(ValueError):
            request_skill(self.status, self.profile, 'learn', 4683, 1, 0)
        self.profile['skill_requests'] = dict(opcodes=dict(list=0x50, info=0x73, learn=0x7c))
        for arguments in ((True,1,0),(4683,True,0),(4683,0,0),(0,1,0),
                          (4683,1,1),(4683,1,False),(0x80000000,1,0),(4683,0x80000000,0)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                request_skill(self.status, self.profile, 'learn', *arguments)
        self.select.assert_not_called()
        self.run.assert_not_called()

    def test_truncated_fingerprint_and_native_exception_are_never_accepted(self):
        self.live.memory.read.return_value = bytes.fromhex('558b')
        with self.assertRaises(ValueError):
            request_list(self.status, self.profile, 0x50)
        self.run.assert_not_called()
        self.live.memory.read.return_value = bytes.fromhex('558bec')
        self.run.return_value = SimpleNamespace(returncode=0, stdout='{"sent":1,"exception":5}')
        with self.assertRaises(RuntimeError):
            request_list(self.status, self.profile, 0x50)
        self.run.assert_called_once()

    def test_skill_transport_selects_verified_profile_and_keeps_old_transport(self):
        fallback = SimpleNamespace(skill=unittest.mock.Mock(return_value='old'))
        transport = SkillTransport(fallback)
        self.assertEqual(transport.skill(self.status, 'learn', 16, 2, 0), 'old')
        fallback.skill.assert_called_once_with(self.status, 'learn', 16, 2, 0)
        self.profile['skill_requests'] = dict(opcodes=dict(list=0x50, info=0x73, learn=0x7c))
        status = dict(self.status, detected_cipher='l2xor16-u64', profile='classic')
        with patch('l2_monitor.classic_requests.CipherProfiles') as registry:
            registry.return_value.profiles = [dict(id='classic', validation='verified', engine_sha256='a'*64)]
            registry.return_value.load_profile.return_value = self.profile
            self.assertEqual(transport.skill(status, 'learn', 4683, 1, 0)['sent'], 1)
            registry.return_value.load_profile.assert_called_once_with('a'*64)
            registry.return_value.profiles = []
            with self.assertRaises(ValueError):
                transport.skill(status, 'learn', 4683, 1, 0)
        fallback.skill.assert_called_once()

    def test_menu_request_preserves_the_full_utf16_server_command(self):
        self.profile['skill_requests'] = dict(community_menu=dict(root='_bbslearnSkills', search_prefix='_bbslearnSkills_search_ '))
        for command in ('_bbslearnSkills', '_bbslearnSkills_search_ Wind Walk',
                        '_bbslearnSkills;learn;51;251;5;1;;ALL;ALL',
                        '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_Wind Walk'):
            with self.subTest(command=command):
                self.run.reset_mock()
                request_skill_menu(self.status, self.profile, command)
                self.assertEqual(self.run.call_args.kwargs['input'], (b'\x23'+command.encode('utf-16le')+b'\0\0').hex()+'\n')
                self.run.assert_called_once()
        self.run.reset_mock()
        for command in ('_bbshome','_bbslearnSkills;learn;51;251;5;1;;ALL;ALL;extra',
                        '_bbslearnSkills_search_ x\x00y','_bbslearnSkills_search_ x;y'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                request_skill_menu(self.status, self.profile, command)
        self.run.assert_not_called()

    def menu_transport(self, available=True):
        menu = SimpleNamespace(snapshot=lambda: dict(search_available=available, completed_revision=0, session_id='s1'),
                               find=unittest.mock.Mock(return_value=None))
        status = dict(self.status, running=True, state='live', session_id='s1')
        monitor = SimpleNamespace(status=lambda: status, stop_event=threading.Event(), skill_menu=menu,
                                  auto_heal=SimpleNamespace(catalog=SimpleNamespace(skill_name=lambda *args:'Wind Walk')))
        self.profile['skill_requests'] = dict(community_menu=dict(root='_bbslearnSkills', search_prefix='_bbslearnSkills_search_ '),
                                              opcodes=dict(list=0x50, info=0x73, learn=0x7c))
        return SkillTransport(None, monitor), menu, status

    def test_menu_learning_selects_an_exact_offer_without_changing_id_or_level(self):
        transport, menu, status = self.menu_transport()
        command = '_bbslearnSkills_learnFromSearch_15_1204_1_ALL_ALL_Wind Walk'
        menu.find.return_value = dict(skill_id=1204, skill_level=1, class_id=15, command=command)
        with patch('l2_monitor.classic_requests.request_skill_menu', return_value=dict(sent=1)) as send:
            self.assertEqual(transport._menu_learn(status,self.profile,1204,1,0)['sent'],1)
            send.assert_called_once_with(status,self.profile,command)
        menu.find.assert_called_once_with(1204,1)

    def test_menu_search_uses_the_catalog_name_and_does_not_invent_a_learn_command(self):
        transport, menu, status = self.menu_transport()
        with patch.object(transport,'_menu_query',return_value=True) as query, \
             patch('l2_monitor.classic_requests.request_skill_menu') as send:
            with self.assertRaisesRegex(ValueError,'не предлагает скилл 1204 уровня 2'):
                transport._menu_learn(status,self.profile,1204,2,0)
            query.assert_called_once_with(status,self.profile,'_bbslearnSkills_search_ Wind Walk')
            send.assert_not_called()

    def test_menu_without_advertised_search_retains_standard_request_fallback(self):
        transport, menu, status = self.menu_transport(available=False)
        with patch.object(transport,'_menu_query',return_value=False) as query, \
             patch('l2_monitor.classic_requests.request_skill',return_value=dict(sent=1)) as send:
            transport._menu_learn(status,self.profile,1204,1,0)
            query.assert_called_once_with(status,self.profile,'_bbslearnSkills')
            send.assert_called_once_with(status,self.profile,'learn',1204,1,0)

    def test_menu_wait_aborts_if_the_connection_changes(self):
        transport, menu, status = self.menu_transport()
        transport.monitor.status = unittest.mock.Mock(side_effect=[status, dict(status,session_id='s2')])
        with patch('l2_monitor.classic_requests.request_skill_menu') as send:
            with self.assertRaisesRegex(ValueError,'подключение изменилось'):
                transport._menu_query(status,self.profile,'_bbslearnSkills')
            send.assert_called_once()

    def test_native_tx_checkpoint_registers_ciphertext_and_never_returns_session_keys(self):
        self.profile.update(outgoing_bytes_offset=0x8978,outgoing_key_offset=0x914d)
        self.live.snapshot.return_value = dict(opcode_map=list(range(209)))
        self.run.return_value = SimpleNamespace(returncode=0,stdout=json.dumps(dict(
            sent=1, exception=0, tx_key_before='00'*16,tx_wire_before=0xfffffffe,tx_wire_after=1)))
        clear_client_anchors(self.process,self.endpoint)
        result = request_list(self.status,self.profile,0x50)
        self.assertNotIn('tx_key_before',result)
        self.assertEqual(client_anchors(self.process,self.endpoint),[dict(client_wire_after=1,wire_hex='030050')])
        self.assertEqual(self.run.call_args.args[0][-2:],[str(0x8978),str(0x914d)])
        clear_client_anchors(self.process,self.endpoint)

    def test_missing_or_wrong_native_tx_checkpoint_cannot_establish_an_anchor(self):
        self.profile.update(outgoing_bytes_offset=0x8978,outgoing_key_offset=0x914d)
        self.live.snapshot.return_value = dict(opcode_map=list(range(209)))
        for outcome in (dict(sent=1),dict(sent=1,tx_key_before='00'*16,tx_wire_before=10,tx_wire_after=12)):
            clear_client_anchors(self.process,self.endpoint)
            self.run.return_value = SimpleNamespace(returncode=0,stdout=json.dumps(outcome))
            with self.assertRaises(RuntimeError):
                request_list(self.status,self.profile,0x50)
            self.assertEqual(client_anchors(self.process,self.endpoint),[])

    def packet_profile(self):
        self.profile.update(packet_requests=dict(sender='list_requests',format='cb',max_body_bytes=32766),
                            opcode_map_count=209,extended_map_count=152,
                            outgoing_bytes_offset=0x8978,outgoing_key_offset=0x914d)
        self.live.snapshot.return_value = dict(opcode_map=list(reversed(range(209))),
                                                extended_map=list(reversed(range(152))))

    def test_raw_queue_body_is_not_reinterpreted_and_both_opcode_maps_form_the_proof(self):
        self.packet_profile()
        for body in (bytes.fromhex('d07100aabbcc'),bytes.fromhex('2300d80000'),b'\x14',
                     b'\x01'+bytes(range(256))*127+b'\0'*253):
            clear_client_anchors(self.process,self.endpoint)
            self.run.return_value.stdout=json.dumps(dict(sent=1,tx_key_before='00'*16,
                tx_wire_before=10,tx_wire_after=10+len(body)+2))
            result=request_packet(self.status,self.profile,body)
            self.assertNotIn('tx_key_before',result)
            self.assertEqual(self.run.call_args.kwargs['input'],body.hex()+'\n')
            mapped=bytearray(body)
            mapped[0]=208-body[0]
            if body[0]==0xd0:mapped[1:3]=(151-int.from_bytes(body[1:3],'little')).to_bytes(2,'little')
            expected=(len(body)+2).to_bytes(2,'little')+xor_encrypt(bytes(mapped),bytes(16))
            self.assertEqual(client_anchors(self.process,self.endpoint)[0]['wire_hex'],expected.hex())
        clear_client_anchors(self.process,self.endpoint)

    def test_invalid_raw_queue_body_never_reaches_native_dispatch(self):
        self.packet_profile()
        for body in (b'',b'\x01'*32767,b'\xff',b'\xd0',b'\xd0\x98\0',bytearray(b'\x50')):
            with self.subTest(body_length=len(body)),self.assertRaises(ValueError):
                request_packet(self.status,self.profile,body)
        self.select.assert_not_called()
        self.run.assert_not_called()

    def test_runtime_dictionary_mismatch_is_rejected_before_native_side_effects(self):
        self.packet_profile()
        self.live.snapshot.return_value['opcode_map']=[]
        with self.assertRaisesRegex(ValueError,'словаре'):
            request_packet(self.status,self.profile,b'\x14')
        self.live.close.assert_called_once()
        self.run.assert_not_called()

    def test_unregistered_raw_sender_cannot_use_the_list_sender_implicitly(self):
        with self.assertRaisesRegex(ValueError,'очереди'):
            request_packet(self.status,self.profile,b'\x50')
        self.select.assert_not_called()


if __name__ == '__main__':
    unittest.main()
