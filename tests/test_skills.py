import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.skills import Skills, SkillActions
from l2_monitor.engine import PacketStore


def packet(direction, event, **fields):
    return dict(direction=direction, fields=dict(event=event, **fields), category='skill_learning',
                opcode='5F', name='SkillList', color='#ffffff')


class SkillTests(unittest.TestCase):
    def setUp(self):
        self.skills = Skills()
        self.skills.reset('s1')
        self.skills.apply([packet('server', 'skill_list', skills=[dict(skill_id=16, skill_level=1)])])
        self.status = dict(running=True, state='live', session_id='s1')
        self.monitor = SimpleNamespace(skills=self.skills, status=lambda: self.status, store=PacketStore(),
                                       inventory_drop=SimpleNamespace(snapshot=lambda: dict(active=False)),
                                       auto_pickup=SimpleNamespace(snapshot=lambda: dict(pending=False)))
        self.calls = []
        self.transport = SimpleNamespace(skill=lambda *args: self.calls.append(args[1:]))
        self.actions = SkillActions(self.monitor, self.transport)
        self.actions.start = lambda: None

    def confirm(self, level, direction='server', request=True, skill_id=16, list_type=0):
        packets = []
        if request:
            packets.append(packet('client', 'skill_learn_request', skill_id=skill_id, skill_level=level, list_type=list_type))
        packets.append(packet(direction, 'skill_list', skills=[dict(skill_id=16, skill_level=level)]))
        self.skills.apply(packets)
        self.monitor.store.add(packets)
        self.actions.tick()

    def test_only_server_owned_list_replaces_state(self):
        for direction, event in [('server', 'learnable_skill_list'), ('client', 'skill_list')]:
            self.skills.apply([packet(direction, event, skills=[dict(skill_id=16, skill_level=99)])])
            self.assertEqual(self.skills.snapshot()['skills'][0]['skill_level'], 1)
        self.skills.apply([packet('server', 'skill_list', skills=[])])
        self.assertEqual(self.skills.snapshot()['skills'], [])

    def test_multiple_levels_advance_only_after_each_confirmation(self):
        self.actions.learn(16, 3)
        self.actions.tick()
        self.assertEqual(self.calls, [('learn', 16, 2, 0)])
        self.assertEqual(self.skills.snapshot()['skills'][0]['skill_level'], 1)
        self.confirm(2)
        self.actions.tick()
        self.assertEqual(self.calls, [('learn', 16, 2, 0), ('learn', 16, 3, 0)])
        self.confirm(3)
        result = self.actions.snapshot()
        self.assertFalse(result['active'])
        self.assertEqual(result['history'][-1]['actual'], 3)
        self.assertEqual(result['state'], 'completed')

    def test_request_or_offered_level_does_not_fake_learning(self):
        self.actions.learn(16, 2)
        self.actions.tick()
        self.monitor.store.add([packet('client', 'skill_learn_request', skill_id=16, skill_level=2, list_type=0),
                                packet('server', 'learnable_skill_list', skills=[dict(skill_id=16, skill_level=2)])])
        self.actions.tick()
        self.assertTrue(self.actions.snapshot()['active'])
        self.assertEqual(self.skills.snapshot()['skills'][0]['skill_level'], 1)
        self.actions.job['deadline'] = 0
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')
        self.assertEqual(self.calls, [('learn', 16, 2, 0)])

    def test_wrong_request_cannot_confirm_action(self):
        self.actions.learn(16, 2)
        self.actions.tick()
        self.confirm(2, list_type=1)
        self.assertTrue(self.actions.snapshot()['active'])
        self.confirm(2, request=False)
        self.assertTrue(self.actions.snapshot()['active'])

    def test_session_change_stops_learning(self):
        self.actions.learn(16, 3)
        self.actions.tick()
        self.status['session_id'] = 's2'
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')
        self.assertEqual(len(self.calls), 1)

    def test_stop_capture_does_not_dispatch_a_queued_level(self):
        self.actions.learn(16, 3)
        self.monitor.stop_event = threading.Event()
        self.monitor.stop_event.set()
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')
        self.assertEqual(self.calls, [])

    def test_invalid_id_old_level_invalid_inputs_and_gap_rejected(self):
        for skill_id, level in [(16, 1), (16, 0), (16, True), (16, 2.5), (0, 2), (16, 0x80000000)]:
            with self.assertRaises(ValueError):
                self.actions.learn(skill_id, level)
        self.skills.gap()
        with self.assertRaises(ValueError):
            self.actions.learn(16, 2)
        self.assertEqual(self.calls, [])

    def test_custom_unowned_id_starts_at_level_one_and_requires_server_confirmation(self):
        self.actions.learn(99, 2)
        self.actions.tick()
        self.assertEqual(self.calls, [('learn', 99, 1, 0)])
        self.assertEqual(self.actions.job['before'], 0)
        self.assertEqual([row['skill_id'] for row in self.skills.snapshot()['skills']], [16])
        self.monitor.store.add([
            packet('client', 'skill_learn_request', skill_id=99, skill_level=1, list_type=0),
            packet('server', 'skill_list', skills=[dict(skill_id=16, skill_level=1), dict(skill_id=99, skill_level=1)])])
        self.actions.tick()
        self.actions.tick()
        self.assertEqual(self.calls[-1], ('learn', 99, 2, 0))

    def test_native_failure_is_not_retried(self):
        def fail(*args):
            raise RuntimeError('uncertain')
        self.transport.skill = fail
        self.actions.learn(16, 2)
        with self.assertRaises(RuntimeError):
            self.actions.tick()
        self.assertEqual(self.actions.job['state'], 'confirming')
        self.transport.skill = lambda *args: self.fail('Learning must not be retried')
        self.actions.tick()
        self.actions.job['deadline'] = 0
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')

    def test_classic_skill_capability_confirms_learning_without_enabling_other_actions(self):
        self.status.update(actions_supported=False, skill_actions_supported=True)
        self.actions.learn(16, 2)
        self.actions.tick()
        self.assertEqual(self.calls, [('learn', 16, 2, 0)])
        self.assertTrue(self.actions.snapshot()['active'])
        self.assertEqual(self.skills.snapshot()['skills'][0]['skill_level'], 1)
        self.confirm(2)
        self.assertEqual(self.actions.snapshot()['state'], 'completed')
        self.assertEqual(self.actions.snapshot()['history'][-1]['actual'], 2)
        self.assertFalse(self.status['actions_supported'])

    def test_classic_refresh_uses_distinct_skill_capability(self):
        self.status.update(actions_supported=False, skill_actions_supported=True)
        self.actions.refresh()
        self.actions.tick()
        self.assertEqual(self.calls, [('list',)])
        self.assertFalse(self.status['actions_supported'])

    def test_unsupported_learning_is_reported_separately_from_capture_synchronization(self):
        error = 'Обучение скиллов для этой сборки клиента пока не подключено'
        for flags in (dict(actions_supported=False),
                      dict(actions_supported=True, skill_actions_supported=False)):
            with self.subTest(flags=flags):
                self.status.update(flags)
                for action in (self.actions.refresh, lambda: self.actions.learn(16, 2)):
                    with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                        action()
        self.status['skill_actions_supported'] = False
        for state, running in (('synchronizing', True), ('stopped', False)):
            self.status.update(state=state, running=running)
            for action in (self.actions.refresh, lambda: self.actions.learn(16, 2)):
                with self.assertRaisesRegex(ValueError, '^Дождитесь синхронизации захвата$'):
                    action()
        self.assertEqual(self.calls, [])

    def test_unsupported_tick_never_dispatches_pending_or_automatic_refresh(self):
        self.status.update(actions_supported=False, skill_actions_supported=False)
        self.skills.gap()
        self.actions.refresh_pending = True
        self.actions.tick()
        self.actions.tick()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.actions.refresh_pending)
        self.assertEqual(self.actions.snapshot()['state'], 'unsupported')

    def test_skill_capability_loss_fails_queued_or_confirming_job_without_dispatch_or_retry(self):
        for dispatched in (False, True):
            with self.subTest(dispatched=dispatched):
                self.setUp()
                self.status.update(actions_supported=False, skill_actions_supported=True)
                self.actions.learn(16, 2)
                if dispatched:
                    self.actions.tick()
                self.status['skill_actions_supported'] = False
                self.actions.tick()
                self.actions.tick()
                result = self.actions.snapshot()
                self.assertFalse(result['active'])
                self.assertEqual(result['state'], 'failed')
                self.assertEqual(result['error'], 'Обучение скиллов для этой сборки клиента пока не подключено')
                self.assertEqual(self.calls, [('learn', 16, 2, 0)] if dispatched else [])

    def test_live_sync_loss_fails_active_learning_instead_of_waiting_forever(self):
        self.status.update(actions_supported=False, skill_actions_supported=True)
        self.actions.learn(16, 2)
        self.status['state'] = 'synchronizing'
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')
        self.assertEqual(self.actions.snapshot()['error'], 'Синхронизация захвата потеряна')
        self.assertEqual(self.calls, [])

    def test_classic_unchanged_server_list_never_fakes_success_or_retries_learning(self):
        self.status.update(actions_supported=False, skill_actions_supported=True)
        self.actions.learn(16, 2)
        with patch('l2_monitor.skills.time.monotonic', return_value=10):
            self.actions.tick()
        self.monitor.store.add([
            packet('client', 'skill_learn_request', skill_id=16, skill_level=2, list_type=0),
            packet('server', 'skill_list', skills=[dict(skill_id=16, skill_level=1)])])
        with patch('l2_monitor.skills.time.monotonic', return_value=12):
            self.actions.tick()
            self.actions.tick()
        self.assertTrue(self.actions.snapshot()['active'])
        self.assertEqual(self.actions.job['actual'], 1)
        self.assertEqual(self.calls, [('learn', 16, 2, 0), ('list',)])
        self.actions.job['deadline'] = 0
        self.actions.tick()
        self.assertEqual(self.actions.snapshot()['state'], 'failed')
        self.assertEqual(self.actions.snapshot()['history'][-1]['actual'], 1)
        self.assertEqual(self.calls, [('learn', 16, 2, 0), ('list',)])


if __name__ == '__main__':
    unittest.main()
