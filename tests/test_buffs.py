import sys
import struct
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.buffs import Buffs, NewbieBuffBatch
from l2_monitor.engine import PacketStore
from l2_monitor.semantics import extra_fields
from test_skills import packet


class BuffTests(unittest.TestCase):
    def setUp(self):
        self.buffs = Buffs()
        self.buffs.reset('s')
        self.profile = self.buffs.profile
        self.status = dict(state='live', running=True, session_id='s')
        self.monitor = SimpleNamespace(buffs=self.buffs, status=lambda: self.status, store=PacketStore(),
                                       stop_event=threading.Event(), inventory_drop=SimpleNamespace(snapshot=lambda: dict(active=False)),
                                       auto_pickup=SimpleNamespace(snapshot=lambda: dict(pending=False)),
                                       skill_actions=SimpleNamespace(snapshot=lambda: dict(active=False, state='ready')))
        self.requests = []
        self.target_id = 7
        self.monitor.auto_heal = SimpleNamespace(snapshot=lambda: dict(health=dict(object_id=7, hp=100)),
                                                reader=SimpleNamespace(read=lambda *args: dict(object_id=7)))
        self.confirm = True
        self.near = True
        self.dialog = True
        self.transport = SimpleNamespace(pickup=self.open_npc, newbie_buff=self.send)
        self.batch = NewbieBuffBatch(self.monitor, self.transport, confirmation_timeout=.03)

    def open_npc(self, *args):
        html = '<html>Newbie Guide: Give me some support magic. <a action="bypass -h 01">buff</a></html>'
        self.monitor.store.add([packet('client', 'action', object_id=self.profile['object_id']),
                                packet('server', 'npc_html', object_id=self.profile['object_id'], html=html if self.dialog else 'different')])
        return dict(sent=self.near)

    def send(self, status, count):
        self.requests.append(count)
        rows = [packet('client', 'bypass_request', command='01') for _ in range(count)]
        if self.confirm:
            # This server coalesces status lists; one final list can cover all ten complete cast bundles.
            for _ in range(count):
                rows.extend(packet('server', 'skill_use', caster_id=self.profile['object_id'], target_id=self.target_id, skill_id=skill, xyz=self.profile['xyz']) for skill in self.profile['skills'])
            rows.append(packet('server', 'buff_list', buffs=[dict(skill_id=skill, skill_level=1, remaining_seconds=3600) for skill in self.profile['skills']]))
        self.buffs.apply(rows)
        self.monitor.store.add(rows)
        return dict(sent=count)

    def run_batch(self, count):
        self.batch.start(count)
        self.batch.thread.join(1)
        self.assertFalse(self.batch.snapshot()['active'])
        return self.batch.snapshot()['history'][-1]

    def test_batch_ten_sends_once_and_confirms_all_casts_with_coalesced_effects(self):
        job = self.run_batch(10)
        self.assertEqual(self.requests, [10])
        self.assertEqual((job['sent'], job['requests_seen'], job['confirmed'], job['state']), (10, 10, 10, 'completed'))

    def test_no_server_casts_does_not_fake_success_or_retry(self):
        self.confirm = False
        job = self.run_batch(10)
        self.assertEqual((job['confirmed'], job['state']), (0, 'failed'))
        self.assertEqual(self.requests, [10])

    def test_other_players_npc_buffs_are_not_counted_as_our_confirmation(self):
        self.target_id = 88
        self.assertEqual(self.run_batch(10)['confirmed'], 0)

    def test_wrong_dialog_or_outside_radius_does_not_send_bypass(self):
        for attribute in ('near', 'dialog'):
            setattr(self, attribute, False)
            self.assertEqual(self.run_batch(10)['sent'], 0)
            setattr(self, attribute, True)
        self.assertEqual(self.requests, [])

    def test_count_validation(self):
        for count in (None, 0, -1, 1001, True, 1.5):
            with self.assertRaises(ValueError):self.batch.start(count)

    def test_observed_schema_and_countdown_are_actual_not_multiplied(self):
        raw = struct.pack('<HBH', 25, 0x85, 2) + struct.pack('<IHiIHi', 4322, 1, 3600, 4323, 1, -1)
        fields = extra_fields('server', raw)
        self.buffs.apply([dict(direction='server', fields=fields)])
        snapshot = self.buffs.snapshot()['buffs']
        self.assertEqual(snapshot[0]['remaining_seconds'], 3600)
        self.assertIsNone(snapshot[1]['remaining_seconds'])
        with self.assertRaises(ValueError):extra_fields('server', raw[:-1])

    def test_observed_item_reuse_message_retains_the_item_and_remaining_seconds(self):
        raw = struct.pack('<HB6I', 27, 0x62, 2303, 2, 3, 1061, 1, 9)
        fields = extra_fields('server', raw)
        self.assertEqual((fields['reuse_item_id'], fields['retry_after_seconds']), (1061, 9))


if __name__ == '__main__':unittest.main()
