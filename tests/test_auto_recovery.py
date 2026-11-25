import copy
import struct
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from l2_monitor.auto_heal import AutoRecovery, recovery_potion
from test_inventory_drop import FakeMonitor


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.monitor = FakeMonitor()
        self.monitor.stop_event = threading.Event()
        self.status = dict(self.monitor.status(), actions_supported=False, detected_cipher='l2xor16-u64', active_source='client')
        self.monitor.status = lambda: dict(self.status)
        self.health = dict(character='Tester', level=50, hp=100, max_hp=100, cp=100, max_cp=100,
                           mp=100, max_mp=100, session_id=self.monitor.session)
        self.monitor.character = SimpleNamespace(snapshot=lambda: copy.copy(self.health) if self.health else None)
        self.calls = []
        self.capability = dict(available=True)
        self.monitor.sender = SimpleNamespace(pending=False, status=lambda: self.capability, send=lambda raw, **kw: self.calls.append(raw))
        self.transport = SimpleNamespace(heal=lambda *a: self.fail('Legacy transport used for a classic client'))
        self.recovery = AutoRecovery(self.monitor, self.transport)
        self.names = {57: 'Greater Healing Potion', 728: 'Mana Potion', 5592: 'Greater CP Potion'}
        self.recovery.catalog.item_name = lambda item: self.names.get(item, '')
        self.monitor.inventory.apply([self.monitor.packet('server', 'inventory_update', items=[
            dict(action=1, object_id=8, item_id=728, slot=2, amount=10),
            dict(action=1, object_id=9, item_id=5592, slot=3, amount=10)])])
        self.clock = 100.

    def tick(self, advance=.5):
        self.clock += advance
        with patch('l2_monitor.auto_heal.time.monotonic', return_value=self.clock):
            for channel in self.recovery.channels.values():
                channel.tick()

    def enable(self, resource, threshold=80, interval=1000):
        item = {'hp':57, 'mp':728, 'cp':5592}[resource]
        self.recovery.channels[resource].configure(True, item, threshold, interval)

    def test_discovers_potions_for_each_resource_without_enabling_consumption(self):
        self.tick()
        self.assertEqual(self.calls, [])
        for resource, item in (('hp',57), ('mp',728), ('cp',5592)):
            state = self.recovery.channels[resource].snapshot()
            self.assertFalse(state['enabled'])
            self.assertEqual([p['item_id'] for p in state['potions']], [item])

    def test_independent_thresholds_and_intervals_use_verified_client_requests(self):
        self.enable('hp', 80, 1000)
        self.enable('cp', 90, 2000)
        self.enable('mp', 60, 3000)
        self.health.update(hp=70, cp=70, mp=70)
        self.tick()
        self.assertEqual([struct.unpack('<HBII', p) for p in self.calls], [(11,0x19,7,0), (11,0x19,9,0)])
        self.health.update(hp=95, cp=95, mp=50)
        self.tick(1)
        self.assertEqual([struct.unpack_from('<I', p, 3)[0] for p in self.calls], [7,9,7,8])
        self.tick(1)
        self.assertEqual([struct.unpack_from('<I', p, 3)[0] for p in self.calls], [7,9,7,8,7,9])

    def test_threshold_is_strict_and_cycle_stops_at_full(self):
        self.enable('mp')
        self.health['mp'] = 80
        self.tick()
        self.assertFalse(self.calls)
        self.health['mp'] = 79
        self.tick(1)
        self.health['mp'] = 100
        self.tick(1)
        self.health['mp'] = 90
        self.tick(1)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.recovery.channels['mp'].active)

    def test_zero_cp_and_mp_are_valid_but_dead_hp_never_consumes(self):
        self.enable('cp'); self.enable('mp')
        self.health.update(hp=0, cp=0, mp=0)
        self.tick()
        self.assertEqual(self.calls, [])
        self.health['hp'] = 1
        self.tick(1)
        self.assertEqual(len(self.calls), 2)

    def test_missing_gap_wrong_session_and_invalid_values_do_not_consume(self):
        self.enable('mp')
        self.health['mp'] = 0
        self.monitor.inventory.gap()
        self.tick()
        self.assertEqual(self.calls, [])
        self.monitor.inventory.coverage_gap = False
        for values in ({'mp':None}, {'max_mp':0}, {'mp':-1}, {'mp':float('nan')}, {'mp':float('inf')},
                       {'session_id':'other'}, {'max_mp':None}):
            base = dict(self.health)
            self.health.update(values)
            self.tick(1)
            self.health = base
        self.health = None
        self.tick(1)
        self.assertEqual(self.calls, [])

    def test_server_bridge_and_unsupported_build_never_send_native_actions(self):
        self.enable('mp'); self.health['mp'] = 1
        self.status['active_source'] = 'server'
        self.tick()
        self.status['active_source'] = 'client'
        self.capability['available'] = False
        self.tick(1)
        self.assertEqual(self.calls, [])

    def test_server_reuse_delay_is_respected_in_addition_to_user_interval(self):
        self.enable('mp'); self.health['mp'] = 1
        self.tick()
        self.monitor.store.add([self.monitor.packet('server', 'reuse', reuse_item_id=728, retry_after_seconds=60)])
        self.tick(2)
        self.assertEqual(len(self.calls), 1)
        self.assertGreater(self.recovery.channels['mp'].snapshot()['cooldown_seconds'], 0)
        self.recovery.channels['mp'].reuse_until = 0
        self.tick(1)
        self.assertEqual(len(self.calls), 2)

    def test_disabled_or_stopped_capture_does_not_send_again(self):
        self.enable('mp'); self.health['mp'] = 1
        self.tick()
        self.recovery.channels['mp'].configure(False, 728)
        self.tick(20)
        self.enable('mp')
        self.monitor.stop_event.set()
        self.tick(20)
        self.assertEqual(len(self.calls), 1)

    def test_failed_unconfirmed_send_blocks_retries_until_reconfigured(self):
        self.enable('mp'); self.health['mp'] = 1
        def failure(*args, **kwargs):
            self.calls.append('attempt')
            raise RuntimeError('not captured')
        self.monitor.sender.send = failure
        self.tick()
        self.tick(100)
        self.assertEqual(self.calls, ['attempt'])
        self.assertEqual(self.recovery.channels['mp'].state, 'failed')
        self.assertEqual(self.recovery.channels['mp'].attempts, 0)

    def test_queued_actions_pause_recovery(self):
        self.enable('cp'); self.health['cp'] = 1
        self.monitor.inventory_drop = SimpleNamespace(snapshot=lambda: dict(active=True))
        self.tick()
        self.assertEqual(self.recovery.channels['cp'].state, 'paused')
        self.assertEqual(self.calls, [])

    def test_localized_potion_filters(self):
        for resource, names in {'cp':['Greater CP Potion', 'Elixir of CP (S-Grade)', 'Зелье CP'],
                                'mp':['Mana Potion', 'Elixir of Mental Strength (A-Grade)', 'Зелье маны'],
                                'hp':['Greater Healing Potion', 'Elixir of Life', 'Зелье здоровья']}.items():
            for name in names:
                self.assertTrue(recovery_potion(name, resource), name)
            self.assertFalse(recovery_potion('Antidote', resource))

