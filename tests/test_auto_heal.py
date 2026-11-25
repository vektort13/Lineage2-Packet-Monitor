import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.auto_heal import AutoHeal, healing_potion
from test_inventory_drop import FakeMonitor


class AutoHealTests(unittest.TestCase):
    def setUp(self):
        self.monitor = FakeMonitor()
        self.monitor.stop_event = threading.Event()
        self.monitor.inventory_drop = SimpleNamespace(snapshot=lambda: dict(active=False))
        self.monitor.skill_actions = SimpleNamespace(snapshot=lambda: dict(active=False))
        self.monitor.newbie_buff = SimpleNamespace(snapshot=lambda: dict(active=False))
        self.hp, self.clock = 79, 100
        self.calls = []
        self.reader = SimpleNamespace(read=lambda *args: dict(object_id=7, character='X501', level=21, hp=self.hp, max_hp=100,
                                                            hp_percent=self.hp, names={57: 'Greater Healing Potion'}))
        self.transport = SimpleNamespace(heal=self.use)
        self.heal = AutoHeal(self.monitor, self.transport, self.reader)

    def use(self, status, oid, threshold, active):
        self.calls.append((oid, threshold, active))
        return dict(sent=int(self.hp < 100 and self.hp > 0), healing=int(self.hp < 100 and self.hp > 0))

    def tick(self, advance=.5):
        self.clock += advance
        with patch('l2_monitor.auto_heal.time.monotonic', return_value=self.clock):self.heal.tick()

    def test_default_off_still_reads_character_and_discovers_real_names(self):
        self.tick()
        state = self.heal.snapshot()
        self.assertFalse(state['enabled'])
        self.assertEqual(state['health']['character'], 'X501')
        self.assertEqual(state['potions'], [dict(item_id=57, name='Greater Healing Potion', amount=5)])
        self.assertEqual(self.calls, [])

    def test_below_threshold_latches_until_full_and_uses_at_most_once_per_second(self):
        self.heal.configure(True, 57, 80, interval_ms=1000)
        self.tick()
        self.assertEqual(len(self.calls), 1)
        self.hp = 90
        self.tick(.5)
        self.assertEqual(len(self.calls), 1)
        self.tick(.5)
        self.assertEqual(len(self.calls), 2)
        self.hp = 100
        self.tick(1)
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.heal.snapshot()['healing'])
        self.hp = 90
        self.tick(1)
        self.assertEqual(len(self.calls), 2)

    def test_exact_threshold_dead_and_stopped_never_use_item(self):
        self.heal.configure(True, 57, 80)
        for hp in (80, 100, 0):
            self.hp = hp
            self.tick(1)
        self.monitor.stop_event.set()
        self.hp = 10
        self.tick(1)
        self.assertEqual(self.calls, [])

    def test_eleven_second_interval_is_the_default(self):
        self.heal.configure(True, 57, 80)
        self.tick()
        self.tick(10)
        self.assertEqual(len(self.calls), 1)
        self.tick(1)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.heal.snapshot()['interval_ms'], 11000)

    def test_changing_interval_keeps_the_active_cycle_and_measures_from_last_use(self):
        self.heal.configure(True, 57, 80)
        self.tick()
        self.hp = 90
        self.heal.configure(True, 57, 80, interval_ms=5000)
        self.tick(4)
        self.assertEqual(len(self.calls), 1)
        self.tick(1)
        self.assertEqual(len(self.calls), 2)

    def test_no_stock_or_pending_buff_does_not_consume(self):
        self.heal.configure(True, 57, 80)
        self.monitor.newbie_buff.snapshot = lambda: dict(active=True)
        self.tick()
        self.assertEqual(self.heal.snapshot()['state'], 'paused')
        self.assertEqual(self.calls, [])

    def test_invalid_config_and_name_filter(self):
        for args in ((True,None,80),(True,57,0),(True,57,100),('true',57,80),(True,True,80)):
            with self.assertRaises(ValueError):self.heal.configure(*args)
        self.assertTrue(healing_potion('Elixir of Life (No Grade)'))
        self.assertFalse(healing_potion('Antidote'))
        self.assertFalse(healing_potion('Mana Potion'))


if __name__ == '__main__':unittest.main()
