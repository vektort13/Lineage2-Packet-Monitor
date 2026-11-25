import sys
import unittest
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from l2_monitor.inventory import Inventory
from l2_monitor.inventory_open import AutoInventoryOpen, InputNotReady
from l2_monitor.semantics import extra_fields


class InventoryTests(unittest.TestCase):
    def test_observed_item_list_layout_is_decoded(self):
        record = bytearray(74)
        struct.pack_into('<IIIQ', record, 0, 7001, 4356, 8, 10)
        struct.pack_into('<HHH', record, 20, 5, 0, 0)
        raw = struct.pack('<HBHH', 7 + 74 + 2, 0x11, 1, 1) + bytes(record) + b'\x00\x00'
        fields = extra_fields('server', raw)
        self.assertEqual(fields['event'], 'inventory_update')
        self.assertEqual(fields['items'][0]['item_id'], 4356)
        self.assertEqual(fields['items'][0]['amount'], 10)
        self.assertEqual(fields['items'][0]['slot'], 8)

    def packet(self, records, frame=1):
        return dict(direction='server', time='2026-11-22T00:00:00+00:00', frame=frame,
                    fields=dict(event='inventory_update', items=records))

    def test_add_modify_and_remove_are_passive_state_updates(self):
        inventory = Inventory()
        inventory.reset('test-session')
        inventory.apply([self.packet([dict(action=1, action_name='added', object_id=7,
                                           item_id=4356, slot=8, amount=10)])])
        self.assertEqual(inventory.snapshot()['items'][0]['item_id'], 4356)
        self.assertEqual(inventory.snapshot()['items'][0]['amount'], 10)
        inventory.apply([self.packet([dict(action=2, action_name='modified', object_id=7,
                                           item_id=4356, slot=8, amount=4)], frame=2)])
        self.assertEqual(inventory.snapshot()['items'][0]['amount'], 4)
        inventory.apply([self.packet([dict(action=3, action_name='removed', object_id=7,
                                           item_id=4356, slot=8, amount=0)], frame=3)])
        self.assertEqual(inventory.snapshot()['items'], [])
        self.assertEqual(len(inventory.snapshot()['events']), 3)

    def test_other_direction_and_gaps_do_not_create_items(self):
        inventory = Inventory()
        inventory.apply([dict(direction='client', fields=dict(event='inventory_update', items=[
            dict(action=1, action_name='added', object_id=9, item_id=1, slot=1, amount=1)]))])
        inventory.gap()
        snapshot = inventory.snapshot()
        self.assertEqual(snapshot['items'], [])
        self.assertTrue(snapshot['coverage_gap'])
        self.assertEqual(snapshot['source'], 'observed-server-inventory')

    def test_full_list_replaces_old_items_and_accepts_empty_inventory(self):
        inventory = Inventory()
        inventory.apply([self.packet([dict(action=1, object_id=7, item_id=4356, slot=8, amount=10)])])
        inventory.gap()
        packet = self.packet([])
        packet['fields'].update(list_type=1, record_size=74)
        inventory.apply([packet])
        snapshot = inventory.snapshot()
        self.assertEqual(snapshot['items'], [])
        self.assertTrue(snapshot['full_list_received'])
        self.assertFalse(snapshot['coverage_gap'])
        inventory.reset('new-session')
        self.assertFalse(inventory.snapshot()['full_list_received'])


class AutoInventoryTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.calls = []
        self.auto = AutoInventoryOpen(opener=self.calls.append, clock=lambda: self.now)

    def test_waits_for_response_and_does_not_toggle_after_confirmation(self):
        self.assertEqual(self.auto.tick(123, {})['state'], 'requested')
        self.now = 19
        self.auto.tick(123, {})
        self.assertEqual(self.calls, [123])
        self.assertEqual(self.auto.tick(123, {'full_list_received': True})['state'], 'received')
        self.now = 100
        self.auto.tick(123, {'full_list_received': True})
        self.assertEqual(self.calls, [123])

    def test_already_captured_full_list_and_disabled_setting_send_no_keys(self):
        self.auto.tick(123, {}, enabled=False)
        self.auto.tick(123, {'full_list_received': True})
        self.assertEqual(self.calls, [])

    def test_retries_once_for_an_inventory_that_was_already_open(self):
        for moment in (0, 19, 20, 39, 40, 100):
            self.now = moment
            state = self.auto.tick(123, {})
        self.assertEqual(self.calls, [123, 123])
        self.assertEqual(state['state'], 'failed')

    def test_focus_failure_does_not_consume_a_toggle(self):
        def unavailable(pid):
            raise InputNotReady('focus')
        self.auto.opener = unavailable
        self.assertEqual(self.auto.tick(123, {})['attempts'], 0)
        self.auto.opener = self.calls.append
        self.now = 3
        self.assertEqual(self.auto.tick(123, {})['state'], 'requested')
        self.assertEqual(self.calls, [123])

    def test_inventory_is_refreshed_after_a_capture_gap(self):
        self.auto.tick(123, {'full_list_received': True})
        self.assertEqual(self.auto.tick(123, {'full_list_received': True, 'coverage_gap': True})['state'], 'requested')
        self.assertEqual(self.calls, [123])


if __name__ == '__main__':
    unittest.main()
