import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.drop_queue import InventoryDropQueue
from l2_monitor.engine import PacketStore
from l2_monitor.inventory import Inventory


class FakeMonitor:
    def __init__(self):
        self.session = 'test-session'
        self.inventory = Inventory()
        self.inventory.reset(self.session)
        self.store = PacketStore()
        self.update_stock(5, full=True)

    def status(self):
        return dict(state='live', running=True, session_id=self.session)

    def packet(self, direction, event, **fields):
        return dict(direction=direction, opcode='17' if direction == 'client' else '16', name=event,
                    category='item_drop', color='#fff', fields=dict(event=event, **fields))

    def update_stock(self, amount, full=False):
        packet = self.packet('server', 'inventory_update', items=[dict(
            action=2 if amount else 3, object_id=7, item_id=57, slot=1, amount=amount)])
        if full:
            packet['fields'].update(list_type=1, record_size=74)
        self.inventory.apply([packet])


class FakeTransport:
    def __init__(self, monitor, acknowledge=True):
        self.monitor = monitor
        self.acknowledge = acknowledge
        self.calls = []
        self.sent = threading.Event()

    def send(self, status, object_id, amount):
        self.calls.append(amount)
        self.sent.set()
        if self.acknowledge:
            self.confirm(amount)
        return dict(destination=[124, 200, 300])

    def confirm(self, amount, ground=True):
        stock = self.monitor.inventory.snapshot()['items'][0]['amount']
        self.monitor.update_stock(stock - amount)
        packets = [self.monitor.packet('client', 'drop_request', object_id=7, amount=amount)]
        if ground:
            packets.append(self.monitor.packet('server', 'drop_item', template_value=57, amount=amount, xyz=[124, 200, 300]))
        self.monitor.store.add(packets)


class InventoryDropTests(unittest.TestCase):
    def setUp(self):
        self.monitor = FakeMonitor()
        self.transport = FakeTransport(self.monitor)
        self.queue = InventoryDropQueue(self.monitor, self.transport, confirmation_timeout=.3)
        self.addCleanup(self.queue.close)

    def wait_idle(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = self.queue.snapshot()
            if not state['active']:
                return state
            time.sleep(.01)
        self.fail('Queue did not finish')

    def test_single_mode_confirms_each_of_three_individual_drops(self):
        self.queue.enqueue(7, 3, 'single', 100)
        result = self.wait_idle()['jobs'][0]
        self.assertEqual(self.transport.calls, [1, 1, 1])
        self.assertEqual((result['state'], result['dropped']), ('completed', 3))

    def test_bulk_mode_sends_the_requested_amount_once(self):
        self.queue.enqueue(7, 3, 'bulk', 100)
        result = self.wait_idle()['jobs'][0]
        self.assertEqual(self.transport.calls, [3])
        self.assertEqual(result['dropped'], 3)

    def test_server_rejection_does_not_repeat_or_advance_the_queue(self):
        self.transport.acknowledge = False
        self.queue.enqueue(7, 2, 'single', 100)
        self.queue.enqueue(7, 1, 'bulk', 100)
        rows = self.wait_idle()['jobs']
        self.assertEqual(self.transport.calls, [1])
        self.assertEqual({row['state'] for row in rows}, {'failed', 'stopped'})
        self.assertEqual(sum(row['dropped'] for row in rows), 0)

    def test_inventory_delta_without_ground_confirmation_is_not_success(self):
        self.transport.send = lambda status, oid, amount: (self.transport.confirm(amount, ground=False) or dict(destination=[124, 200, 300]))
        self.queue.enqueue(7, 1, 'bulk', 100)
        self.assertEqual(self.wait_idle()['jobs'][0]['state'], 'failed')

    def test_pause_and_quantity_reservations(self):
        self.queue.pause()
        self.queue.enqueue(7, 3, 'bulk', 100)
        with self.assertRaises(ValueError):
            self.queue.enqueue(7, 3, 'bulk', 100)
        self.assertFalse(self.transport.sent.wait(.1))
        self.queue.pause(False)
        self.assertEqual(self.wait_idle()['jobs'][0]['state'], 'completed')

    def test_stop_during_confirmation_finishes_inflight_step_only(self):
        self.transport.acknowledge = False
        self.queue.enqueue(7, 3, 'single', 100)
        self.assertTrue(self.transport.sent.wait(1))
        self.queue.stop()
        self.transport.confirm(1)
        result = self.wait_idle()['jobs'][0]
        self.assertEqual(self.transport.calls, [1])
        self.assertEqual((result['state'], result['dropped']), ('stopped', 1))

    def test_session_change_prevents_dispatch(self):
        self.queue.pause()
        self.queue.enqueue(7, 1, 'bulk', 100)
        self.monitor.session = 'other-session'
        self.queue.pause(False)
        self.assertEqual(self.wait_idle()['jobs'][0]['state'], 'failed')
        self.assertEqual(self.transport.calls, [])

    def test_invalid_amounts_and_gap_are_rejected(self):
        for amount in (0, -1, 6, True, 1.5, 2**63):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.queue.enqueue(7, amount)
        self.monitor.inventory.gap()
        with self.assertRaises(ValueError):
            self.queue.enqueue(7, 1)


if __name__ == '__main__':
    unittest.main()
