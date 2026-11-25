import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.auto_pickup import AutoPickup
from test_inventory_drop import FakeMonitor


class PickupTransport:
    def __init__(self, monitor, items):
        self.monitor, self.items = monitor, items
        self.calls = []
        self.sent = True
        self.confirm = True

    def pickup(self, status, oid, xyz, radius):
        self.calls.append((oid, xyz, radius))
        if self.sent and self.confirm:
            stock = self.monitor.inventory.snapshot()['items'][0]['amount']
            self.monitor.update_stock(stock + 1)
            self.monitor.store.add([
                self.monitor.packet('client', 'action', object_id=oid),
                self.monitor.packet('server', 'get_item', object_id=oid, owner_id=99),
            ])
            self.items[0]['state'] = 'picked_up'
        return dict(sent=self.sent, destination=[100, 200, 300])


class AutoPickupTests(unittest.TestCase):
    def setUp(self):
        self.monitor = FakeMonitor()
        self.items = [dict(object_id=70, template_value=57, amount=1, xyz=[124, 200, 300], state='present')]
        self.monitor.world = SimpleNamespace(snapshot=lambda: dict(items=self.items, own_position=[100, 200, 300]))
        self.drop_active = False
        self.monitor.inventory_drop = SimpleNamespace(snapshot=lambda: dict(active=self.drop_active))
        self.transport = PickupTransport(self.monitor, self.items)
        self.auto = AutoPickup(self.monitor, self.transport)

    def test_disabled_by_default(self):
        self.auto.tick()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.auto.snapshot()['state'], 'disabled')

    def test_confirms_pickup_with_server_event_and_inventory_increase(self):
        self.auto.enabled = True
        self.auto.tick()
        self.assertTrue(self.auto.snapshot()['pending'])
        self.auto.tick()
        result = self.auto.snapshot()
        self.assertEqual((result['picked_items'], result['picked_amount']), (1, 1))
        self.assertEqual(self.transport.calls, [(70, [124, 200, 300], 200)])

    def test_pauses_while_drop_queue_is_active_then_picks_up_own_drop(self):
        self.auto.enabled = True
        self.drop_active = True
        self.auto.tick()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.auto.snapshot()['state'], 'dropping')
        self.drop_active = False
        self.items[0]['dropper_id'] = 99
        self.auto.tick()
        self.auto.tick()
        self.assertEqual(self.auto.snapshot()['picked_items'], 1)

    def test_other_players_pickup_without_inventory_update_is_not_counted(self):
        self.auto.enabled = True
        self.transport.confirm = False
        self.auto.tick()
        self.monitor.store.add([self.monitor.packet('server', 'get_item', object_id=70, owner_id=77)])
        self.auto.pending['deadline'] = 0
        self.auto.tick()
        self.assertEqual(self.auto.snapshot()['picked_items'], 0)
        self.assertEqual(self.auto.snapshot()['failures'], 1)

    def test_server_delete_and_inventory_delta_confirm_the_observed_fast_pickup(self):
        self.auto.enabled = True
        self.transport.confirm = False
        self.auto.tick()
        self.monitor.update_stock(6)
        self.monitor.store.add([
            self.monitor.packet('client', 'action', object_id=70),
            self.monitor.packet('server', 'delete_object', object_id=70),
        ])
        self.auto.tick()
        self.assertEqual(self.auto.snapshot()['picked_items'], 1)
        self.assertEqual(self.auto.snapshot()['failures'], 0)

    def test_native_radius_check_does_not_issue_an_action_for_far_item(self):
        self.auto.enabled = True
        self.transport.sent = False
        self.auto.tick()
        self.auto.tick()
        self.assertFalse(self.auto.snapshot()['pending'])
        self.assertEqual(self.auto.snapshot()['attempts'], 0)
        self.assertEqual(len(self.transport.calls), 1)

    def test_disabling_during_confirmation_sends_no_additional_actions(self):
        self.auto.enabled = True
        self.auto.tick()
        self.auto.configure(False)
        self.auto.tick()
        self.auto.tick()
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.auto.snapshot()['state'], 'disabled')

    def test_uncertain_ground_items_and_inventory_gaps_are_not_used(self):
        self.auto.enabled = True
        self.items[0]['state'] = 'uncertain'
        self.auto.tick()
        self.assertEqual(self.transport.calls, [])
        self.items[0]['state'] = 'present'
        self.monitor.inventory.gap()
        self.auto.tick()
        self.assertEqual(self.transport.calls, [])

    def test_native_failure_is_not_retried_automatically(self):
        self.auto.enabled = True
        def failed(*args):
            self.transport.calls.append(args)
            raise RuntimeError('native call failed')
        self.transport.pickup = failed
        self.auto.tick()
        self.auto.tick()
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.auto.snapshot()['state'], 'failed')


if __name__ == '__main__':
    unittest.main()
