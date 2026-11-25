import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from analyze_prime_timeline import lifecycle, parse_fields, transport


def row(frame, seq, payload):
    return {'frame.number': str(frame), 'frame.time_epoch': str(frame),
            'tcp.seq_raw': str(seq), 'tcp.payload': payload.hex(), 'tcp.stream': '0',
            'ip.src': 'server', 'ip.dst': 'client', 'tcp.flags.syn': '0'}


def event(seq, kind, object_id, direction='server'):
    return dict(timeline_seq=seq, event=kind, object_id=object_id,
                direction=direction, completion_frame=seq, relative_seconds=seq)


class TransportTimingTests(unittest.TestCase):
    def test_early_tail_waits_for_late_tcp_prefix(self):
        data, ready, _ = transport([row(1, 102, b'cd'), row(3, 100, b'ab')], 0, 'server', True)
        self.assertEqual(data, b'abcd')
        self.assertEqual(ready, [3, 3, 3, 3])

    def test_retransmission_does_not_postpone_completion(self):
        data, ready, _ = transport([row(1, 100, b'ab'), row(4, 100, b'ab'),
                                    row(2, 102, b'cd')], 0, 'server', True)
        self.assertEqual(data, b'abcd')
        self.assertEqual(ready, [1, 1, 2, 2])

    def test_sequence_wrap_preserves_timing(self):
        data, ready, _ = transport([row(1, 0xfffffffe, b'ab'), row(2, 0, b'cd')], 0, 'server', True)
        self.assertEqual(data, b'abcd')
        self.assertEqual(ready, [1, 1, 2, 2])

    def test_conflicting_overlap_is_rejected(self):
        with self.assertRaises(ValueError):
            transport([row(1, 100, b'ab'), row(2, 101, b'X')], 0, 'server', True)


class ObjectEvidenceTests(unittest.TestCase):
    def test_future_description_does_not_explain_earlier_action(self):
        objects, actions, _, _ = lifecycle([event(1, 'action', 20, 'client'),
                                          event(2, 'npc_info', 20),
                                          event(3, 'action', 20, 'client')], 10)
        self.assertEqual([a['packet_state_before_action'] for a in actions], ['unknown', 'described'])
        self.assertIsNone(actions[0]['visible'])
        self.assertIsNone(actions[1]['targetable'])
        self.assertEqual(objects[20]['object_kind'], 'npc')

    def test_drop_and_pickup_withdraw_only_item(self):
        objects, actions, _, counts = lifecycle([event(1, 'npc_info', 20),
              event(2, 'drop_item', 30), event(3, 'action', 30, 'client'),
              event(4, 'get_item', 30), event(5, 'delete_object', 30)], 10)
        self.assertEqual(objects[20]['packet_state'], 'described')
        self.assertEqual(objects[30]['packet_state'], 'withdrawn')
        self.assertEqual(actions[0]['object_kind'], 'item')
        self.assertEqual(counts['delete_object_from_withdrawn'], 1)

    def test_refresh_and_new_appearance_are_distinct(self):
        objects, _, _, counts = lifecycle([event(1, 'npc_info', 20), event(2, 'npc_info', 20),
                                          event(3, 'delete_object', 20), event(4, 'npc_info', 20)], 10)
        self.assertEqual(objects[20]['descriptions'], 3)
        self.assertEqual(objects[20]['appearance_intervals'], 2)
        self.assertEqual(counts['description_refreshes'], 1)
        self.assertEqual(counts['descriptions_after_withdrawal'], 1)

    def test_unintroduced_delete_preserves_unknown_kind(self):
        objects, _, _, counts = lifecycle([event(1, 'delete_object', 20)], 10)
        self.assertEqual(objects[20]['object_kind'], 'unknown')
        self.assertEqual(counts['delete_object_from_unknown'], 1)

    def test_updates_retain_state_at_the_time_of_the_packet(self):
        events = [event(1, 'position', 20), event(2, 'npc_info', 20),
                  event(3, 'delete_object', 20), event(4, 'move', 20), event(5, 'npc_info', 20)]
        _, _, _, counts = lifecycle(events, 10)
        self.assertEqual(events[0]['object_packet_state_before'], 'unknown')
        self.assertEqual(events[3]['object_packet_state_before'], 'withdrawn')
        self.assertEqual(counts['other_object_updates_while_unknown'], 1)
        self.assertEqual(counts['other_object_updates_while_withdrawn'], 1)

    def test_drop_item_uses_second_id_and_signed_coordinates(self):
        body = bytes([0x16]) + struct.pack('<IIIiiiIQI', 20, 30, 57, -10, 20, -30, 1, 12, 0)
        fields = parse_fields('server', struct.pack('<H', len(body) + 2) + body)
        self.assertEqual((fields['object_id'], fields['dropper_id']), (30, 20))
        self.assertEqual(fields['xyz'], [-10, 20, -30])
        self.assertEqual(fields['amount'], 12)

    def test_incompatible_packet_shape_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_fields('server', b'\x07\x00\x08' + struct.pack('<I', 20))


if __name__ == '__main__':
    unittest.main()
