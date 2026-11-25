import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from decode_online_probe import decode_server, interval_bytes


class OnlineProbeTests(unittest.TestCase):
    def setUp(self):
        # Fixed short-branch vector: counter 7 -> 8, body length 9.
        # Clear body: DeleteObject(0x10000001), trailing DWORD 1.
        self.wire = bytes.fromhex('0b000d070708190b0b0c05')
        self.before = dict(server_counter=7, incoming_key='000102030405060708090a0b0c0d0e0f')
        self.after = dict(server_counter=8, incoming_key='0001026b6c6d6e6f08090a0b0c0d0e0f')

    def test_fixed_vector_and_live_end_state(self):
        _, packets, index = decode_server(self.wire, [5] * len(self.wire), self.before, self.after)
        self.assertEqual(packets[0].hex(), '0b00080100001001000000')
        self.assertEqual(index[0]['object_id'], 0x10000001)

    def test_wrong_final_key_is_rejected(self):
        after = self.after | dict(incoming_key='00' * 16)
        with self.assertRaisesRegex(ValueError, 'final live key'):
            decode_server(self.wire, [5] * len(self.wire), self.before, after)

    def test_missing_capture_record_is_rejected(self):
        after = self.after | dict(server_counter=9)
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            decode_server(self.wire, [5] * len(self.wire), self.before, after)

    def test_interval_excludes_state_read_windows(self):
        rows = [dict(**{'frame.number': str(frame), 'frame.time_epoch': str(frame),
                        'ip.src': '146.59.110.40', 'ip.dst': 'client', 'tcp.stream': '0',
                        'tcp.seq_raw': str(100 + frame), 'tcp.flags.syn': '0', 'tcp.payload': '61'})
                for frame in range(1, 5)]
        data, frames, _ = interval_bytes(rows, 'server', dict(read_end_ns=1_000_000_000),
                                       dict(read_start_ns=4_000_000_000))
        self.assertEqual(data, b'aa')
        self.assertEqual(frames, [2, 3])


if __name__ == '__main__':
    unittest.main()
