import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.tcp_records import TcpRecords


ENDPOINT = dict(local_ip='192.0.2.1', local_port=50123,
                remote_ip='198.51.100.2', remote_port=7777)


def record(body):
    return (len(body) + 2).to_bytes(2, 'little') + body


def row(seq, payload=b'', direction='server', frame=1, syn=False):
    local = (ENDPOINT['local_ip'], ENDPOINT['local_port'])
    remote = (ENDPOINT['remote_ip'], ENDPOINT['remote_port'])
    source, destination = (local, remote) if direction == 'client' else (remote, local)
    return {'ip.src': source[0], 'tcp.srcport': str(source[1]),
            'ip.dst': destination[0], 'tcp.dstport': str(destination[1]),
            'tcp.seq_raw': str(seq & 0xffffffff), 'tcp.flags.syn': '1' if syn else '0',
            'tcp.payload': payload.hex(), 'frame.number': str(frame),
            'frame.time_epoch': f'1700000000.{frame:06d}'}


class TcpRecordTests(unittest.TestCase):
    def test_midstream_has_no_guessed_boundary(self):
        parser = TcpRecords(ENDPOINT)
        self.assertEqual(parser.feed([row(10, record(b'abc'))]), [])
        self.assertEqual(parser.state('server')['status'], 'unsynchronized')
        self.assertEqual(parser.state('server')['buffered_bytes'], 0)
        parser.seed('server', 10)
        self.assertEqual(parser.feed([row(10, record(b'abc'))])[0]['body'], b'abc')

    def test_syn_without_payload_seeds_and_repeated_rows_do_not_reemit(self):
        parser = TcpRecords(ENDPOINT)
        rows = [row(100, syn=True), row(101, record(b'abc'))]
        first = parser.feed(rows)
        self.assertEqual([r['seq'] for r in first], [101])
        self.assertEqual(parser.feed(rows), [])
        self.assertEqual(parser.state('server')['records'], 1)

    def test_syn_with_payload_consumes_sequence_number(self):
        parser = TcpRecords(ENDPOINT)
        result = parser.feed([row(0xffffffff, record(b'abc'), syn=True)])
        self.assertEqual(result[0]['seq'], 0)
        self.assertEqual(result[0]['raw'], record(b'abc'))

    def test_fragmentation_coalescing_and_metadata(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        wire = record(b'one') + record(b'two')
        self.assertEqual(parser.feed([row(100, wire[:1], frame=5)]), [])
        self.assertEqual(parser.state('server')['status'], 'partial')
        result = parser.feed([row(101, wire[1:], frame=6)])
        self.assertEqual([r['body'] for r in result], [b'one', b'two'])
        self.assertEqual(result[0]['frame'], 5)
        self.assertEqual(result[0]['end_frame'], 6)
        self.assertEqual(result[0]['time'], '1700000000.000005')
        self.assertEqual(result[1]['seq'], 105)
        self.assertEqual(parser.state('server')['status'], 'ready')

    def test_out_of_order_and_internal_holes_wait(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        wire = record(b'abcdefgh')
        self.assertEqual(parser.feed([row(106, wire[6:])]), [])
        self.assertEqual(parser.state('server')['status'], 'gap')
        self.assertEqual(parser.feed([row(100, wire[:3])]), [])
        self.assertEqual(parser.state('server')['status'], 'gap')
        result = parser.feed([row(103, wire[3:6])])
        self.assertEqual(result[0]['wire'], wire)

    def test_matching_overlap_and_retransmissions(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        wire = record(b'abcdefgh')
        parser.feed([row(100, wire[:5])])
        result = parser.feed([row(103, wire[3:])])
        self.assertEqual(result[0]['wire'], wire)
        self.assertEqual(parser.feed([row(100, wire)]), [])
        self.assertEqual(parser.state('server')['duplicate_bytes'], 12)

    def test_completion_preserves_order_when_late_prefix_unblocks_two_records(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        wire = record(b'first') + record(b'second')
        self.assertEqual(parser.feed([row(101, wire[1:], frame=1)]), [])
        result = parser.feed([row(100, wire[:1], frame=2)])
        self.assertEqual([packet['body'] for packet in result], [b'first', b'second'])
        self.assertEqual([packet['frame'] for packet in result], [2, 1])
        self.assertEqual([packet['completion_frame'] for packet in result], [2, 2])
        self.assertEqual([packet['completion_time'] for packet in result],
                         ['1700000000.000002', '1700000000.000002'])
        self.assertEqual(parser.feed([row(100, wire[:4], frame=3)]), [])
        # A retransmission cannot change already published capture metadata.
        self.assertEqual([packet['completion_frame'] for packet in result], [2, 2])

    def test_completion_includes_late_internal_hole_not_just_last_byte(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        wire = record(b'first')
        parser.feed([row(100, wire[:3], frame=1), row(104, wire[4:], frame=2)])
        result = parser.feed([row(103, wire[3:4], frame=3)])
        self.assertEqual(result[0]['frame'], 1)
        self.assertEqual(result[0]['end_frame'], 2)
        self.assertEqual(result[0]['completion_frame'], 3)

    def test_conflicting_pending_overlap_stops_until_explicit_seed(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        parser.feed([row(100, record(b'abcdefgh')[:5])])
        self.assertEqual(parser.feed([row(103, b'WRONG')]), [])
        self.assertEqual(parser.state('server')['status'], 'conflict')
        self.assertFalse(parser.state('server')['synchronized'])
        self.assertEqual(parser.feed([row(100, record(b'abc'))]), [])
        parser.seed('server', 500)
        self.assertEqual(parser.feed([row(500, record(b'ok'))])[0]['body'], b'ok')

    def test_emitted_bytes_cannot_be_changed(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        original = parser.feed([row(100, record(b'abc'))])[0]
        self.assertEqual(parser.feed([row(102, b'X' + record(b'new'))]), [])
        self.assertEqual(original['body'], b'abc')
        self.assertEqual(parser.state('server')['status'], 'conflict')
        self.assertEqual(parser.state('server')['records'], 1)

    def test_sequence_rollover_and_old_overlap_then_new_record(self):
        parser = TcpRecords(ENDPOINT)
        start = 0xfffffffc
        parser.seed('server', start)
        first, second = record(b'abc'), record(b'def')
        parser.feed([row(start, first)])
        result = parser.feed([row(start + 2, first[2:] + second)])
        self.assertEqual(result[0]['seq'], 1)
        self.assertEqual(result[0]['body'], b'def')

    def test_directions_and_foreign_connections_are_isolated(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 10)
        parser.seed('client', 10)
        foreign = row(10, record(b'foreign'))
        foreign['ip.src'] = '198.51.100.3'
        result = parser.feed([foreign, row(10, record(b'reply')),
                              row(10, record(b'request'), 'client')])
        self.assertEqual([(r['direction'], r['body']) for r in result],
                         [('server', b'reply'), ('client', b'request')])

    def test_invalid_lengths_stop_without_scanning_for_next_record(self):
        for length in (0, 1, 2):
            with self.subTest(length=length):
                parser = TcpRecords(ENDPOINT)
                parser.seed('server', 10)
                self.assertEqual(parser.feed([row(10, bytes([length, 0]) + record(b'valid'))]), [])
                self.assertEqual(parser.state('server')['status'], 'invalid_length')

    def test_sparse_gap_is_bounded_and_does_not_allocate(self):
        parser = TcpRecords(ENDPOINT, max_buffer=65535)
        parser.seed('server', 10)
        parser.feed([row(10 + 65535, b'x')])
        self.assertEqual(parser.state('server')['status'], 'overflow')
        self.assertEqual(parser.state('server')['buffered_bytes'], 0)

    def test_retained_history_is_bounded_and_old_bytes_are_unverifiable(self):
        parser = TcpRecords(ENDPOINT, history_bytes=3)
        parser.seed('server', 100)
        parser.feed([row(100, record(b'abcdefgh'))])
        self.assertEqual(parser.state('server')['history_bytes'], 3)
        parser.feed([row(100, b'?????')])
        self.assertEqual(parser.state('server')['unverifiable_bytes'], 5)
        self.assertEqual(parser.state('server')['status'], 'ready')

    def test_maximum_record_and_shuffled_segment_boundaries(self):
        rng = random.Random(187)
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 0xfffff800)
        wire = record(bytes(rng.randrange(256) for _ in range(65533)))
        parts = []
        offset = 0
        while offset < len(wire):
            size = rng.randrange(1, 1800)
            parts.append(row(0xfffff800 + offset, wire[offset:offset + size], frame=len(parts) + 1))
            offset += size
        rng.shuffle(parts)
        result = parser.feed(parts + parts)
        self.assertEqual([r['wire'] for r in result], [wire])
        self.assertEqual(parser.state('server')['buffered_bytes'], 0)
        self.assertLessEqual(parser.state('server')['history_bytes'], 65535)

    def test_new_syn_resets_only_its_direction_and_explicit_unseed_is_supported(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('client', 10)
        parser.seed('server', 10)
        parser.feed([row(10, record(b'old'))])
        result = parser.feed([row(500, record(b'new'), syn=True)])
        self.assertEqual(result[0]['seq'], 501)
        self.assertEqual(parser.state('client')['next_seq'], 10)
        parser.seed('server', None)
        self.assertEqual(parser.state('server')['status'], 'unsynchronized')

    def test_ambiguous_half_sequence_space_and_malformed_rows(self):
        parser = TcpRecords(ENDPOINT)
        parser.seed('server', 100)
        bad = row(100, b'bad')
        bad['tcp.payload'] = 'xy'
        self.assertEqual(parser.feed([{}, bad]), [])
        parser.feed([row(100 + 0x80000000, b'x')])
        self.assertEqual(parser.state('server')['status'], 'overflow')


if __name__ == '__main__':
    unittest.main()
