import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from capture_summary import contiguous_chunks, framing_candidate


class CaptureSummaryTests(unittest.TestCase):
    def test_split_messages_reordered_and_retransmitted(self):
        data = b'\x05\x00abc\x04\x00de'
        chunks, stats = contiguous_chunks([(103, data[3:]), (100, data[:5]), (100, data[:5])])
        self.assertEqual(chunks, [data])
        self.assertEqual(stats['conflicting_bytes'], 0)
        self.assertEqual(framing_candidate(chunks[0])['candidate_records'], 2)

    def test_gap_does_not_join_messages(self):
        chunks, stats = contiguous_chunks([(10, b'\x05\x00a'), (15, b'bc')])
        self.assertEqual(stats['gap_bytes'], 2)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(framing_candidate(chunks[0])['candidate_records'], 0)

    def test_conflicting_retransmission_is_reported(self):
        _, stats = contiguous_chunks([(10, b'abc'), (11, b'Xd')])
        self.assertEqual(stats['conflicting_bytes'], 2)

    def test_sequence_wrap(self):
        chunks, stats = contiguous_chunks([(2**32 - 2, b'ab'), (0, b'cd')])
        self.assertEqual(chunks, [b'abcd'])
        self.assertEqual(stats['gap_bytes'], 0)

    def test_partial_header_and_impossible_lengths(self):
        self.assertEqual(framing_candidate(b'\x05')['trailing_bytes'], 1)
        self.assertEqual(framing_candidate(b'\x01\x00')['stop_reason'], 'length_less_than_3')

    def test_empty_segments_do_not_create_gaps(self):
        chunks, stats = contiguous_chunks([(10, b'ab'), (20, b''), (25, b'x')])
        self.assertEqual(chunks, [b'ab', b'x'])
        self.assertEqual(stats['gap_bytes'], 13)
        chunks, stats = contiguous_chunks([(10, b'ab'), (20, b'')])
        self.assertEqual(chunks, [b'ab'])
        self.assertEqual(stats['gap_bytes'], 0)
        self.assertEqual(contiguous_chunks([(20, b'')])[0], [])

    def test_partial_next_header_has_explicit_reason(self):
        result = framing_candidate(b'\x03\x00a\x07')
        self.assertEqual(result['candidate_records'], 1)
        self.assertEqual(result['consumed_bytes'], 3)
        self.assertEqual(result['trailing_bytes'], 1)
        self.assertEqual(result['stop_reason'], 'partial_header')


if __name__ == '__main__':
    unittest.main()
