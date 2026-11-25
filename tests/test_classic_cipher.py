"""Synthetic end-to-end checkpoint tests; no client/process/network access."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.classic_cipher import RunningXor64, decode_classic_window
from l2_monitor.protocol import Catalog


ENDPOINT = dict(local_ip='192.0.2.1', local_port=50001,
                remote_ip='198.51.100.2', remote_port=7777)
BASES = dict(server=0xfffffff0, client=1000)
MASK64 = (1 << 64) - 1


def encrypt_sequence(bodies, initial):
    """Independent fixture encryptor, including a uint64 key counter."""
    key = bytes(initial)
    records = []
    for body in bodies:
        encrypted = bytearray()
        previous = 0
        for index, value in enumerate(body):
            previous = value ^ key[index % 16] ^ previous
            encrypted.append(previous)
        records.append((len(body) + 2).to_bytes(2, 'little') + encrypted)
        counter = (int.from_bytes(key[8:], 'little') + len(body)) & MASK64
        key = key[:8] + counter.to_bytes(8, 'little')
    return records, key


def make_row(direction, offset, payload, frame):
    source, destination = (('local', 'remote') if direction == 'client' else ('remote', 'local'))
    return {'ip.src': ENDPOINT[source + '_ip'], 'ip.dst': ENDPOINT[destination + '_ip'],
            'tcp.srcport': str(ENDPOINT[source + '_port']),
            'tcp.dstport': str(ENDPOINT[destination + '_port']), 'tcp.stream': '0',
            'tcp.seq_raw': str((BASES[direction] + offset) & 0xffffffff),
            'tcp.flags.syn': '0', 'tcp.payload': payload.hex(),
            'frame.number': str(frame), 'frame.time_epoch': f'2.{frame:06d}'}


def fixture(server=None, client=None, *, tail=0xfffffff9):
    bodies = dict(server=[b'\x99server-one', b'\x98server-two'] if server is None else server,
                  client=[b'\x17client-one', b'\x20\x01\x00client-two'] if client is None else client)
    opcode_map = list(range(0xd1))
    opcode_map[0x17], opcode_map[0x0f] = opcode_map[0x0f], opcode_map[0x17]
    opcode_map[0x20], opcode_map[0xd0] = opcode_map[0xd0], opcode_map[0x20]
    extended_map = list(range(64))
    extended_map[1], extended_map[17] = extended_map[17], extended_map[1]
    initial = b'abcdefgh' + tail.to_bytes(8, 'little')
    before = dict(socket=0x12345000, incoming_key=initial.hex(), outgoing_key=initial.hex(),
                  server_wire=0xfffffff8, client_wire=100, opcode_map=opcode_map,
                  extended_map=extended_map, read_start_ns=1_000_000_000, read_end_ns=1_001_000_000)
    after = copy.deepcopy(before)
    after.update(read_start_ns=3_000_000_000, read_end_ns=3_001_000_000)
    rows, wires = [], {}
    for direction, field in (('server', 'incoming_key'), ('client', 'outgoing_key')):
        records, ending = encrypt_sequence(bodies[direction], initial)
        wires[direction] = b''.join(records)
        after[field] = ending.hex()
        after[direction + '_wire'] = (before[direction + '_wire'] + len(wires[direction])) & 0xffffffff
        if wires[direction]:
            rows.append(make_row(direction, 0, wires[direction], len(rows) + 1))
    return rows, before, after, wires


class ClassicCipherTests(unittest.TestCase):
    def decode(self, rows, before, after, cursors=None):
        return decode_classic_window(rows, before, after, ENDPOINT, Catalog(), 'synthetic', cursors)

    def test_uint64_counter_carries_beyond_uint32_and_wraps_uint64(self):
        for tail in (0xfffffff9, MASK64 - 3):
            with self.subTest(tail=tail):
                initial = b'abcdefgh' + tail.to_bytes(8, 'little')
                bodies = [bytes(range(33)), b'last']
                records, expected_key = encrypt_sequence(bodies, initial)
                cipher = RunningXor64(initial)
                self.assertEqual([cipher.decrypt(record[2:]) for record in records], bodies)
                self.assertEqual(bytes(cipher.key), expected_key)
                self.assertEqual(bytes(cipher.key[:8]), b'abcdefgh')

    def test_invalid_key_sizes_are_rejected(self):
        for size in (0, 15, 17):
            with self.subTest(size=size), self.assertRaises(ValueError):
                RunningXor64(bytes(size))

    def test_both_directions_decode_and_normalize_opcode_permutations(self):
        rows, before, after, wires = fixture()
        packets, result = self.decode(rows, before, after)
        server = [bytes.fromhex(packet['raw_hex'])[2:] for packet in packets if packet['direction'] == 'server']
        client = [packet for packet in packets if packet['direction'] == 'client']
        self.assertEqual(server, [b'\x99server-one', b'\x98server-two'])
        self.assertEqual(bytes.fromhex(client[0]['raw_hex'])[2:], b'\x0fclient-one')
        self.assertEqual(bytes.fromhex(client[1]['raw_hex'])[2:], b'\xd0\x11\x00client-two')
        self.assertEqual(bytes.fromhex(client[0]['decrypted_wire_hex'])[2:], b'\x17client-one')
        self.assertEqual(bytes.fromhex(client[1]['decrypted_wire_hex'])[2:], b'\x20\x01\x00client-two')
        self.assertEqual(client[1]['opcode'], 'D0 11 00')
        self.assertTrue(result['end_states_verified'])
        for direction in ('client', 'server'):
            self.assertEqual(result['directions'][direction]['records'], 2)
            self.assertEqual(result['directions'][direction]['wire_bytes'], len(wires[direction]))
            self.assertEqual(result['wire_cursors'][direction],
                             (BASES[direction] + len(wires[direction])) & 0xffffffff)
        self.assertTrue(all(packet['ciphertext_reproduced'] and packet['cipher_end_state_verified']
                            and packet['actions_supported'] is False for packet in packets))

    def test_tcp_split_out_of_order_and_matching_duplicate_rows(self):
        _, before, after, wires = fixture()
        rows = []
        for direction in ('server', 'client'):
            wire = wires[direction]
            # Capture the tail before a missing prefix, including a split u16.
            for start, end in ((7, len(wire)), (1, 7), (0, 1), (1, 7), (0, 1)):
                rows.append(make_row(direction, start, wire[start:end], len(rows) + 1))
        packets, result = self.decode(rows, before, after)
        self.assertEqual(len(packets), 4)
        self.assertTrue(result['end_states_verified'])
        self.assertEqual([packet['opcode'] for packet in packets if packet['direction'] == 'client'],
                         ['0F', 'D0 11 00'])
        self.assertEqual([packet['frame'] for packet in packets if packet['direction'] == 'server'], [3, 3])
        self.assertEqual([packet['frame'] for packet in packets if packet['direction'] == 'client'], [8, 8])

    def test_missing_bytes_reject_entire_checkpoint_window(self):
        _, before, after, wires = fixture()
        rows = [make_row('server', 0, wires['server'][:6], 1),
                make_row('server', 7, wires['server'][7:], 2),
                make_row('client', 0, wires['client'], 3)]
        with self.assertRaises(ValueError):
            self.decode(rows, before, after)

    def test_conflicting_retransmission_rejects_window(self):
        rows, before, after, wires = fixture()
        changed = bytes([wires['server'][3] ^ 0x80])
        rows.append(make_row('server', 3, changed, 3))
        with self.assertRaises(ValueError):
            self.decode(rows, before, after)

    def test_wrong_full_ending_key_is_rejected_in_either_direction(self):
        for field in ('incoming_key', 'outgoing_key'):
            for byte in (0, 8, 15):
                with self.subTest(field=field, byte=byte):
                    rows, before, after, _ = fixture()
                    key = bytearray.fromhex(after[field])
                    key[byte] ^= 1
                    after[field] = key.hex()
                    with self.assertRaises(ValueError):
                        self.decode(rows, before, after)

    def test_wire_byte_counters_are_required_for_both_directions(self):
        for direction in ('server', 'client'):
            for difference in (-1, 1, 2):
                with self.subTest(direction=direction, difference=difference):
                    rows, before, after, _ = fixture()
                    after[direction + '_wire'] = (after[direction + '_wire'] + difference) & 0xffffffff
                    with self.assertRaises(ValueError):
                        self.decode(rows, before, after)

    def test_changed_socket_or_opcode_maps_reject_before_publication(self):
        for field in ('socket', 'opcode_map', 'extended_map'):
            with self.subTest(field=field):
                rows, before, after, _ = fixture()
                if field == 'socket':
                    after[field] += 4
                else:
                    after[field][0], after[field][1] = after[field][1], after[field][0]
                with self.assertRaises(ValueError):
                    self.decode(rows, before, after)

    def test_out_of_range_client_opcode_is_rejected(self):
        rows, before, after, _ = fixture(client=[b'\xffinvalid'])
        with self.assertRaisesRegex(ValueError, 'opcode is outside'):
            self.decode(rows, before, after)

    def test_out_of_range_or_truncated_extended_opcode_is_rejected(self):
        for body in (b'\x20\x40\x00', b'\x20', b'\x20\x01'):
            with self.subTest(body=body):
                rows, before, after, _ = fixture(client=[body])
                with self.assertRaisesRegex(ValueError, 'extended|Extended'):
                    self.decode(rows, before, after)

    def test_idle_direction_is_valid_and_keeps_existing_cursor(self):
        rows, before, after, _ = fixture(client=[])
        packets, result = self.decode(rows, before, after, {'client': 999})
        self.assertEqual(len(packets), 2)
        self.assertEqual(result['directions']['client']['records'], 0)
        self.assertEqual(result['wire_cursors']['client'], 999)

    def test_explicit_cursor_excludes_previous_window(self):
        rows, before, after, wires = fixture()
        old_record, _ = encrypt_sequence([b'old'], b'abcdefgh' + bytes(8))
        old_wire = old_record[0]
        prefixed = []
        for direction in ('server', 'client'):
            prefixed.append(make_row(direction, -len(old_wire), old_wire, len(prefixed) + 1))
            prefixed.append(make_row(direction, 0, wires[direction], len(prefixed) + 1))
        packets, result = self.decode(prefixed, before, after, BASES)
        self.assertEqual(len(packets), 4)
        self.assertTrue(result['end_states_verified'])


class StrongAnchorTests(unittest.TestCase):
    def make_window(self, *, server=None, client=None, tail=0xfffffff9):
        server = [b'\x99server-one', b'\x98server-two'] if server is None else server
        client = [b'\x17client-one', b'\x20\x01\x00client-two'] if client is None else client
        rows, before, after, wires = fixture(server=server, client=client, tail=tail)
        if server:
            after['last_server_packet_hex'] = ((len(server[-1]) + 2).to_bytes(2, 'little') + server[-1]).hex()
        proofs = []
        if client:
            size = len(client[-1]) + 2
            proofs.append(dict(client_wire_after=after['client_wire'], wire_hex=wires['client'][-size:].hex()))
        return rows, before, after, wires, proofs

    def decode(self, rows, before, after, proofs, cursors=None):
        return decode_classic_window(rows, before, after, ENDPOINT, Catalog(), 'native-anchors',
                                     cursors=cursors, client_anchors=proofs)

    def test_both_native_anchors_ignore_capture_timestamps(self):
        rows, before, after, wires, proofs = self.make_window()
        for row in rows:
            row['frame.time_epoch'] = '0.500000'  # Both directions captured before memory checkpoint.
        packets, verification = self.decode(rows, before, after, proofs)
        self.assertEqual(len(packets), 4)
        self.assertEqual([packet['opcode'] for packet in packets if packet['direction'] == 'client'],
                         ['0F', 'D0 11 00'])
        self.assertEqual(verification['wire_cursors']['server'],
                         (BASES['server'] + len(wires['server'])) & 0xffffffff)

    def test_uniform_record_counterexample_uses_native_end_not_timestamp_start(self):
        first, second, extra = b'\x99' + b'A' * 28, b'\x98' + b'B' * 28, b'\x97' + b'C' * 28
        _, before, after, _, proofs = self.make_window(server=[first, second], client=[])
        records, _ = encrypt_sequence([first, second, extra], bytes.fromhex(before['incoming_key']))
        rows = [make_row('server', index * 31, wire, index + 1) for index, wire in enumerate(records)]
        rows[0]['frame.time_epoch'] = '0.500000'
        expected = [first, second]
        legacy_after = {key: value for key, value in after.items() if key != 'last_server_packet_hex'}
        legacy, legacy_verification = decode_classic_window(rows, before, legacy_after, ENDPOINT, Catalog(), 'legacy')
        self.assertTrue(legacy_verification['directions']['server']['key_matches'])
        self.assertNotEqual([bytes.fromhex(packet['raw_hex'])[2:] for packet in legacy], expected)
        packets, verification = self.decode(rows, before, after, proofs)
        self.assertEqual([bytes.fromhex(packet['raw_hex'])[2:] for packet in packets], expected)
        self.assertTrue(verification['end_states_verified'])
        with self.assertRaisesRegex(ValueError, 'cursor disagrees'):
            self.decode(rows, before, after, proofs, {'server': (BASES['server'] + 31) & 0xffffffff})

    def test_fragmented_native_anchor_handles_out_of_order_and_matching_duplicates(self):
        _, before, after, wires, proofs = self.make_window()
        rows = []
        for direction in ('server', 'client'):
            wire = wires[direction]
            for start, end in ((7, len(wire)), (1, 7), (0, 1), (1, 7)):
                rows.append(make_row(direction, start, wire[start:end], len(rows) + 1))
        packets, _ = self.decode(rows, before, after, proofs)
        self.assertEqual(len(packets), 4)
        self.assertEqual([packet['opcode'] for packet in packets if packet['direction'] == 'client'],
                         ['0F', 'D0 11 00'])

    def test_native_receive_counter_rollback_wraps_uint64_and_tcp_sequence(self):
        rows, before, after, wires, proofs = self.make_window(tail=MASK64 - 3)
        packets, result = self.decode(rows, before, after, proofs)
        self.assertEqual(len(packets), 4)
        self.assertEqual(result['wire_cursors']['server'],
                         (BASES['server'] + len(wires['server'])) & 0xffffffff)

    def test_native_receive_packet_missing_or_corrupt_never_falls_back_to_timestamps(self):
        rows, before, after, _, proofs = self.make_window()
        changed = bytearray.fromhex(after['last_server_packet_hex'])
        changed[-1] ^= 0x40
        after['last_server_packet_hex'] = changed.hex()
        with self.assertRaisesRegex(ValueError, 'Waiting.*native packet anchor'):
            self.decode(rows, before, after, proofs)
        with self.assertRaisesRegex(ValueError, 'Waiting'):
            self.decode([row for row in rows if row['ip.src'] == ENDPOINT['local_ip']], before, after, proofs)

    def test_ambiguous_receive_anchor_is_rejected(self):
        rows, before, after, wires, proofs = self.make_window(client=[])
        last = wires['server'][-(len(b'\x98server-two') + 2):]
        rows[0]['tcp.payload'] = (wires['server'] + last).hex()
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.decode(rows, before, after, proofs)

    def test_receive_holes_and_conflicting_bytes_are_rejected(self):
        _, before, after, wires, proofs = self.make_window(client=[])
        wire = wires['server']
        rows = [make_row('server', 0, wire[:6], 1), make_row('server', 7, wire[7:], 2)]
        with self.assertRaises(ValueError):
            self.decode(rows, before, after, proofs)
        rows = [make_row('server', 0, wire, 1), make_row('server', 5, bytes([wire[5] ^ 1]), 2)]
        with self.assertRaises(ValueError):
            self.decode(rows, before, after, proofs)

    def test_visible_before_native_packet_must_agree_with_after_wire_delta(self):
        rows, before, after, wires, proofs = self.make_window(client=[])
        previous_body = b'\x97previous'
        key = bytes.fromhex(before['incoming_key'])
        tail = (int.from_bytes(key[8:], 'little') - len(previous_body)) & MASK64
        previous_wire = encrypt_sequence([previous_body], key[:8] + tail.to_bytes(8, 'little'))[0][0]
        before['last_server_packet_hex'] = ((len(previous_body) + 2).to_bytes(2, 'little') + previous_body).hex()
        rows.insert(0, make_row('server', -len(previous_wire), previous_wire, 1))
        for index, row in enumerate(rows, 1):
            row['frame.number'] = str(index)
        self.assertEqual(len(self.decode(rows, before, after, proofs)[0]), 2)
        # Retain exact proof bytes at a contradictory sequence location.
        rows[0]['tcp.seq_raw'] = str((BASES['server'] - len(previous_wire) - 1) & 0xffffffff)
        rows.insert(1, make_row('server', -1, b'\0', 1))
        for index, row in enumerate(rows, 1):
            row['frame.number'] = str(index)
        with self.assertRaisesRegex(ValueError, 'anchors disagree'):
            self.decode(rows, before, after, proofs)

    def test_client_proofs_empty_missing_or_wrong_counter_cannot_use_timestamp_fallback(self):
        rows, before, after, _, proofs = self.make_window()
        with self.assertRaisesRegex(ValueError, 'Waiting.*client-send proof'):
            self.decode(rows, before, after, [])
        missing = [dict(client_wire_after=proofs[0]['client_wire_after'], wire_hex='0300ff')]
        with self.assertRaisesRegex(ValueError, 'Waiting.*client-send proof'):
            self.decode(rows, before, after, missing)
        wrong = [dict(proofs[0], client_wire_after=proofs[0]['client_wire_after'] + 1)]
        with self.assertRaises(ValueError):
            self.decode(rows, before, after, wrong)

    def test_all_unique_client_proofs_must_agree_on_sequence_base(self):
        rows, before, after, wires, proofs = self.make_window()
        first_size = int.from_bytes(wires['client'][:2], 'little')
        first = dict(client_wire_after=(before['client_wire'] + first_size) & 0xffffffff,
                     wire_hex=wires['client'][:first_size].hex())
        self.assertEqual(len(self.decode(rows, before, after, proofs + [first])[0]), 4)
        first['client_wire_after'] += 1
        with self.assertRaisesRegex(ValueError, 'proofs disagree'):
            self.decode(rows, before, after, proofs + [first])

    def test_client_counter_wrap_and_old_wrong_cursor_rejection(self):
        rows, before, after, wires, proofs = self.make_window()
        before['client_wire'] = 0xfffffff8
        after['client_wire'] = (before['client_wire'] + len(wires['client'])) & 0xffffffff
        proofs[0]['client_wire_after'] = after['client_wire']
        self.assertEqual(len(self.decode(rows, before, after, proofs)[0]), 4)
        with self.assertRaisesRegex(ValueError, 'cursor disagrees'):
            self.decode(rows, before, after, proofs, {'client': BASES['client'] + 1})

    def test_only_repeated_short_client_wire_cannot_anchor_a_counter(self):
        rows, before, after, wires, proofs = self.make_window(client=[b'\x14', b'\x14'])
        with self.assertRaisesRegex(ValueError, 'unique.*client-send proof'):
            self.decode(rows, before, after, proofs)

    def test_zero_traffic_requires_no_client_proof_or_visible_receive_anchor(self):
        rows, before, after, _, _ = self.make_window(client=[])
        before.update(incoming_key=after['incoming_key'], server_wire=after['server_wire'])
        packets, result = self.decode([], before, after, [])
        self.assertEqual(packets, [])
        self.assertEqual(result['directions']['server']['records'], 0)

    def test_verified_client_cursor_survives_proofs_trimmed_from_capture(self):
        rows, before, after, wires, proofs = self.make_window()
        packets, result = self.decode(rows, before, after, [], {'client': BASES['client']})
        self.assertEqual(len(packets), 4)
        self.assertEqual(result['wire_cursors']['client'], BASES['client'] + len(wires['client']))
        # An old short proof may have the same wire bytes as a later packet;
        # its counter-derived position outside this capture is not visible.
        rows, before, after, _, proofs = self.make_window(client=[b'\x14', b'\x14'])
        old = dict(client_wire_after=before['client_wire'] - 3, wire_hex=proofs[0]['wire_hex'])
        self.assertEqual(len(self.decode(rows, before, after, [old], {'client': BASES['client']})[0]), 4)

    def test_visible_client_proof_must_confirm_verified_cursor(self):
        rows, before, after, _, proofs = self.make_window()
        wrong = [dict(proofs[0], client_wire_after=proofs[0]['client_wire_after'] - 1)]
        with self.assertRaisesRegex(ValueError, 'proof disagrees'):
            self.decode(rows, before, after, wrong, {'client': BASES['client']})

    def test_verified_server_cursor_handles_repeated_three_byte_action_failed(self):
        rows, before, after, _, proofs = self.make_window(server=[b'\x25', b'\x25'], client=[])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.decode(rows, before, after, proofs)
        packets, result = self.decode(rows, before, after, proofs, {'server': BASES['server']})
        self.assertEqual([packet['opcode'] for packet in packets], ['25', '25'])
        self.assertEqual(result['wire_cursors']['server'], (BASES['server'] + 6) & 0xffffffff)

    def test_fresh_long_proof_does_not_misattribute_old_identical_short_request(self):
        root = b'\x23' + '_bbslearnSkills\0'.encode('utf-16le')
        rows, before, after, wires, proofs = self.make_window(client=[b'\x50', root])
        short_wire = wires['client'][:3].hex()
        proofs.extend([dict(client_wire_after=before['client_wire'] + 3, wire_hex=short_wire),
                       dict(client_wire_after=before['client_wire'] - 30, wire_hex=short_wire)])
        packets, verification = self.decode(rows, before, after, proofs)
        self.assertEqual(len(packets), 4)
        self.assertTrue(verification['end_states_verified'])


if __name__ == '__main__':
    unittest.main()
