import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.diagnostics import parse_client_diagnostic
from l2_monitor.diagnostic_audit import audit_files, write_audit


CMPF0 = bytes.fromhex('1c00ff0402434d5046303a203642384331314144205b307835305d00')


def diagnostic(message):
    body = b'\xff\x04\x02' + message.encode('ascii') + b'\x00'
    return struct.pack('<H', len(body) + 2) + body


def record(raw=CMPF0, **values):
    row = dict(direction='client', opcode='FF', raw_hex=raw.hex(),
               sha256=hashlib.sha256(raw).hexdigest(), ciphertext_reproduced=True,
               frame=290, session_id='saved-test')
    row.update(values)
    return row


class DiagnosticParsingTests(unittest.TestCase):
    def test_observed_cmpf0_value_has_no_assigned_address_role(self):
        result = parse_client_diagnostic(CMPF0)
        self.assertEqual(result['diagnostic_value'], '0x6B8C11AD')
        self.assertEqual(result['reported_opcode'], '0x50')
        self.assertTrue(result['diagnostic_format_verified'])
        self.assertNotIn('return_address', result)
        self.assertNotIn('module', result)

    def test_observed_thread_message_retains_both_numbers(self):
        raw = diagnostic('Packet Fake Send Thrd [0x50] 21896 != 125724 | Error [4353001E]')
        result = parse_client_diagnostic(raw)
        self.assertEqual((result['thread_id_left'], result['thread_id_right']), (21896, 125724))
        self.assertTrue(result['thread_ids_differ'])
        self.assertEqual(result['error_code'], '0x4353001E')
        self.assertEqual(result['reported_opcode'], '0x50')

    def test_variant_text_is_preserved_without_guessing_values(self):
        message = 'CMPF0: new-format [0x50]'
        result = parse_client_diagnostic(diagnostic(message))
        self.assertEqual(result['message'], message)
        self.assertEqual(result['diagnostic_type'], 'cmpf0')
        self.assertFalse(result['diagnostic_format_verified'])
        self.assertNotIn('diagnostic_value', result)

    def test_other_envelopes_are_not_diagnostics(self):
        for raw in (b'', b'\x03\x00\xff', bytes.fromhex('0600ff010200')):
            self.assertIsNone(parse_client_diagnostic(raw))

    def test_missing_terminator_embedded_nul_and_nonascii_are_rejected(self):
        for raw in (CMPF0[:-1], CMPF0[:-1] + b'\x00tail\x00', CMPF0[:5] + b'\xff\x00'):
            with self.assertRaises((ValueError, UnicodeError)):
                parse_client_diagnostic(raw)


class SavedDiagnosticAuditTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'packets.jsonl'

    def write_records(self, rows):
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')

    def test_saved_record_audit_preserves_source_and_reports_only_observed_fields(self):
        self.write_records([record()])
        before = self.path.read_bytes()
        report = audit_files([self.path])
        source = report['sources'][0]
        self.assertEqual(source['sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(source['packet_types'], {'client:FF': 1})
        self.assertEqual(source['diagnostics'][0]['fields']['diagnostic_value'], '0x6B8C11AD')
        self.assertEqual(report['totals']['issues'], 0)
        self.assertEqual(report['packets_sent'], 0)
        self.assertIn('diagnostic_value_role', report['unknowns'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_truncated_json_wrong_length_and_digest_mismatch_are_visible(self):
        self.write_records([record(sha256='0' * 64), record(raw_hex='0300ff040200')])
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write('{"truncated":')
        source = audit_files([self.path])['sources'][0]
        self.assertEqual({i['code'] for i in source['issues']},
                         {'packet_digest_mismatch', 'invalid_packet_length', 'invalid_json_record'})
        self.assertEqual(source['diagnostics'], [])

    def test_server_bytes_cannot_be_attributed_to_client_diagnostic(self):
        self.write_records([record(direction='server')])
        source = audit_files([self.path])['sources'][0]
        self.assertEqual(source['packet_types'], {'server:FF': 1})
        self.assertEqual(source['diagnostics'], [])

    def test_missing_source_is_an_issue(self):
        report = audit_files([self.path])
        self.assertEqual(report['totals']['issues'], 1)
        self.assertIsNone(report['sources'][0]['sha256'])

    def test_input_cannot_be_replaced_by_report(self):
        self.write_records([record()])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'different'):
            write_audit([self.path], self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_hard_link_cannot_replace_input_with_report(self):
        self.write_records([record()])
        before = self.path.read_bytes()
        output = self.path.parent / 'same-file.json'
        output.hardlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'different'):
            write_audit([self.path], output)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
