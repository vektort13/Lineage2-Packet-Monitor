"""Reproducible audit of saved JSONL records; performs no process or socket I/O."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from .diagnostics import parse_client_diagnostic


def audit_files(paths):
    report = dict(schema='l2-client-diagnostic-audit-v1', sources=[],
                  scope='saved-jsonl-records', active_capture_started=False,
                  packets_sent=0,
                  unknowns=['originating_module', 'emission_function',
                            'meaning_of_cmpf0', 'diagnostic_value_role',
                            'conditions_for_accepting_the_requested_packet'],
                  limitations=[
                      'Only supplied decoded records are examined; missing records or '
                      'capture gaps cannot establish that a packet was never sent.',
                      'Ciphertext reproduction flags are recorded claims from the '
                      'decoder; this audit does not independently decrypt a PCAP.',
                      'A diagnostic value is not attributed to a module or interpreted '
                      'as an address by this audit.'])
    for path in paths:
        path = Path(path).resolve()
        source = dict(path=str(path), sha256=None, lines=0, packet_records=0,
                      checked_packet_records=0, packet_types={}, diagnostics=[],
                      issues=[], issue_count=0, stable_during_read=None)
        report['sources'].append(source)
        counts = Counter()
        digest = hashlib.sha256()

        def issue(line, code, detail):
            source['issue_count'] += 1
            if len(source['issues']) < 100:
                source['issues'].append(dict(line=line, code=code, detail=detail))

        try:
            before = path.stat()
            with path.open('rb') as stream:
                for number, line in enumerate(stream, 1):
                    digest.update(line)
                    source['lines'] = number
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict):
                            raise ValueError('JSONL record must be an object')
                    except (ValueError, UnicodeError) as error:
                        issue(number, 'invalid_json_record', str(error))
                        continue
                    source['packet_records'] += 1
                    direction = record.get('direction')
                    if direction not in ('client', 'server'):
                        issue(number, 'invalid_direction', 'Expected client or server')
                        continue
                    try:
                        raw = bytes.fromhex(record.get('raw_hex', ''))
                    except (TypeError, ValueError) as error:
                        issue(number, 'invalid_packet_hex', str(error))
                        continue
                    if len(raw) < 3 or int.from_bytes(raw[:2], 'little') != len(raw):
                        issue(number, 'invalid_packet_length',
                              'Full record length must equal the u16 prefix and be at least 3')
                        continue
                    packet_hash = hashlib.sha256(raw).hexdigest()
                    if record.get('sha256') and record['sha256'] != packet_hash:
                        issue(number, 'packet_digest_mismatch',
                              'Decoded bytes differ from the recorded SHA-256')
                        continue
                    source['checked_packet_records'] += 1
                    counts[f'{direction}:{raw[2]:02X}'] += 1
                    if direction != 'client':
                        continue
                    try:
                        fields = parse_client_diagnostic(raw)
                    except (ValueError, UnicodeError) as error:
                        issue(number, 'invalid_client_diagnostic', str(error))
                        continue
                    if fields is not None:
                        source['diagnostics'].append(dict(
                            line=number, frame=record.get('frame'), time=record.get('time'),
                            session_id=record.get('session_id'), packet_sha256=packet_hash,
                            recorded_ciphertext_reproduced=record.get('ciphertext_reproduced') is True,
                            fields=fields))
            after = path.stat()
            source['sha256'] = digest.hexdigest()
            source['stable_during_read'] = (before.st_size == after.st_size and
                                             before.st_mtime_ns == after.st_mtime_ns)
            if not source['stable_during_read']:
                issue(None, 'source_changed_during_read',
                      'File size or modification time changed while reading')
        except OSError as error:
            issue(None, 'source_io_error', str(error))
        source['packet_types'] = dict(sorted(counts.items()))
        source['issues_truncated'] = source['issue_count'] > len(source['issues'])
    report['totals'] = dict(sources=len(report['sources']),
                          packet_records=sum(s['packet_records'] for s in report['sources']),
                          checked_packet_records=sum(s['checked_packet_records'] for s in report['sources']),
                          diagnostics=sum(len(s['diagnostics']) for s in report['sources']),
                          issues=sum(s['issue_count'] for s in report['sources']))
    return report


def write_audit(paths, output):
    """Write to a separate destination so a source cannot overwrite itself."""
    paths = [Path(p).resolve() for p in paths]
    output = Path(output).resolve()
    if output in paths or (output.exists() and any(output.samefile(p) for p in paths if p.exists())):
        raise ValueError('Audit output must be different from every input file')
    report = audit_files(paths)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = write_audit(args.captures, args.output)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(report['totals']))
    return 1 if report['totals']['issues'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
