"""Offline TCP inventory and conservative framing checks; no decryption or networking."""
import argparse
import csv
import hashlib
import io
import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'frame.cap_len',
          'frame.protocols', 'ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport',
          'tcp.stream', 'tcp.seq_raw', 'tcp.flags.syn', 'tcp.len', 'tcp.payload']


def contiguous_chunks(segments):
    """Reorder payload within a sequence span smaller than 2**31 bytes.

    Ignore empty payloads. Preserve holes and count conflicts; for conflicting
    overlaps retain bytes encountered first after the stable offset sort.
    """
    segments = [(seq, data) for seq, data in segments if data]
    if not segments:
        return [], {'gap_bytes': 0, 'overlap_bytes': 0, 'conflicting_bytes': 0}
    anchor = segments[0][0]
    ordered = sorted((((seq - anchor + 2**31) % 2**32 - 2**31, data)
                      for seq, data in segments), key=lambda item: item[0])
    start = ordered[0][0]
    buf = bytearray()
    chunks = []
    stats = {'gap_bytes': 0, 'overlap_bytes': 0, 'conflicting_bytes': 0}
    for offset, data in ordered:
        end = start + len(buf)
        if offset > end:
            chunks.append(bytes(buf))
            stats['gap_bytes'] += offset - end
            start, buf = offset, bytearray()
            end = offset
        overlap = min(max(end - offset, 0), len(data))
        if overlap:
            old = buf[offset - start:offset - start + overlap]
            stats['overlap_bytes'] += overlap
            stats['conflicting_bytes'] += sum(a != b for a, b in zip(old, data[:overlap]))
        buf.extend(data[overlap:])
    if buf:
        chunks.append(bytes(buf))
    return chunks, stats


def framing_candidate(data):
    """Try u16 LE total lengths >= 3 from byte zero, without guessing alignment."""
    offset = 0
    lengths = Counter()
    reason = None
    while offset + 2 <= len(data):
        size = int.from_bytes(data[offset:offset + 2], 'little')
        if size < 3:
            reason = 'length_less_than_3'
            break
        if offset + size > len(data):
            reason = 'declared_length_exceeds_available_bytes'
            break
        lengths[size] += 1
        offset += size
    if reason is None and offset < len(data):
        reason = 'partial_header'
    return {'candidate_records': sum(lengths.values()),
            'length_histogram': dict(sorted(lengths.items())),
            'consumed_bytes': offset, 'trailing_bytes': len(data) - offset,
            'stop_reason': reason, 'alignment_verified': False}


def summarize(rows, character):
    groups = defaultdict(list)
    syn_streams = set()
    for row in rows:
        if row['tcp.flags.syn'] == '1':
            syn_streams.add(row['tcp.stream'])
        if row['tcp.stream']:
            key = (row['tcp.stream'], row['ip.src'], row['tcp.srcport'],
                   row['ip.dst'], row['tcp.dstport'])
            groups[key].append(row)
    directions = []
    for key, items in sorted(groups.items()):
        segments = [(int(r['tcp.seq_raw']), bytes.fromhex(r['tcp.payload']))
                    for r in items if r['tcp.payload']]
        chunks, integrity = contiguous_chunks(segments)
        directions.append({'stream': key[0], 'source': f'{key[1]}:{key[2]}',
                           'destination': f'{key[3]}:{key[4]}',
                           'captured_frames': len(items),
                           'payload_frames': len(segments),
                           'unique_payload_bytes': sum(map(len, chunks)),
                           'syn_observed_in_stream': key[0] in syn_streams,
                           'integrity': integrity,
                           'u16le_candidates_per_contiguous_chunk': [framing_candidate(c) for c in chunks],
                           'character_literal_present': {
                               encoding: any(character.encode(encoding) in c for c in chunks)
                               for encoding in ('utf-8', 'utf-16le')}})
    times = [float(r['frame.time_epoch']) for r in rows]
    return {'captured_frames': len(rows),
            'duration_seconds': max(times) - min(times) if times else 0,
            'start_utc': datetime.fromtimestamp(min(times), timezone.utc).isoformat() if times else None,
            'end_utc': datetime.fromtimestamp(max(times), timezone.utc).isoformat() if times else None,
            'payload_frames': sum(int(r['tcp.len'] or 0) > 0 for r in rows),
            'truncated_frames': sum(int(r['frame.cap_len']) < int(r['frame.len']) for r in rows),
            'protocol_stacks': dict(Counter(r['frame.protocols'] for r in rows)),
            'directions': directions,
            'decryption_performed': False,
            'limitations': [
                'TCP framing candidates do not identify opcodes or prove protocol identity.',
                'A missing SYN means the recording does not establish connection-start coverage.',
                'Every chunk starts at its first captured byte; alignment is not inferred or repaired.',
                'Conflicting overlap bytes make reconstructed content ambiguous.',
                'Absence of a character literal does not prove encryption.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    parser.add_argument('--character', default='X501')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    command = [args.tshark, '-n', '-r', str(args.capture), '-T', 'fields',
               '-E', 'header=y', '-E', 'separator=/t']
    for field in FIELDS:
        command.extend(['-e', field])
    result = subprocess.run(command, capture_output=True, check=True, timeout=60)
    rows = list(csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), delimiter='\t'))
    report = summarize(rows, args.character)
    report['capture_path'] = str(args.capture.resolve())
    with args.capture.open('rb') as capture_file:
        report['capture_sha256'] = hashlib.file_digest(capture_file, 'sha256').hexdigest()
    report['tshark_command'] = command
    report['tshark_diagnostics'] = result.stderr.decode('utf-8', errors='replace').strip()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"Saved {args.output}; frames={len(rows)}; decryption_performed=false")


if __name__ == '__main__':
    main()
