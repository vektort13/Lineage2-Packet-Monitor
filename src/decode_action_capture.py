"""Verify an action capture using retained keys, counters and inflater history."""
import argparse
import collections
import csv
import hashlib
import io
import json
import subprocess
from pathlib import Path

from decode_prime_client_native import NativeCipherOracle
from l2_monitor.discovery import WIRESHARK
from l2_monitor.engine import FIELDS
from l2_monitor.live_state import ROOT, load_profile
from l2_monitor.protocol import Catalog, decode_window
from analyze_prime_timeline import transport
from reference_xor import split_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    source = args.directory / 'private-state.json'
    state = json.loads(source.read_text('utf-8'))
    capture = args.directory / state.get('capture_filename', 'exchange.pcapng')
    capture_hash = hashlib.sha256(capture.read_bytes()).hexdigest()
    if capture_hash != state['capture_sha256']:
        raise ValueError('Capture hash mismatch')
    command = [WIRESHARK + 'tshark.exe', '-n', '-r', str(capture),
               '-T', 'fields', '-E', 'header=y', '-E', 'occurrence=f']
    for field in FIELDS:
        command.extend(['-e', field])
    result = subprocess.run(command, capture_output=True, timeout=60, check=True)
    rows = list(csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), delimiter='\t'))
    endpoint = state['endpoint']
    rows = [r for r in rows if {r['tcp.srcport'], r['tcp.dstport']}
            == {str(endpoint['local_port']), str(endpoint['remote_port'])}]
    for row in rows:
        row['tcp.stream'] = '0'
    snapshots = state['snapshots']
    for snapshot in snapshots:
        snapshot['dictionary'] = bytes.fromhex(snapshot['dictionary_hex'])
    profile = load_profile()
    oracle = NativeCipherOracle([ROOT / p for p in profile['snapshot_dirs']],
                                ROOT / profile['runtime_path'])
    catalog, cursors, packets, windows, errors = Catalog(), None, [], [], []
    # Captured timestamps and process wall time can differ. Test nearby complete
    # record boundaries, accepting one only through the full native end states.
    server_rows = [r for r in rows if r['tcp.payload'] and r['ip.src'] == endpoint['remote_ip']]
    client_rows = [r for r in rows if r['tcp.payload'] and r['ip.dst'] == endpoint['remote_ip']]
    wire, ready, _ = transport(rows, 0, endpoint['remote_ip'], True)
    base = int(server_rows[0]['tcp.seq_raw'])
    timestamps = {int(r['frame.number']): float(r['frame.time_epoch']) for r in rows}
    starts, offset = [], 0
    for record in split_records(wire):
        if abs(timestamps[ready[offset]] - snapshots[0]['read_start_ns'] / 1e9) < 4:
            starts.append((base + offset) & 0xffffffff)
        offset += len(record)
    client_start = int(client_rows[0]['tcp.seq_raw']) if client_rows else None
    try:
        for start in starts:
            try:
                candidate = dict(server=start, client=client_start)
                decode_window(rows, snapshots[0], snapshots[1], oracle,
                    endpoint['remote_ip'], catalog, args.directory.name, cursors=candidate)
                cursors = candidate
                break
            except ValueError:
                pass
        for number, (before, after) in enumerate(zip(snapshots, snapshots[1:])):
            try:
                decoded, verification = decode_window(rows, before, after, oracle,
                    endpoint['remote_ip'], catalog, args.directory.name, cursors=cursors)
                cursors = verification['wire_cursors']
                packets.extend(decoded)
                windows.append(dict(start_anchor=number, end_anchor=number + 1, **verification))
            except ValueError as error:
                errors.append(dict(start_anchor=number, error=str(error)))
                cursors = None
    finally:
        oracle.close()
    output = args.directory / 'decoded'
    output.mkdir(exist_ok=True)
    (output / 'packets.jsonl').write_text(''.join(json.dumps(p, ensure_ascii=False) + '\n'
                                               for p in packets), 'utf-8')
    for direction in ('client', 'server'):
        (output / (direction + '-packets.bin')).write_bytes(b''.join(bytes.fromhex(p['raw_hex'])
                                      for p in packets if p['direction'] == direction))
    report = dict(capture_sha256=capture_hash, state_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  capture_rows=len(rows), verified_windows=windows, failed_windows=errors,
                  packet_counts=dict(collections.Counter(p['direction'] for p in packets)),
                  types=dict(collections.Counter(p['direction'] + ':' + p['opcode'] + ':' + p['name']
                                                 for p in packets)))
    (output / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'verified_windows'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
