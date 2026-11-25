"""Bounded passive capture plus ordinary read-only cipher state observations."""
import argparse
import hashlib
import json
import struct
import subprocess
import time
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess


def snapshot(process):
    for _ in range(100):
        before = time.time_ns()
        root = struct.unpack('<I', process.read(0x208c5360, 4))[0]
        socket = struct.unpack('<I', process.read(root + 0x48, 4))[0]
        if struct.unpack('<I', process.read(socket, 4))[0] != 0x205d326c:
            raise ValueError('Observed socket layout changed')

        def read():
            return (process.read(0x053b5244, 8), process.read(socket + 0x927c, 34),
                    process.read(0x053b4fb0, 4))

        first = read()
        time.sleep(0.002)
        second = read()
        after = time.time_ns()
        if first == second:
            counters, keys, header = first
            server_count, client_count = struct.unpack('<II', counters)
            return dict(read_start_ns=before, read_end_ns=after, socket=hex(socket),
                        server_counter=server_count, client_counter=client_count,
                        outgoing_key=keys[1:17].hex(), incoming_key=keys[18:34].hex(),
                        client_header_state=struct.unpack('<I', header)[0],
                        consistency='two equal observations; no thread suspension')
    raise ValueError('Could not obtain two matching read-only observations')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--interface', default='6')
    parser.add_argument('--seconds', type=int, default=45)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 120:
        raise ValueError('Capture duration must be 10..120 seconds')
    args.output_dir.mkdir(parents=True, exist_ok=False)
    path = args.output_dir / 'online.pcapng'
    command = ['C:/Program Files/Wireshark/dumpcap.exe', '-i', args.interface,
               '-f', '(host 146.59.110.40 and tcp port 2110) or (pppoes and host 146.59.110.40 and tcp port 2110)',
               '-a', f'duration:{args.seconds + 6}', '-a', 'filesize:8192', '-w', str(path)]
    process = ReadOnlyProcess(args.pid)
    capture = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    report = dict(pid=args.pid, command=command, mode='passive current-session capture; ordinary query/read only',
                  snapshots=[])
    try:
        time.sleep(3)
        if capture.poll() is not None:
            raise ValueError('Capture stopped before initial observation')
        report['snapshots'].append(snapshot(process))
        for elapsed in range(args.seconds):
            time.sleep(1)
            if (elapsed + 1) % 5 == 0 or elapsed + 1 == args.seconds:
                state = snapshot(process)
                report['snapshots'].append(state)
                print(json.dumps(dict(elapsed=elapsed + 1, server_counter=state['server_counter'],
                                      client_counter=state['client_counter'])), flush=True)
        stdout, stderr = capture.communicate(timeout=15)
        report.update(capture_exit_code=capture.returncode,
                      capture_diagnostics=stderr.decode('utf-8', errors='replace'),
                      capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    finally:
        process.close()
        if capture.poll() is None:
            capture.terminate()
            capture.communicate(timeout=10)
        (args.output_dir / 'private-state.json').write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    if capture.returncode:
        raise ValueError(f'Capture failed: {capture.returncode}')
    print(json.dumps(dict(output_dir=str(args.output_dir), snapshots=len(report['snapshots']),
                          capture_sha256=report['capture_sha256'])), flush=True)


if __name__ == '__main__':
    main()
