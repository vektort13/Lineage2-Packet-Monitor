"""Record a user-performed shop action and retain real cipher/inflate states."""
import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from l2_monitor.discovery import NO_WINDOW, WIRESHARK, select_interface, select_process
from l2_monitor.live_state import LiveState


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--label', default='User-performed Gold to Silver and back through game shop')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    process, endpoint = select_process()
    interface = select_interface()
    live = LiveState(process['pid'], process['exe'])
    host, port = endpoint['remote_ip'], endpoint['remote_port']
    capture_file = args.output_dir / 'capture.pcapng'
    command = [WIRESHARK + 'dumpcap.exe', '-i', interface['device'], '-f',
        f'(host {host} and tcp port {port}) or (pppoes and host {host} and tcp port {port})',
        '-a', f'duration:{args.seconds + 6}', '-a', 'filesize:16384', '-w', str(capture_file)]
    log = (args.output_dir / 'capture.log').open('wb')
    capture = subprocess.Popen(command, stdout=log, stderr=log, creationflags=NO_WINDOW)
    report = dict(label=args.label, capture_filename=capture_file.name,
                  process=process, endpoint=endpoint, interface=interface, command=command,
                  snapshots=[], errors=[], state='starting')

    def save():
        temporary = args.output_dir / 'private-state.tmp'
        temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', 'utf-8')
        os.replace(temporary, args.output_dir / 'private-state.json')

    def observe():
        state = live.snapshot()
        state['dictionary_hex'] = state.pop('dictionary').hex()
        report['snapshots'].append(state)
        save()

    try:
        time.sleep(3)
        if capture.poll() is not None:
            raise ValueError('Capture did not start')
        observe()
        report.update(state='recording', ready_utc=datetime.now(timezone.utc).isoformat())
        save()
        print(json.dumps(dict(ready=True, output_dir=str(args.output_dir), pid=process['pid'],
                              capture_pid=capture.pid, ready_utc=report['ready_utc'])), flush=True)
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and capture.poll() is None:
            if (args.output_dir / 'stop.request').exists():
                break
            time.sleep(1)
            if time.monotonic() % 5 < 1:
                try:
                    observe()
                except Exception as error:
                    report['errors'].append(str(error))
        observe()
        report.update(state='complete', end_utc=datetime.now(timezone.utc).isoformat())
        # Retain the wire suffix after the final process-state anchor; Npcap's
        # timestamp clock and buffer delivery can lag process wall time.
        time.sleep(4)
    finally:
        live.close()
        if capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=5)
        log.close()
        report['capture_sha256'] = hashlib.sha256(capture_file.read_bytes()).hexdigest() if capture_file.exists() else None
        save()
    print(json.dumps(dict(complete=True, snapshots=len(report['snapshots']),
                          capture_sha256=report['capture_sha256'])), flush=True)


if __name__ == '__main__':
    main()
