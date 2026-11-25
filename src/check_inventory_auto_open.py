"""Verify automatic inventory opening against the selected running test client."""
import argparse
import json
import time
from pathlib import Path

from l2_monitor.engine import Monitor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--timeout', type=int, default=75)
    args = parser.parse_args()
    monitor = Monitor(interval=2)
    monitor.start(pid=args.pid)
    deadline = time.monotonic() + args.timeout
    report = {}
    try:
        while time.monotonic() < deadline:
            status = monitor.status()
            inventory = monitor.inventory.snapshot()
            auto = status.get('inventory_auto_open') or {}
            if inventory.get('full_list_received') or auto.get('state') == 'failed':
                break
            time.sleep(0.5)
        packets = monitor.store.export()
        report = dict(
            passed=bool(inventory.get('full_list_received')),
            pid=args.pid, state=status['state'],
            auto_open=auto, item_count=len(inventory['items']),
            client_item_list_requests=sum(p['direction'] == 'client' and p['opcode'] == '14' for p in packets),
            server_item_lists=sum(p['direction'] == 'server' and p['opcode'] == '11' for p in packets),
            validated_windows=status['validated_windows'], sync_errors=status['sync_errors'],
            last_error=status.get('last_error'), log_directory=status.get('log_directory'))
    finally:
        monitor.stop()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
