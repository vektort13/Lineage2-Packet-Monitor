"""Run the local passive packet monitor and its HTTP API."""
import argparse
import json
import signal
import threading
import webbrowser

from l2_monitor.engine import Monitor
from l2_monitor.http_api import ApiServer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--interval', type=float, default=4)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--interface', default='auto')
    parser.add_argument('--cipher', choices=['auto', 'asterios', 'l2xor16', 'l2xor16-u64', 'plain'], default='auto')
    parser.add_argument('--no-autostart', action='store_true')
    parser.add_argument('--open', action='store_true', help='Open the local dashboard')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 2 <= args.interval <= 30:
        parser.error('port: 1..65535; interval: 2..30 seconds')
    monitor = Monitor(args.interval)
    server = ApiServer(('127.0.0.1', args.port), monitor)

    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    url = f'http://127.0.0.1:{args.port}'
    print(json.dumps(dict(url=url, api=url + '/api/docs', version='1.0')), flush=True)
    if not args.no_autostart:
        monitor.start(args.pid, args.interface, args.cipher)
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        monitor.stop()
        server.server_close()


if __name__ == '__main__':
    main()
