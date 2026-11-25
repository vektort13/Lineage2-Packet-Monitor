"""Launch the native Windows Qt Widgets packet monitor."""
import argparse
import sys
import threading
from pathlib import Path

from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from l2_monitor.engine import Monitor
from l2_monitor.native_ui import MonitorWindow, run_ui_self_test


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--interface', default='auto')
    parser.add_argument('--cipher', choices=['auto', 'asterios', 'l2xor16', 'l2xor16-u64', 'plain'], default='auto')
    parser.add_argument('--source', choices=['auto','network','client','server'], default=None)
    parser.add_argument('--interval', type=float, default=4)
    parser.add_argument('--no-autostart', action='store_true')
    parser.add_argument('--api', action='store_true', help='Enable the optional loopback JSON API')
    parser.add_argument('--no-api', action='store_true')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--self-test-output', type=Path)
    parser.add_argument('--audit-diagnostics', type=Path, nargs='+',
                        help='Audit saved packet JSONL files without starting capture')
    parser.add_argument('--audit-output', type=Path,
                        help='JSON report destination for --audit-diagnostics')
    args = parser.parse_args(argv)
    if args.audit_diagnostics:
        if not args.audit_output or args.self_test:
            parser.error('--audit-diagnostics requires --audit-output and cannot be used with --self-test')
        from l2_monitor.diagnostic_audit import write_audit
        try:
            report = write_audit(args.audit_diagnostics, args.audit_output)
        except (ValueError, OSError) as error:
            parser.error(str(error))
        return 1 if report['totals']['issues'] else 0
    if args.audit_output:
        parser.error('--audit-output requires --audit-diagnostics')
    if not 2 <= args.interval <= 30 or not 1 <= args.port <= 65535:
        parser.error('interval: 2..30 seconds; port: 1..65535')
    if args.pid is not None and args.pid <= 0:
        parser.error('pid must be positive')
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName('L2 Packet Monitor')
    app.setOrganizationName('AsteriosTools')
    app.setStyle('Fusion')
    app.setFont(QFont('Segoe UI', 10))
    if getattr(sys, 'frozen', False):
        icon_path = Path(sys._MEIPASS) / 'assets' / 'L2PacketMonitor.ico'
    else:
        icon_path = Path(__file__).resolve().parents[1] / 'packaging' / 'L2PacketMonitor.ico'
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    monitor = Monitor(interval=args.interval)
    server = None
    if args.api and not args.no_api and not args.self_test:
        try:
            from l2_monitor.http_api import ApiServer
            server = ApiServer(('127.0.0.1', args.port), monitor)
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.3}, daemon=True).start()
        except Exception as error:
            QMessageBox.warning(None, 'JSON API', str(error))
    window = MonitorWindow(monitor, pid=args.pid, interface=args.interface, cipher=args.cipher,
                           autostart=not args.no_autostart, self_test=args.self_test, source=args.source)
    window.setWindowIcon(app.windowIcon())
    window.show()
    exit_code = [0]
    if args.self_test:
        def done(code):
            exit_code[0] = code
            window.close()
        run_ui_self_test(window, args.self_test_output, done)
    app.exec()
    monitor.bridge_stop()
    if server:
        server.shutdown()
        server.server_close()
    return exit_code[0]


if __name__ == '__main__':
    raise SystemExit(main())
