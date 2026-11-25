"""Authenticated local ingress for plaintext copies from an owned L2 server.

The callback commits a complete validated batch, returning False to reject it.
Callbacks are serialized. Sequence state advances only after callback acceptance.
This is capture ingress, never a command or arbitrary network proxy.
"""
from __future__ import annotations

import hmac
import json
import math
import secrets
import sys
import threading
import time
import zipfile
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
MAX_BODY = 1024 * 1024
MAX_BATCH = 128
MAX_SESSIONS = 256
PROTOCOLS = frozenset(('classic-h5', 'asterios-448', 'raw'))


class BridgeError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _validate(payload):
    if not isinstance(payload, dict) or type(payload.get('schema')) is not int or payload['schema'] != 1:
        raise BridgeError(400, 'Unsupported schema')
    session = payload.get('session_id')
    if (not isinstance(session, str) or not 1 <= len(session) <= 128
            or any(not (c.isascii() and (c.isalnum() or c in '._:-')) for c in session)):
        raise BridgeError(400, 'Invalid session_id')
    protocol = payload.get('protocol')
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise BridgeError(400, 'Unsupported protocol')
    packets = payload.get('packets')
    if not isinstance(packets, list) or not 1 <= len(packets) <= MAX_BATCH:
        raise BridgeError(400, 'Invalid packet count')
    normalized = []
    previous = 0
    for packet in packets:
        if not isinstance(packet, dict):
            raise BridgeError(400, 'Invalid packet')
        sequence = packet.get('sequence')
        if type(sequence) is not int or not 1 <= sequence <= (1 << 53) - 1 or sequence <= previous:
            raise BridgeError(400, 'Invalid sequence order')
        previous = sequence
        direction = packet.get('direction')
        if direction not in ('client', 'server'):
            raise BridgeError(400, 'Invalid direction')
        value = packet.get('hex')
        if (not isinstance(value, str) or not 6 <= len(value) <= 65536 or len(value) % 2
                or any(c not in '0123456789abcdefABCDEF' for c in value)):
            raise BridgeError(400, 'Invalid packet hex')
        raw = bytes.fromhex(value)
        if not 3 <= len(raw) <= 32768 or int.from_bytes(raw[:2], 'little') != len(raw):
            raise BridgeError(400, 'Packet must contain its exact u16 length')
        timestamp = packet.get('timestamp', time.time())
        if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
                or not 0 <= timestamp <= 253402300799):
            raise BridgeError(400, 'Invalid timestamp')
        normalized.append(dict(sequence=sequence, direction=direction, hex=raw.hex(), timestamp=float(timestamp)))
    return dict(schema=1, session_id=session, protocol=protocol, packets=normalized)


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, bridge):
        self.bridge = bridge
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', 0), _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _Handler(BaseHTTPRequestHandler):
    server_version = 'L2Bridge/1'

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_):
        pass

    def _reply(self, status, result):
        raw = json.dumps(result, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_POST(self):
        bridge = self.server.bridge
        try:
            expected_hosts = {'127.0.0.1:%d' % self.server.server_port, 'localhost:%d' % self.server.server_port}
            if self.headers.get('Host', '') not in expected_hosts:
                raise BridgeError(403, 'Local Host required')
            origin = self.headers.get('Origin')
            if origin:
                parsed = urlsplit(origin)
                if parsed.scheme != 'http' or parsed.netloc not in expected_hosts or parsed.path not in ('', '/'):
                    raise BridgeError(403, 'Origin rejected')
            token = self.headers.get('X-L2-Bridge-Token', '')
            if not hmac.compare_digest(token.encode('utf-8'), bridge._token.encode('ascii')):
                raise BridgeError(401, 'Authentication required')
            if self.path != '/v1/packets':
                raise BridgeError(404, 'Unknown endpoint')
            if self.headers.get('Transfer-Encoding'):
                raise BridgeError(400, 'Transfer-Encoding unsupported')
            try:
                size = int(self.headers.get('Content-Length', ''))
            except ValueError:
                raise BridgeError(411, 'Content-Length required')
            if not 1 <= size <= MAX_BODY:
                raise BridgeError(413, 'Body too large')
            if self.headers.get_content_type() != 'application/json':
                raise BridgeError(415, 'JSON required')
            chunks, remaining, deadline = [], size, time.monotonic() + 3
            while remaining:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    raise BridgeError(408, 'Body read timed out')
                self.connection.settimeout(timeout)
                chunk = self.rfile.read1(min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            if len(raw) != size:
                raise BridgeError(400, 'Incomplete body')
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                raise BridgeError(400, 'Invalid JSON')
            result = bridge._receive(_validate(payload))
            self._reply(200, result)
        except BridgeError as exc:
            bridge._rejected()
            self._reply(exc.status, dict(ok=False, error=str(exc)))
        except (TimeoutError, ConnectionError, OSError):
            bridge._rejected()

    def do_GET(self):
        self._reply(405, dict(ok=False, error='POST required'))


class ServerBridge:
    def __init__(self, on_batch):
        self._on_batch = on_batch
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._server = None
        self._thread = None
        self._token = ''
        self._sessions = OrderedDict()
        self._accepted_batches = self._accepted_packets = self._rejected_batches = self._gaps = 0
        self._last_packet_time = None

    def start(self):
        with self._lifecycle:
            if self._server is None:
                self._token = secrets.token_urlsafe(32)
                self._server = _HTTPServer(self)
                self._thread = threading.Thread(target=self._server.serve_forever, kwargs={'poll_interval': .1},
                                                name='l2-server-bridge', daemon=True)
                self._thread.start()
            return self.configuration()

    def configuration(self):
        with self._lock:
            return dict(schema=1, endpoint=('http://127.0.0.1:%d/v1/packets' % self._server.server_port
                                          if self._server else None), token=self._token,
                        token_header='X-L2-Bridge-Token', max_batch=MAX_BATCH, max_body=MAX_BODY)

    def snapshot(self):
        with self._lock:
            config = self.configuration()
            config.pop('token')
            return dict(config, running=self._server is not None, sessions=len(self._sessions),
                        accepted_batches=self._accepted_batches, accepted_packets=self._accepted_packets,
                        rejected_batches=self._rejected_batches, gaps=self._gaps,
                        received=self._accepted_packets, dropped=self._rejected_batches,
                        last_packet_time=self._last_packet_time)

    def _rejected(self):
        with self._lock:
            self._rejected_batches += 1

    def _receive(self, batch):
        with self._lock:
            session = batch['session_id']
            previous, protocol = self._sessions.get(session, (0, batch['protocol']))
            if protocol != batch['protocol']:
                raise BridgeError(409, 'Protocol changed inside session; begin a new session')
            packets = batch['packets']
            if session not in self._sessions and len(self._sessions) >= MAX_SESSIONS:
                raise BridgeError(429, 'Session limit reached; restart bridge capture')
            if packets[0]['sequence'] <= previous:
                raise BridgeError(409, 'Duplicate or overlapping sequence')
            expected = previous + 1
            gap = False
            for packet in packets:
                gap |= packet['sequence'] != expected
                expected = packet['sequence'] + 1
            batch = dict(batch, gap=gap, expected_sequence=previous + 1,
                         first_sequence=packets[0]['sequence'], last_sequence=packets[-1]['sequence'])
            try:
                accepted = self._on_batch(batch)
            except Exception:
                raise BridgeError(503, 'Capture consumer unavailable') from None
            if accepted is not None and accepted is not True:
                raise BridgeError(409, 'Capture consumer rejected session')
            self._sessions[session] = (batch['last_sequence'], protocol)
            self._sessions.move_to_end(session)
            self._accepted_batches += 1
            self._accepted_packets += len(packets)
            self._gaps += int(gap)
            self._last_packet_time = time.time()
            return dict(ok=True, accepted=len(packets), last_sequence=batch['last_sequence'], gap=gap)

    def export_package(self, path):
        if self._server is None:
            self.start()
        sdk = ROOT / 'src' / 'server_bridge_sdk'
        if not sdk.is_dir():
            raise FileNotFoundError('Bundled server bridge SDK is missing')
        target = Path(path)
        with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('bridge.json', json.dumps(self.configuration(), ensure_ascii=False, indent=2) + '\n')
            for source in sorted(sdk.rglob('*')):
                if source.is_file() and source.suffix in ('.py', '.java', '.md'):
                    archive.write(source, source.relative_to(sdk).as_posix())
        return str(target.resolve())

    def close(self):
        with self._lifecycle:
            server, thread = self._server, self._thread
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=4)
                with self._lock:
                    self._server = self._thread = None
                    self._token = ''
                    self._sessions.clear()
