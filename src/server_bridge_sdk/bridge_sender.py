"""Python 3 stdlib producer. Import into the server, not into the game client."""
import http.client
import json
import queue
import threading
import time
import uuid
from urllib.parse import urlsplit


class Connection:
    def __init__(self, sender, protocol):
        if protocol not in ('classic-h5', 'asterios-448', 'raw'):
            raise ValueError('Unknown protocol')
        self.sender, self.protocol = sender, protocol
        self.session_id, self.sequence = str(uuid.uuid4()), 0
        self.lock = threading.Lock()

    def capture(self, full_packet, direction):
        """Copy full plaintext u16-length + opcode + payload; never wait for HTTP."""
        raw = bytes(full_packet)
        if direction not in ('client', 'server') or not 3 <= len(raw) <= 32768:
            raise ValueError('Invalid packet')
        if int.from_bytes(raw[:2], 'little') != len(raw):
            raise ValueError('Expected complete u16-framed packet')
        with self.lock:
            self.sequence += 1  # Increment even on loss so the next delivery exposes a gap.
            record = dict(sequence=self.sequence, direction=direction, hex=raw.hex(), timestamp=time.time())
            if self.sender.closed.is_set():
                self.sender._count('dropped', 1)
                return False
            try:
                self.sender.pending.put_nowait((self, record))
                return True
            except queue.Full:
                self.sender._count('dropped', 1)
                return False


class BridgeSender:
    def __init__(self, configuration, capacity=1024):
        url = urlsplit(configuration['endpoint'])
        if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost')
                or not url.port or url.path != '/v1/packets' or url.query or url.fragment or url.username):
            raise ValueError('Expected local bridge endpoint; use a loopback tunnel for a remote server')
        if capacity < 1:
            raise ValueError('Positive queue capacity required')
        self.url, self.token = url, configuration['token']
        self.pending = queue.Queue(maxsize=capacity)
        self.closed = threading.Event()
        self.stats_lock = threading.Lock()
        self.counts = dict(delivered=0, dropped=0, failed_batches=0)
        self.worker = threading.Thread(target=self._run, name='l2-bridge-sender', daemon=True)
        self.worker.start()

    @classmethod
    def from_file(cls, path='bridge.json', capacity=1024):
        with open(path, encoding='utf-8') as source:
            return cls(json.load(source), capacity)

    def begin_connection(self, protocol='raw'):
        return Connection(self, protocol)

    def _count(self, key, value):
        with self.stats_lock:
            self.counts[key] += value

    def snapshot(self):
        with self.stats_lock:
            return dict(self.counts, queued=self.pending.qsize(), running=not self.closed.is_set())

    def _run(self):
        carried = None
        while not self.closed.is_set():
            try:
                connection, packet = carried or self.pending.get(timeout=.1)
                carried = None
            except queue.Empty:
                continue
            packets = [packet]
            # Keep each connection's ordered packets together, bounded under receiver 1 MiB.
            size = len(packet['hex'])
            while len(packets) < 32 and size < 800000:
                try:
                    other, next_packet = self.pending.get_nowait()
                except queue.Empty:
                    break
                if other is not connection or size + len(next_packet['hex']) > 900000:
                    carried = (other, next_packet)
                    break
                packets.append(next_packet)
                size += len(next_packet['hex'])
            payload = dict(schema=1, session_id=connection.session_id, protocol=connection.protocol, packets=packets)
            client = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=2)
            try:
                client.request('POST', self.url.path, body=json.dumps(payload).encode('utf-8'),
                               headers={'Content-Type': 'application/json', 'X-L2-Bridge-Token': self.token})
                response = client.getresponse()
                result = json.loads(response.read(4096))
                if response.status != 200 or result.get('ok') is not True or result.get('accepted') != len(packets):
                    raise OSError('Batch was not accepted')
                self._count('delivered', len(packets))
            except (OSError, ValueError, http.client.HTTPException):
                # No automatic retry: an ambiguous timeout might already have committed.
                self._count('dropped', len(packets))
                self._count('failed_batches', 1)
            finally:
                client.close()
        self._count('dropped', self.pending.qsize() + int(carried is not None))

    def close(self):
        self.closed.set()
        self.worker.join(timeout=3)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
