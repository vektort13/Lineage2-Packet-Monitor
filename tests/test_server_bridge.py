import copy
import http.client
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.server_bridge import MAX_BODY, MAX_SESSIONS, ServerBridge

ROOT = Path(__file__).resolve().parents[1]


def payload(sequence=1, session='session-1', protocol='classic-h5'):
    return dict(schema=1, session_id=session, protocol=protocol,
                packets=[dict(sequence=sequence, direction='client', hex='030050', timestamp=123.5)])


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.received = []
        self.bridge = ServerBridge(self.received.append)
        self.config = self.bridge.start()

    def tearDown(self):
        self.bridge.close()

    def post(self, data, headers=None, token=True, raw=None):
        url = urlsplit(self.config['endpoint'])
        client = http.client.HTTPConnection(url.hostname, url.port, timeout=4)
        actual = {'Content-Type': 'application/json'}
        if token:
            actual['X-L2-Bridge-Token'] = self.config['token']
        actual.update(headers or {})
        try:
            client.request('POST', url.path, body=raw if raw is not None else json.dumps(data).encode(), headers=actual)
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

    def test_real_http_normalizes_and_commits_without_exposing_token(self):
        body = payload()
        body['packets'][0]['hex'] = '0300AA'
        status, response = self.post(body)
        self.assertEqual((200, True, 1, False), (status, response['ok'], response['accepted'], response['gap']))
        self.assertEqual('0300aa', self.received[0]['packets'][0]['hex'])
        self.assertEqual((1, 1), (self.received[0]['first_sequence'], self.received[0]['last_sequence']))
        snapshot = self.bridge.snapshot()
        self.assertEqual(1, snapshot['received'])
        self.assertNotIn('token', snapshot)
        self.assertNotIn(self.config['token'], json.dumps(snapshot))
        self.assertEqual(self.config, self.bridge.start())

    def test_auth_host_origin_and_content_type(self):
        cases = [(dict(token=False), 401),
                 (dict(headers={'X-L2-Bridge-Token': 'wrong'}), 401),
                 (dict(headers={'Host': 'evil.invalid'}), 403),
                 (dict(headers={'Origin': 'http://evil.invalid'}), 403),
                 (dict(headers={'Content-Type': 'text/plain'}), 415)]
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(expected, self.post(payload(), **arguments)[0])
        self.assertFalse(self.received)
        local_origin = self.config['endpoint'].rsplit('/', 2)[0]
        self.assertEqual(200, self.post(payload(), headers={'Origin': local_origin})[0])

    def test_full_validation_precedes_callback(self):
        valid = payload()
        invalid = copy.deepcopy(valid['packets'][0])
        invalid.update(sequence=2, hex='040050')
        valid['packets'].append(invalid)
        self.assertEqual(400, self.post(valid)[0])
        self.assertFalse(self.received)
        self.assertEqual(200, self.post(payload())[0])

    def test_strict_fields_and_bounds(self):
        cases = []
        for key, value in [('schema', True), ('session_id', 'a b'), ('session_id', 'a' * 129),
                           ('protocol', []), ('protocol', 'unknown'), ('packets', [])]:
            body = payload(); body[key] = value; cases.append(body)
        for key, value in [('sequence', True), ('sequence', 0), ('sequence', 1 << 53),
                           ('direction', 'C>S'), ('hex', '03 0050'), ('hex', '0200'),
                           ('hex', '040050'), ('hex', '0300GG'), ('timestamp', float('nan')),
                           ('timestamp', True), ('timestamp', -1), ('timestamp', 253402300800)]:
            body = payload(); body['packets'][0][key] = value; cases.append(body)
        body = payload(); body['packets'] *= 129; cases.append(body)
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(400, self.post(body)[0])
        self.assertFalse(self.received)

    def test_malformed_json_and_oversize_are_rejected(self):
        self.assertEqual(400, self.post(None, raw=b'{')[0])
        self.assertEqual(413, self.post(None, raw=b' ' * (MAX_BODY + 1))[0])
        self.assertFalse(self.received)

    def test_duplicate_overlap_backward_and_internal_order(self):
        self.assertEqual(200, self.post(payload())[0])
        self.assertEqual(409, self.post(payload())[0])
        body = payload(); body['packets'].append(dict(body['packets'][0], sequence=2))
        self.assertEqual(409, self.post(body)[0])
        body = payload(2); body['packets'].append(dict(body['packets'][0], sequence=1))
        self.assertEqual(400, self.post(body)[0])
        self.assertEqual(1, len(self.received))

    def test_gap_first_internal_and_contiguous(self):
        status, response = self.post(payload(3))
        self.assertEqual((200, True), (status, response['gap']))
        self.assertEqual(1, self.received[-1]['expected_sequence'])
        body = payload(4)
        body['packets'].append(dict(body['packets'][0], sequence=6, direction='server'))
        self.assertTrue(self.post(body)[1]['gap'])
        self.assertFalse(self.post(payload(7))[1]['gap'])
        self.assertEqual(2, self.bridge.snapshot()['gaps'])

    def test_session_protocol_independence_and_restart(self):
        self.assertEqual(200, self.post(payload())[0])
        self.assertEqual(409, self.post(payload(2, protocol='raw'))[0])
        self.assertEqual(200, self.post(payload(session='other', protocol='raw'))[0])
        old_token = self.config['token']
        self.bridge.close()
        self.assertFalse(self.bridge.snapshot()['running'])
        self.assertEqual('', self.bridge.configuration()['token'])
        self.config = self.bridge.start()
        self.assertNotEqual(old_token, self.config['token'])
        self.assertEqual(200, self.post(payload())[0])

    def test_callback_rejection_and_exception_do_not_advance(self):
        self.bridge._on_batch = lambda _: False
        self.assertEqual(409, self.post(payload())[0])
        def failure(_):
            raise RuntimeError('PRIVATE CALLBACK DETAILS')
        self.bridge._on_batch = failure
        status, response = self.post(payload())
        self.assertEqual(503, status)
        self.assertNotIn('PRIVATE', str(response))
        self.bridge._on_batch = self.received.append
        self.assertEqual(200, self.post(payload())[0])

    def test_callbacks_are_serialized_across_http_threads(self):
        active = []
        maximum = [0]
        def callback(batch):
            active.append(batch['session_id'])
            maximum[0] = max(maximum[0], len(active))
            time.sleep(.03)
            active.pop()
        self.bridge._on_batch = callback
        results = []
        threads = [threading.Thread(target=lambda n=n: results.append(self.post(payload(session='s%d' % n))[0]))
                   for n in range(4)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        self.assertEqual([200] * 4, sorted(results))
        self.assertEqual(1, maximum[0])

    def test_session_limit_never_forgets_duplicate_history(self):
        # Direct validated receive avoids hundreds of TCP handshakes for capacity check.
        from l2_monitor.server_bridge import BridgeError, _validate
        for index in range(MAX_SESSIONS):
            self.bridge._receive(_validate(payload(session='s%d' % index)))
        with self.assertRaises(BridgeError) as failure:
            self.bridge._receive(_validate(payload(session='overflow')))
        self.assertEqual(429, failure.exception.status)
        self.assertEqual(409, self.post(payload(session='s0'))[0])

    def test_export_contains_config_and_both_source_sdks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'sdk.zip'
            self.bridge.export_package(target)
            with zipfile.ZipFile(target) as archive:
                self.assertEqual({'bridge.json', 'README.md', 'bridge_sender.py', 'L2PlaintextBridge.java'}, set(archive.namelist()))
                config = json.loads(archive.read('bridge.json'))
                self.assertEqual(self.config['token'], config['token'])
                self.assertEqual(self.config['endpoint'], config['endpoint'])

    def test_python_sdk_real_sender_and_new_connection(self):
        spec = importlib.util.spec_from_file_location('bridge_sender_test', ROOT / 'src/server_bridge_sdk/bridge_sender.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        sender = module.BridgeSender(self.config, capacity=8)
        try:
            first = sender.begin_connection('classic-h5')
            second = sender.begin_connection('raw')
            self.assertTrue(first.capture(b'\x03\x00\x50', 'client'))
            self.assertTrue(first.capture(b'\x03\x00\x14', 'server'))
            self.assertTrue(second.capture(b'\x03\x00\x01', 'server'))
            deadline = time.monotonic() + 4
            while sender.snapshot()['delivered'] < 3 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(3, sender.snapshot()['delivered'])
            self.assertEqual(0, sender.snapshot()['dropped'])
            self.assertEqual(2, self.bridge.snapshot()['sessions'])
            first_packets = [p for b in self.received if b['session_id'] == first.session_id for p in b['packets']]
            self.assertEqual([1, 2], [p['sequence'] for p in first_packets])
            self.assertEqual(['client', 'server'], [p['direction'] for p in first_packets])
        finally:
            sender.close()
        self.assertFalse(sender.worker.is_alive())
        self.assertFalse(first.capture(b'\x03\x00\x50', 'client'))

    def test_python_sdk_queue_loss_is_reported_as_next_sequence_gap(self):
        spec = importlib.util.spec_from_file_location('bridge_sender_loss_test', ROOT / 'src/server_bridge_sdk/bridge_sender.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        entered, release = threading.Event(), threading.Event()
        def callback(batch):
            self.received.append(batch)
            if batch['first_sequence'] == 1:
                entered.set()
                release.wait(2)
        self.bridge._on_batch = callback
        sender = module.BridgeSender(self.config, capacity=1)
        try:
            connection = sender.begin_connection('raw')
            self.assertTrue(connection.capture(b'\x03\x00\x50', 'client'))
            self.assertTrue(entered.wait(1))
            self.assertTrue(connection.capture(b'\x03\x00\x50', 'client'))
            self.assertFalse(connection.capture(b'\x03\x00\x50', 'client'))
            release.set()
            deadline = time.monotonic() + 3
            while sender.snapshot()['delivered'] < 2 and time.monotonic() < deadline: time.sleep(.01)
            self.assertEqual(2, sender.snapshot()['delivered'])
            self.assertTrue(connection.capture(b'\x03\x00\x50', 'client'))
            deadline = time.monotonic() + 3
            while sender.snapshot()['delivered'] < 3 and time.monotonic() < deadline: time.sleep(.01)
            self.assertEqual(3, sender.snapshot()['delivered'])
            self.assertEqual(1, sender.snapshot()['dropped'])
            self.assertEqual([1, 2, 4], [p['sequence'] for b in self.received for p in b['packets']])
            self.assertTrue(self.received[-1]['gap'])
        finally:
            release.set()
            sender.close()

    def test_python_sdk_http_rejection_is_loss_not_delivery(self):
        spec = importlib.util.spec_from_file_location('bridge_sender_reject_test', ROOT / 'src/server_bridge_sdk/bridge_sender.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.bridge._on_batch = lambda _: False
        sender = module.BridgeSender(self.config)
        try:
            connection = sender.begin_connection('raw')
            connection.capture(b'\x03\x00\x50', 'client')
            deadline = time.monotonic() + 3
            while sender.snapshot()['failed_batches'] < 1 and time.monotonic() < deadline: time.sleep(.01)
            self.assertEqual((0, 1), (sender.snapshot()['delivered'], sender.snapshot()['dropped']))
            self.bridge._on_batch = self.received.append
            connection.capture(b'\x03\x00\x50', 'client')
            deadline = time.monotonic() + 3
            while sender.snapshot()['delivered'] < 1 and time.monotonic() < deadline: time.sleep(.01)
            self.assertEqual(1, sender.snapshot()['delivered'])
            self.assertTrue(self.received[0]['gap'])
            self.assertEqual(2, self.received[0]['first_sequence'])
        finally:
            sender.close()

    def test_python_sdk_maximum_packets_respect_http_body_budget(self):
        spec = importlib.util.spec_from_file_location('bridge_sender_large_test', ROOT / 'src/server_bridge_sdk/bridge_sender.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        sender = module.BridgeSender(self.config, capacity=64)
        try:
            connection = sender.begin_connection('raw')
            packet = b'\x00\x80\x50' + bytes(32765)
            for index in range(20):
                self.assertTrue(connection.capture(packet, 'client' if index % 2 == 0 else 'server'))
            deadline = time.monotonic() + 5
            while sender.snapshot()['delivered'] < 20 and time.monotonic() < deadline: time.sleep(.01)
            self.assertEqual(20, sender.snapshot()['delivered'])
            self.assertEqual(0, sender.snapshot()['dropped'])
            self.assertGreaterEqual(len(self.received), 2)
            for batch in self.received:
                self.assertLessEqual(len(json.dumps(batch).encode()), MAX_BODY)
            self.assertEqual(list(range(1, 21)), [p['sequence'] for b in self.received for p in b['packets']])
        finally:
            sender.close()

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'Java JDK not installed')
    def test_java8_sdk_compiles_and_sends_real_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / 'src/server_bridge_sdk/L2PlaintextBridge.java', root / 'L2PlaintextBridge.java')
            (root / 'Smoke.java').write_text('''
public class Smoke {
 public static void main(String[] args) throws Exception {
  try (L2PlaintextBridge bridge = new L2PlaintextBridge(args[0], args[1], 64)) {
   L2PlaintextBridge.Connection c = bridge.beginConnection("classic-h5");
   byte[] packet = new byte[32768]; packet[1] = (byte)128; packet[2] = 80;
   for (int i = 0; i < 20; ++i)
    if (!c.capture(packet, i % 2 == 0 ? "client" : "server")) throw new Exception("enqueue failed");
   long deadline = System.nanoTime() + 4000000000L;
   while (bridge.delivered.get() < 20 && System.nanoTime() < deadline) Thread.sleep(10);
   if (bridge.delivered.get() != 20 || bridge.dropped.get() != 0) throw new Exception("delivery failed");
  }
 }
}
''', encoding='utf-8')
            compiled = subprocess.run([shutil.which('javac'), '-source', '8', '-target', '8', 'L2PlaintextBridge.java', 'Smoke.java'],
                                      cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            executed = subprocess.run([shutil.which('java'), '-cp', str(root), 'Smoke', self.config['endpoint'], self.config['token']],
                                      cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(0, executed.returncode, executed.stderr)
            self.assertEqual(list(range(1, 21)), [p['sequence'] for b in self.received for p in b['packets']])
            self.assertEqual(['client', 'server'] * 10, [p['direction'] for b in self.received for p in b['packets']])
            self.assertGreaterEqual(len(self.received), 2)
            for batch in self.received:
                self.assertLessEqual(len(json.dumps(batch).encode()), MAX_BODY)


if __name__ == '__main__':
    unittest.main()
