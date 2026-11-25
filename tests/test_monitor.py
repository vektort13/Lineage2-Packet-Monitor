import hashlib
import http.client
import json
import random
import struct
import sys
import tempfile
import threading
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor.editor import Drafts, convert, from_text, parse_hex, to_text
from l2_monitor.engine import Monitor, PacketStore
from l2_monitor.http_api import ApiServer
from l2_monitor.protocol import Catalog, decode_window
from l2_monitor.ciphers import decrypt_body, server_variant, xor_encrypt
from l2_monitor.world import World
from l2_monitor.library import Library
from l2_monitor.semantics import extra_fields
from l2_monitor.alignment import wire_slice, record_prefix
from l2_monitor.sender import validate_packet, NativeSender


class EditorTests(unittest.TestCase):
    def test_arbitrary_bytes_roundtrip_all_encodings(self):
        data = bytes(range(256)) + b'\0'
        for encoding in ['utf-8', 'utf-16le', 'cp1251', 'latin-1']:
            with self.subTest(encoding=encoding):
                self.assertEqual(from_text(to_text(data, encoding), encoding), data)

    def test_literal_escape_and_raw_byte_are_distinct(self):
        data = b'\\xFF\xff\n\0'
        self.assertEqual(from_text(to_text(data, 'utf-8'), 'utf-8'), data)
        self.assertNotEqual(from_text(r'\\xFF', 'utf-8'), from_text(r'\xFF', 'utf-8'))

    def test_unicode_and_truncated_utf16_roundtrip(self):
        data = 'Привет 🌍'.encode('utf-16le') + b'\x00\xd8\x01'
        self.assertEqual(from_text(to_text(data, 'utf-16le'), 'utf-16le'), data)

    def test_encoding_and_length_update(self):
        result = convert(dict(mode='text-to-hex', encoding='utf-16le', text=r'X501\0'))
        self.assertEqual(result['hex'], '58 00 35 00 30 00 31 00 00 00')
        result = convert(dict(hex='00 00 08 01 00 00 10', update_length=True))
        self.assertEqual(result['hex'][:5], '07 00')
        self.assertTrue(result['length_matches'])

    def test_malformed_hex_and_escape_are_rejected(self):
        for text in ['F', '0G', '1 2']:
            with self.assertRaises(ValueError):
                parse_hex(text)
        for text in ['\\', r'\xF', r'\q']:
            with self.assertRaises(ValueError):
                from_text(text, 'utf-8')

    def test_saved_copy_preserves_original(self):
        with tempfile.TemporaryDirectory() as directory:
            drafts = Drafts(Path(directory))
            original = dict(id=1, raw_hex='03007d', sha256=hashlib.sha256(bytes.fromhex('03007d')).hexdigest())
            draft = drafts.save(dict(hex='03 00 08'), original)
            self.assertEqual(original['raw_hex'], '03007d')
            self.assertEqual(draft['changed_bytes'], 1)
            self.assertEqual((Path(directory) / (draft['id'] + '.bin')).read_bytes(), b'\x03\x00\x08')
            with self.assertRaises(ValueError):
                drafts.get('../outside')


class StoreTests(unittest.TestCase):
    def packet(self, category='movement', direction='server'):
        return dict(category=category, direction=direction, opcode='79', name='ValidateLocation',
                    fields={}, raw_hex='030079', color='#58a6ff')

    def test_multiple_categories_types_and_none_selected(self):
        store = PacketStore()
        store.add([self.packet('movement'), self.packet('state'), self.packet('movement', 'client')])
        self.assertEqual(len(store.query(categories={'state','movement'}, types={'server:79'})['packets']), 2)
        self.assertEqual(store.query(categories=set())['packets'], [])
        self.assertEqual(store.query(types=set())['packets'], [])
        self.assertEqual(store.type_list()[1]['count'], 2)

    def test_filtered_cursor_does_not_skip_next_matching_page(self):
        store = PacketStore()
        store.add([self.packet('state'), self.packet(), self.packet('state'), self.packet()])
        page = store.query(0, 1, category='movement')
        self.assertEqual(page['cursor'], 2)
        next_page = store.query(page['cursor'], 1, category='movement')
        self.assertEqual([p['id'] for p in next_page['packets']], [4])
        self.assertNotIn('raw_hex', next_page['packets'][0])

    def test_expired_history_is_explicit(self):
        store = PacketStore(2)
        store.add([self.packet() for _ in range(5)])
        self.assertTrue(store.query(1)['history_truncated'])
        self.assertIsNone(store.detail(1))


class DiagnosticPacketTests(unittest.TestCase):
    def test_observed_diagnostic_is_classified_and_decoded(self):
        raw = bytes.fromhex('1c00ff0402434d5046303a203642384331314144205b307835305d00')
        packet = Catalog().packet('client', raw, 0, 1, 'test')
        self.assertEqual(packet['category'], 'error')
        self.assertEqual(packet['name'], 'ClientDiagnostic')
        self.assertEqual(packet['fields']['message'], 'CMPF0: 6B8C11AD [0x50]')
        self.assertEqual(packet['fields']['diagnostic_type'], 'cmpf0')

    def test_unrecognized_ff_is_not_reclassified(self):
        raw = bytes.fromhex('0600ff010200')
        packet = Catalog().packet('client', raw, 0, 1, 'test')
        self.assertEqual(packet['name'], 'Unknown')


class CipherAndDictionaryTests(unittest.TestCase):
    def test_cipher_variants_and_fixed_asterios_vector(self):
        plain, _, count = decrypt_body(bytes.fromhex('0d070708190b0b0c05'), 'asterios', bytes(range(16)), 7)
        self.assertEqual(plain.hex(), '080100001001000000')
        self.assertEqual(count, 8)
        self.assertEqual(server_variant(9, 8), 'asterios:short-xor')
        self.assertEqual(server_variant(150, 54), 'asterios:plain-cyclic')
        self.assertEqual(server_variant(100, 5), 'asterios:running-xor16')

    def test_standard_xor_option(self):
        key = bytes(range(16))
        plain = b'\x79reference vector'
        cipher = xor_encrypt(plain, key)
        result, _, _ = decrypt_body(cipher, 'l2xor16', key)
        self.assertEqual(result, plain)
        with self.assertRaises(ValueError):
            decrypt_body(cipher, 'auto', key)

    def fixture(self):
        rng = random.Random(73)
        dictionary = bytes(rng.randrange(256) for _ in range(32768))
        body = b'\x7d' + dictionary[-200:] + bytes(rng.randrange(256) for _ in range(400))
        inner = struct.pack('<H', len(body) + 2) + body
        compressor = zlib.compressobj(wbits=-15, zdict=dictionary)
        compressed = compressor.compress(inner) + compressor.flush(zlib.Z_SYNC_FLUSH)
        outer_body = b'\x8d' + compressed
        self.assertGreater(len(outer_body), 111)
        wire = struct.pack('<H', len(outer_body) + 2) + outer_body
        key = bytes(range(16)).hex()
        before = dict(server_counter=53, client_counter=0, incoming_key=key, outgoing_key=key,
                      client_header_state=0, dictionary=dictionary, inflate_total=0, read_end_ns=1_000_000_000)
        after = dict(before, server_counter=54, dictionary=(dictionary + inner)[-32768:],
                     inflate_total=len(inner), read_start_ns=3_000_000_000)
        rows = [{'frame.number':'1', 'frame.time_epoch':'2.0', 'ip.src':'146.59.110.40',
                 'ip.dst':'client', 'tcp.stream':'0', 'tcp.seq_raw':'100', 'tcp.flags.syn':'0',
                 'tcp.payload':wire.hex()}]
        return rows, before, after, inner

    def test_mid_session_dictionary_and_auto_detection(self):
        rows, before, after, inner = self.fixture()
        packets, verification = decode_window(rows, before, after, None, '146.59.110.40', Catalog(), 'test')
        self.assertEqual(bytes.fromhex(packets[0]['raw_hex']), inner)
        self.assertTrue(verification['dictionary_verified'])
        self.assertEqual(verification['cipher'], 'asterios')

    def test_wrong_final_dictionary_is_rejected(self):
        rows, before, after, _ = self.fixture()
        after['dictionary'] = bytes(32768)
        with self.assertRaisesRegex(ValueError, 'словарь'):
            decode_window(rows, before, after, None, '146.59.110.40', Catalog(), 'test', 'asterios')

    def test_cursor_uses_exact_records_despite_timestamp_and_future_tail(self):
        rows, before, after, inner = self.fixture()
        wire = bytes.fromhex(rows[0]['tcp.payload'])
        rows[0]['frame.time_epoch'] = '0.5'  # Before the wall-time snapshot.
        rows[0]['tcp.payload'] = (wire + b'\x03\x00\x7d').hex()
        packets, result = decode_window(rows, before, after, None, '146.59.110.40', Catalog(), 'test',
                                         'asterios', {'server':100})
        self.assertEqual(bytes.fromhex(packets[0]['raw_hex']), inner)
        self.assertEqual(result['wire_cursors']['server'], 100 + len(wire))


class ObservationTests(unittest.TestCase):
    def packet(self, event, **fields):
        return dict(direction='server', opcode='05', name='SpawnItem', time='2026-11-21T12:00:00Z',
                    frame=1, session_id='test', sha256='abc', raw_hex='030005', fields=dict(event=event, **fields))

    def test_pickup_confirmation_delete_order_and_gap(self):
        world = World()
        world.apply([self.packet('spawn_item', object_id=50, template_value=4357, amount=10, xyz=[3,4,0])])
        action = self.packet('action', object_id=50, xyz=[0,0,0])
        action['direction'] = 'client'
        world.apply([action])
        self.assertEqual(action['category'], 'item_action')
        self.assertEqual(world.snapshot()['items'][0]['distance_xy'], 5)
        world.gap()
        self.assertEqual(world.snapshot()['items'][0]['state'], 'uncertain')
        world.apply([self.packet('delete_object', object_id=50),
                     self.packet('get_item', object_id=50, owner_id=70, xyz=[3,4,0])])
        self.assertEqual(world.snapshot()['items'], [])
        self.assertEqual(world.snapshot()['events'][0]['template_value'], 4357)

    def test_library_persists_deduplicates_and_scopes_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.sqlite'
            library = Library(path)
            packet = self.packet('spawn_item', object_id=50, template_value=4357, amount=10, xyz=[3,4,0])
            library.observe([packet, packet], 'server-a', 'profile')
            library.observe([packet], 'server-b', 'profile')
            skill = self.packet('skill_launched', skill_id=5586, skill_level=3)
            library.observe([skill], 'server-a', 'profile')
            rows = Library(path).query('item', 'server-a')
            self.assertEqual(rows[0]['observations'], 1)
            self.assertIsNone(rows[0]['name'])
            self.assertEqual(len(library.query('item')), 2)
            self.assertEqual(library.query('skill')[0]['level'], 3)
            self.assertIn('raw_hex', json.loads(library.export())['entries'][0]['sample'])
            self.assertIn('entity_id', library.export('csv').decode('utf-8-sig'))

    def test_exchange_and_inventory_schema(self):
        request = struct.pack('<HBIIQ', 45, 0xb0, 53728110, 3, 1) + bytes(26)
        fields = extra_fields('client', request)
        self.assertEqual(fields['exchange'], '1 Gold → 10 Silver')
        self.assertEqual(fields['confirmation'], 'request')
        inventory = struct.pack('<HBH', 81, 0x21, 1) + struct.pack('<HIIIQ', 1, 88, 4357, 8, 10) + bytes(54)
        self.assertEqual(extra_fields('server', inventory)['items'][0]['amount'], 10)
        with self.assertRaises(ValueError):
            extra_fields('server', inventory[:-1])

    def test_observed_hybrid_skill_offsets(self):
        raw = bytes.fromhex('48004800000000361e081021d7191000d2150000030000000b0c0000d21500007017000098ecfefff89c0100f0f0ffff00000000e8ecfeffd89c0100f0f0ffff0100000000000000')
        fields = extra_fields('server', raw)
        self.assertEqual((fields['skill_id'],fields['skill_level']), (5586,3))
        self.assertEqual(fields['target_id'], 270128929)

    def test_owned_skill_list_and_offered_level_are_distinct(self):
        owned = bytes.fromhex('19005f01000000000000000400000003000000030000000000')
        self.assertEqual(extra_fields('server', owned)['skills'][0]['skill_level'], 4)
        offered = bytes.fromhex('6d00fef900040000000300000005000000720100000a00000000000000000010000000020000003200000005000000000000000000380000000200000032000000050000000000000000007d0500000100000000000000340001000000aa210000010000000000000000000000')
        fields = extra_fields('server', offered)
        self.assertEqual(fields['confirmation'], 'offered-by-server')
        self.assertEqual(fields['skills'][0]['skill_level'], 5)
        self.assertEqual(fields['skills'][3]['required_items'], [{'item_id':8618,'amount':1}])
        with self.assertRaises((ValueError,struct.error)):
            extra_fields('server', offered[:-1])


class SenderValidationTests(unittest.TestCase):
    def test_full_plain_packet_length_is_required(self):
        self.assertEqual(validate_packet(bytes.fromhex('030050')),b'\x50')
        for raw in (b'',b'\x50',bytes.fromhex('040050'),bytes.fromhex('0300d0')):
            with self.assertRaises(ValueError):
                validate_packet(raw)

    def test_server_source_and_blocked_profile_do_not_execute(self):
        class Stopped:
            def status(self):return dict(state='stopped')
        sender = NativeSender(Stopped())
        sender._invoke = lambda *args: self.fail('Native call must not run')
        with self.assertRaisesRegex(ValueError,'клиентский'):
            sender.send(bytes.fromhex('030050'), {'direction':'server'})
        self.assertFalse(sender.status()['available'])
        with self.assertRaises(ValueError) as result:
            sender.send(bytes.fromhex('030050'))
        self.assertEqual(str(result.exception), sender.status()['reason'])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = Monitor()
        cls.server = ApiServer(('127.0.0.1', 0), cls.monitor)
        cls.thread = threading.Thread(target=lambda: cls.server.serve_forever(poll_interval=0.02), daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def request(self, method, path, body=None, token=True, host=None):
        port = self.server.server_address[1]
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        headers = {'Content-Type':'application/json'}
        if token:
            headers['X-Monitor-Token'] = self.server.token
        if host:
            headers['Host'] = host
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, json.loads(data)

    def test_mutation_requires_token(self):
        for path in ('/api/convert', '/api/inventory/drop', '/api/inventory/drop-pause', '/api/inventory/drop-stop', '/api/auto-pickup', '/api/skills/learn', '/api/skills/refresh', '/api/buffs/start', '/api/auto-heal', '/api/packet-queue/start', '/api/packet-queue/add'):
            status, _ = self.request('POST', path, dict(hex='41'), token=False)
            self.assertEqual(status, 403, path)

    def test_complete_client_catalog_is_available_without_game(self):
        status, data = self.request('GET', '/api/client-catalog?kind=skills&search=1068')
        self.assertEqual(status, 200)
        self.assertTrue(data['rows'])
        self.assertTrue(all(row['id'] == 1068 and row['name'] == 'Might' for row in data['rows']))
        self.assertEqual(data['skills'], 84004)
        status, data = self.request('GET', '/api/client-catalog?kind=items&offset=28000&limit=10')
        self.assertEqual(status, 200)
        self.assertEqual(len(data['rows']), 10)
        self.assertEqual(data['total'], 28690)

    def test_api_and_queue_share_one_sender_without_a_window(self):
        self.assertIs(self.server.sender, self.monitor.sender)
        self.assertIs(self.monitor.packet_queue_runner.sender, self.monitor.sender)
        self.assertIs(self.monitor.packet_queue_runner.queue, self.monitor.packet_queue)
        status, data = self.request('GET', '/api/packet-queue')
        self.assertEqual(status, 200)
        self.assertFalse(data['active'])

    def test_inventory_drop_routes_validate_state_and_pause_control(self):
        status, data = self.request('GET', '/api/inventory/drop-queue')
        self.assertEqual(status, 200)
        self.assertFalse(data['active'])
        status, _ = self.request('POST', '/api/inventory/drop', dict(object_id=7, amount=1))
        self.assertEqual(status, 400)
        status, data = self.request('POST', '/api/inventory/drop-pause', dict(paused=True))
        self.assertEqual(status, 200)
        self.assertTrue(data['paused'])
        status, _ = self.request('POST', '/api/inventory/drop-pause', dict(paused='false'))
        self.assertEqual(status, 400)
        status, data = self.request('POST', '/api/inventory/drop-stop', {})
        self.assertEqual(status, 200)
        self.assertFalse(data['paused'])

    def test_auto_pickup_api_defaults_and_validation(self):
        status, data = self.request('GET', '/api/auto-pickup')
        self.assertEqual(status, 200)
        self.assertFalse(data['enabled'])
        for body in (dict(enabled='true'), dict(enabled=True, radius=1), dict(enabled=True, interval_ms=0)):
            status, _ = self.request('POST', '/api/auto-pickup', body)
            self.assertEqual(status, 400)
        status, data = self.request('POST', '/api/auto-pickup', dict(enabled=False, radius=250))
        self.assertEqual(status, 200)
        self.assertFalse(data['enabled'])
        self.assertEqual(data['radius'], 250)

    def test_foreign_host_is_rejected(self):
        status, _ = self.request('GET', '/api/status', host='foreign.invalid')
        self.assertEqual(status, 403)

    def test_buff_batch_and_healing_api_validation(self):
        for body in (dict(count=0), dict(count=1001), dict(count=True), dict(count=10)):
            status, _ = self.request('POST', '/api/buffs/start', body)
            self.assertEqual(status, 400)
        for body in (dict(enabled=True), dict(enabled=True, item_id=1061, threshold=100), dict(enabled='true')):
            status, _ = self.request('POST', '/api/auto-heal', body)
            self.assertEqual(status, 400)
        status, data = self.request('POST', '/api/auto-heal', dict(enabled=False, item_id=1061, threshold=80))
        self.assertEqual(status, 200)
        self.assertFalse(data['enabled'])
        self.assertEqual(data['interval_ms'], 11000)

    def test_converter_api_and_cipher_registry(self):
        status, data = self.request('POST', '/api/convert', dict(hex='58 35 30 31', encoding='utf-8'))
        self.assertEqual(status, 200)
        self.assertEqual(data['text'], 'X501')
        status, data = self.request('GET', '/api/ciphers')
        self.assertEqual(status, 200)
        self.assertEqual({x['id'] for x in data['ciphers']}, {'auto','asterios','l2xor16','l2xor16-u64','plain'})

    def test_invalid_page_is_rejected(self):
        status, _ = self.request('GET', '/api/packets?limit=100000')
        self.assertEqual(status, 400)

    def test_item_type_and_empty_filter_routes(self):
        for path in ('/api/items','/api/inventory','/api/skills','/api/buffs','/api/auto-heal','/api/character','/api/types','/api/packets?categories=','/api/packets?types='):
            status, data = self.request('GET', path)
            self.assertEqual(status, 200, (path, data))


if __name__ == '__main__':
    unittest.main()
