"""Loopback HTTP API and static packet dashboard; no server dependencies."""
import json
import secrets
import threading
import tempfile
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .discovery import interfaces, processes
from .live_state import ROOT
from .protocol import CATEGORIES
from .editor import Drafts, convert, parse_hex
from .ciphers import CIPHERS, decrypt_body


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, monitor):
        super().__init__(address, Handler)
        self.monitor = monitor
        self.token = secrets.token_urlsafe(32)
        self.drafts = Drafts()
        self.sender = monitor.sender


class Handler(BaseHTTPRequestHandler):
    server_version = 'L2Monitor/1.0'

    def log_message(self, *args):
        pass

    def send(self, data, content_type='application/json; charset=utf-8', status=200, filename=None):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def allowed(self, mutation=False):
        port = self.server.server_address[1]
        hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
        if self.headers.get('Host') not in hosts:
            self.send({'error': 'Invalid Host'}, status=403)
            return False
        origin = self.headers.get('Origin')
        if origin and origin not in {'http://' + h for h in hosts}:
            self.send({'error': 'Invalid Origin'}, status=403)
            return False
        provided = self.headers.get('X-Monitor-Token', '')
        if mutation and (not provided.isascii() or not secrets.compare_digest(provided, self.server.token)):
            self.send({'error': 'X-Monitor-Token required; GET /api/info'}, status=403)
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        try:
            self.get()
        except (ValueError, KeyError) as error:
            self.send({'error': str(error)}, status=400)
        except Exception as error:
            self.send({'error': str(error)}, status=500)

    def get(self):
        parsed = urlsplit(self.path)
        path, query, monitor = parsed.path, parse_qs(parsed.query, keep_blank_values=True), self.server.monitor
        if path in ('/', '/index.html', '/app.js', '/styles.css', '/api/docs'):
            file = {'/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js',
                    '/styles.css': 'styles.css', '/api/docs': 'api.html'}[path]
            mime = {'html': 'text/html', 'js': 'application/javascript', 'css': 'text/css'}[file.rsplit('.', 1)[1]]
            asset=ROOT / 'web' / file
            if not asset.exists():
                return self.send({'application':'L2 Packet Monitor Desktop', 'api':'/api/info',
                                  'interface':'native-window'})
            return self.send(asset.read_bytes(), mime + '; charset=utf-8')
        if path == '/favicon.ico':
            return self.send(b'', 'image/x-icon', status=204)
        if path == '/api/health':
            return self.send({'ok': True, 'version': '1.0', 'capture_running': monitor.status()['running']})
        if path == '/api/info':
            return self.send(dict(version='1.0', token=self.server.token,
                categories=[dict(id=k, label=v[0], color=v[1]) for k, v in CATEGORIES.items()],
                ciphers=[dict(id=k, **v) for k, v in CIPHERS.items()],
                endpoints=['GET /api/status', 'GET /api/processes', 'GET /api/interfaces',
                           'GET /api/packets', 'GET /api/packets/{id}', 'GET /api/export',
                           'GET /api/items', 'GET /api/inventory', 'GET /api/inventory/drop-queue',
                           'POST /api/inventory/drop', 'POST /api/inventory/drop-pause', 'POST /api/inventory/drop-stop',
                           'GET /api/auto-pickup', 'POST /api/auto-pickup',
                           'GET /api/skills', 'POST /api/skills/refresh', 'POST /api/skills/learn',
                           'GET /api/buffs', 'POST /api/buffs/start',
                           'GET /api/auto-heal', 'POST /api/auto-heal', 'GET /api/character',
                           'GET /api/recovery', 'POST /api/recovery',
                           'GET /api/client-catalog', 'GET /api/packet-queue', 'POST /api/packet-queue/add',
                           'POST /api/packet-queue/start', 'POST /api/packet-queue/pause', 'POST /api/packet-queue/stop',
                           'GET /api/types', 'GET /api/library', 'GET /api/library/export',
                           'POST /api/start', 'POST /api/stop', 'POST /api/convert',
                           'POST /api/drafts', 'GET /api/drafts/{id}', 'GET /api/drafts/{id}.bin',
                           'GET /api/ciphers', 'POST /api/cipher', 'POST /api/decrypt',
                           'GET /api/sender', 'POST /api/send', 'GET /api/sources',
                           'POST /api/source', 'GET /api/profiles/export',
                           'POST /api/bridge/start', 'POST /api/bridge/stop',
                           'POST /api/bridge/configuration', 'POST /api/bridge/export']))
        if path == '/api/sources':
            return self.send(monitor.source_status())
        if path == '/api/profiles/export':
            with tempfile.TemporaryDirectory() as folder:
                target=Path(folder)/'l2-client-profiles.zip'
                monitor.export_profiles(target)
                return self.send(target.read_bytes(),'application/zip',filename=target.name)
        if path == '/api/sender':
            return self.send(self.server.sender.status())
        if path == '/api/items':
            return self.send(monitor.world.snapshot())
        if path == '/api/inventory':
            return self.send(monitor.inventory.snapshot())
        if path == '/api/inventory/drop-queue':
            return self.send(monitor.inventory_drop.snapshot())
        if path == '/api/auto-pickup':
            return self.send(monitor.auto_pickup.snapshot())
        if path == '/api/skills':
            result = monitor.skills.snapshot()
            result['skills'] = [dict(row, name=monitor.auto_heal.catalog.skill_name(row['skill_id'], row['skill_level'])) for row in result['skills']]
            return self.send(dict(**result, actions=monitor.skill_actions.snapshot()))
        if path == '/api/client-catalog':
            return self.send(monitor.auto_heal.catalog.query(query.get('kind', ['items'])[0], query.get('search', [''])[0],
                int(query.get('offset', ['0'])[0]), int(query.get('limit', ['1000'])[0])))
        if path == '/api/packet-queue':
            runner = getattr(monitor, 'packet_queue_runner', None)
            if runner is None:
                raise ValueError('Очередь доступна в нативном окне программы')
            sender = runner.sender.status()
            return self.send(dict(**runner.snapshot(), entries=runner.queue.items(),
                                  available=sender['available'],
                                  blocked_reason=runner.validation_error() or sender.get('reason')))
        if path == '/api/buffs':
            return self.send(dict(**monitor.buffs.snapshot(), actions=monitor.newbie_buff.snapshot()))
        if path == '/api/auto-heal':
            return self.send(monitor.auto_heal.snapshot())
        if path == '/api/recovery':
            return self.send({key: channel.snapshot() for key, channel in monitor.recovery.items()})
        if path == '/api/character':
            return self.send(dict(character=monitor.character_status()))
        if path == '/api/types':
            return self.send({'types': monitor.store.type_list()})
        if path in ('/api/library', '/api/library/export'):
            filters = dict(kind=query.get('kind', [None])[0] or None,
                           server=query.get('server', [None])[0] or None,
                           search=query.get('search', [''])[0])
            if path.endswith('/export'):
                format = query.get('format', ['json'])[0]
                return self.send(monitor.library.export(format, **filters),
                    'application/json; charset=utf-8' if format == 'json' else 'text/csv; charset=utf-8',
                    filename='l2-library.' + format)
            rows = monitor.library.query(**filters)
            return self.send({'entries': rows, 'count':len(rows)})
        if path == '/api/ciphers':
            return self.send({'ciphers': [dict(id=k, **v) for k, v in CIPHERS.items()]})
        if path == '/api/status':
            return self.send(monitor.status())
        if path == '/api/processes':
            return self.send({'processes': processes()})
        if path == '/api/interfaces':
            return self.send({'interfaces': interfaces()})
        if path == '/api/packets':
            after = int(query.get('after', ['0'])[0])
            limit = int(query.get('limit', ['250'])[0])
            if after < 0 or not 1 <= limit <= 1000:
                raise ValueError('after >= 0, 1 <= limit <= 1000')
            category = query.get('category', [None])[0]
            direction = query.get('direction', [None])[0]
            if category and category not in CATEGORIES:
                raise ValueError('Unknown category')
            if direction and direction not in ('server', 'client'):
                raise ValueError('Unknown direction')
            categories = set(filter(None, query['categories'][0].split(','))) if 'categories' in query else None
            types = set(filter(None, query['types'][0].split(','))) if 'types' in query else None
            if categories is not None and not categories.issubset(CATEGORIES):
                raise ValueError('Unknown categories')
            return self.send(monitor.store.query(after, limit, category, direction,
                                                query.get('search', [''])[0], categories, types))
        if path.startswith('/api/packets/'):
            packet = monitor.store.detail(int(path.rsplit('/', 1)[1]))
            return self.send(packet if packet else {'error': 'Packet expired or not found'}, status=200 if packet else 404)
        if path == '/api/export':
            rows = monitor.store.export()
            data = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows).encode('utf-8')
            return self.send(data, 'application/x-ndjson; charset=utf-8', filename='l2-packets.jsonl')
        if path.startswith('/api/drafts/'):
            draft_id = path.rsplit('/', 1)[1]
            binary = draft_id.endswith('.bin')
            draft = self.server.drafts.get(draft_id[:-4] if binary else draft_id)
            if not draft:
                return self.send({'error': 'Draft not found'}, status=404)
            if binary:
                return self.send(bytes.fromhex(draft['hex']), 'application/octet-stream', filename=draft['id'] + '.bin')
            return self.send(draft)
        self.send({'error': 'Not found'}, status=404)

    def do_POST(self):
        if not self.allowed(mutation=True):
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 512000:
                raise ValueError('Request body too large')
            body = json.loads(self.rfile.read(length) or b'{}')
            if not isinstance(body, dict):
                raise ValueError('Expected JSON object')
            path = urlsplit(self.path).path
            if path == '/api/source':
                self.server.monitor.configure_source(body.get('mode'))
                return self.send(self.server.monitor.source_status())
            if path == '/api/bridge/start':
                return self.send(self.server.monitor.bridge_start(),status=202)
            if path == '/api/bridge/stop':
                self.server.monitor.bridge_stop()
                return self.send(self.server.monitor.source_status())
            if path == '/api/bridge/configuration':
                return self.send(self.server.monitor.bridge_configuration())
            if path == '/api/bridge/export':
                with tempfile.TemporaryDirectory() as folder:
                    target=Path(folder)/'l2-server-bridge.zip'
                    self.server.monitor.export_bridge_package(target)
                    return self.send(target.read_bytes(),'application/zip',filename=target.name)
            if path.startswith('/api/packet-queue/'):
                runner = getattr(self.server.monitor, 'packet_queue_runner', None)
                if runner is None:
                    raise ValueError('Очередь доступна в нативном окне программы')
                action = path.rsplit('/', 1)[1]
                if action == 'start':
                    runner.start(body.get('repeats', 1), body.get('interval_ms', 250))
                elif action == 'pause':
                    if type(body.get('paused')) is not bool:
                        raise ValueError('paused must be boolean')
                    runner.pause(body['paused'])
                elif action == 'stop':
                    runner.stop()
                elif action in ('add', 'clear'):
                    if runner.snapshot()['active']:
                        raise ValueError('Сначала остановите очередь')
                    if action == 'clear':
                        runner.queue.clear()
                    else:
                        raw = parse_hex(body.get('hex', ''))
                        from .sender import validate_packet
                        validate_packet(raw)
                        runner.queue.add(dict(raw_hex=raw.hex(), direction=body.get('direction', 'client'),
                            opcode=f'{raw[2]:02X}', length=len(raw), name='API', category='other'))
                else:
                    return self.send({'error': 'Not found'}, status=404)
                return self.send(runner.snapshot(), status=202)
            if path == '/api/auto-heal':
                self.server.monitor.auto_heal.configure(body.get('enabled'), body.get('item_id'), body.get('threshold', 80), body.get('interval_ms', 11000))
                return self.send(self.server.monitor.auto_heal.snapshot())
            if path == '/api/recovery':
                resource = body.get('resource')
                if resource not in ('cp', 'hp', 'mp'):
                    raise ValueError('Выберите CP, HP или MP')
                channel = self.server.monitor.recovery[resource]
                channel.configure(body.get('enabled'), body.get('item_id'), body.get('threshold', 80), body.get('interval_ms', 11000))
                return self.send(channel.snapshot())
            if path == '/api/buffs/start':
                self.server.monitor.newbie_buff.start(body.get('count'))
                return self.send(self.server.monitor.newbie_buff.snapshot(), status=202)
            if path == '/api/skills/refresh':
                self.server.monitor.refresh_skills()
                return self.send(self.server.monitor.skill_actions.snapshot(), status=202)
            if path == '/api/skills/learn':
                self.server.monitor.skill_actions.learn(body.get('skill_id'), body.get('level'))
                return self.send(self.server.monitor.skill_actions.snapshot(), status=202)
            if path == '/api/auto-pickup':
                self.server.monitor.auto_pickup.configure(body.get('enabled'), body.get('radius', 200), body.get('interval_ms', 750))
                return self.send(self.server.monitor.auto_pickup.snapshot())
            if path == '/api/inventory/drop':
                job_id = self.server.monitor.inventory_drop.enqueue(
                    body.get('object_id'), body.get('amount'), body.get('mode', 'single'), body.get('interval_ms', 500))
                return self.send(dict(job_id=job_id), status=202)
            if path == '/api/inventory/drop-pause':
                paused = body.get('paused', True)
                if type(paused) is not bool:
                    raise ValueError('paused must be boolean')
                self.server.monitor.inventory_drop.pause(paused)
                return self.send(self.server.monitor.inventory_drop.snapshot())
            if path == '/api/inventory/drop-stop':
                self.server.monitor.inventory_drop.stop()
                return self.send(self.server.monitor.inventory_drop.snapshot())
            if path == '/api/start':
                pid = body.get('pid')
                if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0):
                    raise ValueError('pid must be a positive integer')
                interface = body.get('interface', 'auto')
                if not isinstance(interface, str) or len(interface) > 200:
                    raise ValueError('Invalid interface')
                started = self.server.monitor.start(pid, interface, body.get('cipher', 'auto'),source=body.get('source'))
                return self.send({'started': started, 'status': self.server.monitor.status()}, status=202)
            if path == '/api/stop':
                self.server.monitor.stop()
                return self.send(self.server.monitor.status())
            if path == '/api/convert':
                return self.send(convert(body))
            if path == '/api/send':
                source_id = body.get('packet_id')
                source = self.server.monitor.store.detail(int(source_id)) if source_id is not None else None
                if source_id is not None and source is None:
                    return self.send({'error':'Source packet expired or not found'},status=404)
                return self.send(self.server.sender.send(parse_hex(body.get('hex','')),source),status=202)
            if path == '/api/cipher':
                mode = body.get('cipher', 'auto')
                if mode not in CIPHERS:
                    raise ValueError('Неизвестный шифр')
                options = dict(self.server.monitor.options, cipher=mode)
                self.server.monitor.stop()
                if self.server.monitor.status()['running']:
                    return self.send({'error': 'Захват ещё останавливается'}, status=409)
                self.server.monitor.start(**options)
                return self.send(self.server.monitor.status(), status=202)
            if path == '/api/decrypt':
                counter = body.get('counter', 0)
                if not isinstance(counter, int) or not 0 <= counter <= 0xffffffff:
                    raise ValueError('counter: 0..4294967295')
                plain, key, count = decrypt_body(parse_hex(body.get('hex', '')),
                    body.get('cipher', 'asterios'), parse_hex(body.get('key', '')), counter)
                return self.send(dict(hex=plain.hex(' ').upper(), next_key=key.hex(),
                                      counter=count, direction='server', framing='body-only'))
            if path == '/api/drafts':
                source = body.get('packet_id')
                original = self.server.monitor.store.detail(int(source)) if source is not None else None
                if source is not None and original is None:
                    return self.send({'error': 'Source packet expired or not found'}, status=404)
                return self.send(self.server.drafts.save(body, original), status=201)
            self.send({'error': 'Not found'}, status=404)
        except (ValueError, TypeError, OSError) as error:
            self.send({'error': str(error)}, status=400)

