"""Continuous bounded capture, process discovery and verified packet publication."""
import collections
import hashlib
import json
import logging
import logging.handlers
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psutil
from decode_prime_client_native import NativeCipherOracle
from .discovery import NO_WINDOW, WIRESHARK, select_interface, select_process
from .live_state import ROOT, DATA_ROOT, LiveState, load_profile, supports_profile
from .wire_capture import wire_packet
from .cipher_profiles import CipherProfiles
from .classic_cipher import ClassicLiveState, decode_classic_window
from .character import CharacterState
from .classic_requests import request_list, request_skill_menu, SkillTransport, client_anchors, clear_client_anchors
from .classic_skill_menu import SkillMenu
from .npcap import Capture as NativeCapture
from .protocol import Catalog, decode_window
from .ciphers import CIPHERS
from .world import World
from .inventory import Inventory
from .inventory_open import AutoInventoryOpen
from .drop_queue import InventoryDropQueue
from .auto_pickup import AutoPickup
from .skills import Skills, SkillActions
from .buffs import Buffs, NewbieBuffBatch
from .auto_heal import AutoRecovery
from .library import Library
from .sender import NativeSender
from .packet_queue import PacketQueue
from .queue_runner import QueueRunner
from .packet_sources import SOURCE_MODES, PROTOCOLS, decode_packet
from .client_tap import ClientTap, supports as supports_tap
from .server_bridge import ServerBridge


FIELDS = ['frame.number', 'frame.time_epoch', 'ip.src', 'tcp.srcport', 'ip.dst',
          'tcp.dstport', 'tcp.stream', 'tcp.seq_raw', 'tcp.flags.syn', 'tcp.payload']


class PacketStore:
    def __init__(self, capacity=10000):
        self.lock = threading.RLock()
        self.items = collections.deque(maxlen=capacity)
        self.sequence = 0
        self.counts = collections.Counter()
        self.directions = collections.Counter()
        self.types = {}

    def add(self, packets):
        with self.lock:
            for packet in packets:
                self.sequence += 1
                packet = dict(packet, id=self.sequence)
                self.items.append(packet)
                self.counts[packet['category']] += 1
                self.directions[packet['direction']] += 1
                key = packet['direction'] + ':' + packet['opcode']
                metadata = self.types.setdefault(key, dict(id=key, direction=packet['direction'],
                    opcode=packet['opcode'], name=packet['name'], category=packet['category'],
                    color=packet['color'], count=0))
                metadata['count'] += 1

    def query(self, after=0, limit=250, category=None, direction=None, search='', categories=None, types=None):
        search = search.lower()
        with self.lock:
            selected = [p for p in self.items if p['id'] > after
                        and (not category or p['category'] == category)
                        and (categories is None or p['category'] in categories)
                        and (types is None or p['direction'] + ':' + p['opcode'] in types)
                        and (not direction or p['direction'] == direction)
                        and (not search or search in (p['opcode'] + ' ' + p['name'] + ' '
                             + json.dumps(p['fields'], ensure_ascii=False)).lower())]
            page = selected[:limit]
            cursor = page[-1]['id'] if len(selected) > limit and page else self.sequence
            return dict(packets=[{k: v for k, v in p.items() if k != 'raw_hex'} for p in page],
                        cursor=cursor, more=len(selected) > limit,
                        oldest_id=self.items[0]['id'] if self.items else None,
                        history_truncated=bool(after and self.items and after < self.items[0]['id'] - 1))

    def detail(self, packet_id):
        with self.lock:
            return next((dict(p) for p in self.items if p['id'] == packet_id), None)

    def export(self):
        with self.lock:
            return [dict(p) for p in self.items]

    def stats(self):
        with self.lock:
            return dict(total=self.sequence, retained=len(self.items), capacity=self.items.maxlen,
                        categories=dict(self.counts), directions=dict(self.directions))

    def type_list(self):
        with self.lock:
            return [dict(t) for _, t in sorted(self.types.items())]


class Capture:
    def __init__(self, endpoint, interface, run_dir):
        self.endpoint = endpoint
        self.lock = threading.Lock()
        self.rows = collections.deque(maxlen=30000)
        self.diagnostics = collections.deque(maxlen=15)
        self.received = 0
        host, port = endpoint['remote_ip'], endpoint['remote_port']
        bpf = f'(host {host} and tcp port {port}) or (pppoes and host {host} and tcp port {port})'
        command = [WIRESHARK + 'tshark.exe', '-n', '-l', '-P', '-i', interface['device'],
                   '-f', bpf, '-b', 'duration:60', '-b', 'filesize:4096', '-b', 'files:2',
                   '-w', str(run_dir / 'capture.pcapng'), '-T', 'fields', '-E', 'occurrence=f']
        for field in FIELDS:
            command.extend(['-e', field])
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, encoding='utf-8', errors='replace',
                                        bufsize=1, creationflags=NO_WINDOW)
        self.threads = [threading.Thread(target=self._read, daemon=True),
                        threading.Thread(target=self._stderr, daemon=True)]
        for thread in self.threads:
            thread.start()

    def _read(self):
        for line in self.process.stdout:
            values = line.rstrip('\r\n').split('\t')
            if len(values) != len(FIELDS):
                continue
            row = dict(zip(FIELDS, values))
            remote = str(self.endpoint['remote_port'])
            local = str(self.endpoint['local_port'])
            if ({row['tcp.srcport'], row['tcp.dstport']} != {remote, local}
                    or not row['tcp.seq_raw'] or not row['frame.time_epoch']):
                continue
            row['tcp.stream'] = '0'  # Only the selected four-tuple enters this buffer.
            with self.lock:
                self.received += 1
                row['source_frame'] = row['frame.number']
                row['frame.number'] = str(self.received)
                self.rows.append(row)

    def _stderr(self):
        for line in self.process.stderr:
            if line.strip():
                self.diagnostics.append(line.strip())

    def read_rows(self):
        with self.lock:
            return list(self.rows)

    def trim(self, timestamp_ns):
        cutoff = timestamp_ns / 1e9 - 3
        with self.lock:
            while self.rows and float(self.rows[0]['frame.time_epoch']) < cutoff:
                self.rows.popleft()

    def close(self):
        # Only children of the TShark instance created above are terminated.
        try:
            children = psutil.Process(self.process.pid).children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=3)
        _, alive = psutil.wait_procs(children, timeout=2)
        for child in alive:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        for thread in self.threads:
            thread.join(timeout=1)


class Monitor:
    def __init__(self, interval=4, library_path=None, capture_backend='npcap'):
        if capture_backend not in ('npcap','tshark'):
            raise ValueError('capture_backend: npcap or tshark')
        self.capture_backend = capture_backend
        self.store, self.catalog = PacketStore(), Catalog()
        self.world = World()
        self.inventory = Inventory()
        self.character = CharacterState()
        self.auto_inventory_enabled = True
        self.inventory_drop = InventoryDropQueue(self)
        self.auto_pickup = AutoPickup(self, self.inventory_drop.transport)
        self.skills = Skills()
        self.skill_menu = SkillMenu()
        self.skill_actions = SkillActions(self, SkillTransport(self.inventory_drop.transport, self))
        self.buffs = Buffs()
        self.newbie_buff = NewbieBuffBatch(self, self.inventory_drop.transport)
        self.auto_heal = AutoRecovery(self, self.inventory_drop.transport)
        self.recovery = self.auto_heal.channels
        self.library = Library(library_path)
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None
        self.interval = interval
        self.options = dict(pid=None, interface='auto', cipher='auto')
        self.skill_refresh_requested = threading.Event()
        self.ingest_lock = threading.RLock()
        self.source_mode = 'auto'
        self._server_session = None
        self.bridge = ServerBridge(self._accept_server_batch)
        self.state = dict(state='stopped', message='Захват остановлен', process=None,
                          endpoint=None, interface=None, validated_windows=0, sync_errors=0,
                          captured_frames=0, compressed_blocks=0, expanded_bytes=0,
                          last_error=None, last_verified=None, profile=load_profile()['id'],
                          capture_backend=capture_backend)
        self.state.update(requested_source='auto', active_source=None, protocol=None)
        self.sender = NativeSender(self)
        self.packet_queue = PacketQueue()
        self.packet_queue_runner = QueueRunner(self, self.packet_queue, self.sender)

    def update(self, **values):
        with self.lock:
            self.state.update(values)

    def status(self):
        with self.lock:
            return dict(self.state, running=bool(self.thread and self.thread.is_alive()),
                        interval_seconds=self.interval, packets=self.store.stats())

    def character_status(self):
        return self.character.snapshot() or self.auto_heal.snapshot()['health']

    def configure_source(self, mode):
        if mode not in SOURCE_MODES:
            raise ValueError('Неизвестный источник пакетов')
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('Остановите захват перед сменой источника')
            self.source_mode = mode
            self.update(requested_source=mode)

    def source_status(self):
        # Bridge serializes callbacks: do not take its lock while holding Monitor.lock.
        bridge = self.bridge.snapshot()
        state = self.status()
        registry = CipherProfiles()
        profiles = []
        for item in registry.profiles:
            data = registry.load_profile(item['engine_sha256'], verified_only=False)
            profiles.append(dict(item, client_tap_supported=supports_tap(data),
                                 protocol=data.get('packet_protocol', 'asterios-448' if item['algorithm']=='asterios' else 'raw')))
        current = next((item for item in profiles if item['id']==state.get('profile')), {})
        bridge['active_session'] = dict(id=self._server_session,protocol=state.get('protocol')) if self._server_session else None
        return dict(mode=self.source_mode, active_source=state.get('active_source'),
                    message=state.get('source_fallback') or state.get('message',''), protocol=state.get('protocol'),
                    client_tap_supported=current.get('client_tap_supported',False),
                    profiles=profiles, algorithms=registry.algorithms, protocols=list(PROTOCOLS), bridge=bridge)

    def bridge_start(self):
        return self.bridge.start()

    def bridge_stop(self):
        self.bridge.close()
        if self.source_mode == 'server' and self.status()['running']:
            with self.ingest_lock:
                for model in self._models(): model.gap()
                self.update(state='waiting',message='Серверный мост остановлен')

    def bridge_configuration(self):
        return self.bridge.start()

    def export_bridge_package(self, path):
        self.bridge.start()
        return self.bridge.export_package(path)

    def export_profiles(self, path):
        from .profile_bundles import export_profiles
        return export_profiles(path)

    def import_profiles(self, path):
        if self.status()['running']:
            raise ValueError('Остановите захват перед сменой источника')
        from .profile_bundles import import_profiles
        from .sender import _queue_profile
        result = import_profiles(path)
        _queue_profile.cache_clear()
        return result

    def _models(self):
        return (self.world,self.inventory,self.skills,self.skill_menu,self.buffs,self.character)

    def _publish(self, packets, server, profile, log=None):
        for model in self._models():
            model.apply(packets)
        self.store.add(packets)
        self.library.observe(packets,server,profile)
        if log:
            for packet in packets:
                log.info(json.dumps(packet,ensure_ascii=False))

    def _accept_server_batch(self, batch):
        with self.ingest_lock:
            if (self.source_mode != 'server' or self.stop_event.is_set()
                    or not self.thread or not self.thread.is_alive()):
                return False
            if self._server_session and batch['session_id'] != self._server_session:
                return False
            if self._server_session and batch['protocol'] != self.state.get('protocol'):
                return False
            first = self._server_session is None
            session_id = ('server:'+uuid.uuid4().hex) if first else self.state['session_id']
            packets = [decode_packet(self.catalog,row['direction'],bytes.fromhex(row['hex']),
                row['timestamp'],row['sequence'],session_id,batch['protocol'],
                cipher='plaintext',data_layer='game-packet',capture_source='server',
                plaintext_verified=False,source_authenticated=True,cipher_end_state_verified=False,
                actions_supported=False) for row in batch['packets']]
            if first:
                for model in self._models(): model.reset(session_id)
                self._server_session = batch['session_id']
            if batch.get('gap'):
                for model in self._models(): model.gap()
            self._publish(packets,'server-bridge:'+batch['session_id'],batch['protocol'],getattr(self,'_server_log',None))
            state=self.status()
            self.update(state='live',message='Серверный источник открытых пакетов работает',
                        session_id=session_id, protocol=batch['protocol'],
                        captured_frames=state.get('captured_frames',0)+len(packets),
                        validated_windows=state.get('validated_windows',0)+1,
                        sync_errors=state.get('sync_errors',0)+int(bool(batch.get('gap'))),
                        last_verified=datetime.now(timezone.utc).isoformat(),last_error=None,
                        verification=dict(method='authenticated-server-plaintext',
                                          cipher_end_states_verified=False,sequence_gap=bool(batch.get('gap'))))
            return True

    def _source_log(self, session_id, prefix):
        run_dir=DATA_ROOT/'reports'/(prefix+'-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
        run_dir.mkdir(parents=True)
        log=logging.getLogger(session_id)
        log.setLevel(logging.INFO); log.propagate=False
        handler=logging.handlers.RotatingFileHandler(run_dir/'packets.jsonl',maxBytes=5*1024*1024,backupCount=2,encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s')); log.addHandler(handler)
        return run_dir,log,handler

    def _server_capture(self):
        session_id='server-wait:'+uuid.uuid4().hex
        run_dir,log,handler=self._source_log(session_id,'server-bridge')
        with self.ingest_lock:
            self._server_session=None
            self._server_log=log
            for model in self._models(): model.reset(session_id)
            self.update(state='waiting',message='Ожидание открытых пакетов от серверного модуля',
                        active_source='server',capture_backend='server-bridge',process=None,endpoint=None,
                        session_id=session_id,profile='server-bridge',profile_supported=False,
                        actions_supported=False,skill_actions_supported=False,detected_cipher='plaintext',protocol=None,
                        last_error=None,verification=None,log_directory=str(run_dir))
        try:
            self.bridge.start()
            while not self.stop_event.wait(.2): pass
        finally:
            with self.ingest_lock:
                self._server_log=None
            handler.close();log.removeHandler(handler)

    def refresh_skills(self):
        status = self.status()
        if status.get('state') == 'live' and status.get('detected_cipher') == 'l2xor16-u64':
            self.skill_refresh_requested.set()
            return
        self.skill_actions.refresh()

    def start(self, pid=None, interface='auto', cipher='auto', source=None):
        if cipher not in CIPHERS:
            raise ValueError('Неизвестный шифр')
        with self.lock:
            if self.thread and self.thread.is_alive():
                return False
            if source is not None:
                self.configure_source(source)
            self.stop_event.clear()
            self.options = dict(pid=pid, interface=interface, cipher=cipher,source=self.source_mode)
            self.state['requested_cipher'] = cipher
            self.state.update(source_fallback=None,validated_windows=0,sync_errors=0,captured_frames=0,
                              compressed_blocks=0,expanded_bytes=0)
            self.thread = threading.Thread(target=self._run, args=(pid, interface), daemon=True)
            self.update(state='discovering', message='Поиск игрового процесса', last_error=None)
            self.thread.start()
            self.skill_actions.start()
            self.auto_heal.start()
            return True

    def stop(self):
        self.packet_queue_runner.stop()
        self.inventory_drop.stop()
        self.stop_event.set()
        thread = self.thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=10)
        if not thread or not thread.is_alive():
            self.update(state='stopped', message='Захват остановлен')

    def _run(self, requested_pid, requested_interface):
        while not self.stop_event.is_set():
            try:
                if self.source_mode == 'server':
                    self._server_capture()
                    continue
                process, endpoint = select_process(requested_pid)
                engine = Path(process['exe']).parent / 'Engine.dll'
                checksum = hashlib.sha256(engine.read_bytes()).hexdigest() if engine.is_file() else None
                registered = CipherProfiles().load_profile(checksum) if checksum else None
                if self.source_mode in ('auto','client') and registered and supports_tap(registered):
                    try:
                        self._plaintext_session(process,endpoint,registered)
                        continue
                    except Exception as error:
                        if self.source_mode == 'client' or self.stop_event.is_set(): raise
                        self.update(source_fallback='Открытый захват клиента недоступен: '+str(error))
                elif self.source_mode == 'client':
                    raise ValueError('Для этой сборки нет проверенного адаптера открытых пакетов клиента')
                interface = select_interface(requested_interface, endpoint)
                if registered and registered.get('algorithm') == 'l2xor16-u64':
                    self._session(process, endpoint, interface, registered)
                elif supports_profile(process['exe']):
                    self._session(process, endpoint, interface)
                else:
                    self._wire_session(process, endpoint, interface)
            except Exception as error:
                self.update(state='waiting', message=str(error), last_error=str(error))
                self.stop_event.wait(3)
        self.update(state='stopped', message='Захват остановлен')

    def _wire_session(self, process, endpoint, interface):
        session_id = f"{process['pid']}:{process['create_time']}:{endpoint['local_port']}:{uuid.uuid4().hex[:8]}"
        run_dir = DATA_ROOT / 'reports' / ('wire-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
        run_dir.mkdir(parents=True)
        for model in (self.world, self.inventory, self.skills, self.skill_menu, self.buffs, self.character):
            model.reset(session_id)
        capture = (NativeCapture if self.capture_backend == 'npcap' else Capture)(endpoint, interface, run_dir)
        try:
            self.update(state='capturing', message='Соединение обнаружено; захват TCP. Для этой сборки клиента пока нет профиля расшифровки',
                        active_source='network', protocol='raw',capture_backend=self.capture_backend,
                        process=process, endpoint=endpoint, interface=interface, session_id=session_id,
                        log_directory=str(run_dir), last_error=None, last_verified=None, verification=None,
                        detected_cipher='unknown', profile='unprofiled', profile_supported=False, actions_supported=False,
                        skill_actions_supported=False, captured_frames=0,
                        inventory_auto_open=dict(state='waiting', attempts=0, error=None))
            cursor = 0
            while not self.stop_event.wait(.5):
                if capture.process.poll() is not None:
                    raise ValueError('Захват завершён: ' + ' '.join(capture.diagnostics)[-1000:])
                current, current_endpoint = select_process(process['pid'])
                if current['create_time'] != process['create_time'] or current_endpoint != endpoint:
                    raise ValueError('Игровое соединение изменилось; повторное подключение монитора')
                packets = []
                for row in capture.read_rows():
                    number = int(row['frame.number'])
                    if number <= cursor:
                        continue
                    cursor = number
                    packet = wire_packet(row, endpoint, session_id)
                    if packet:
                        packets.append(packet)
                self.store.add(packets)
                self.update(captured_frames=capture.received)
                capture.trim(time.time_ns())
        finally:
            capture.close()

    def _plaintext_session(self, process, endpoint, profile):
        session_id=f"{process['pid']}:{process['create_time']}:{endpoint['local_port']}:{uuid.uuid4().hex[:8]}"
        run_dir,log,handler=self._source_log(session_id,'client-plaintext')
        tap=ClientTap(process,endpoint,profile)
        jobs={name:dict(state='waiting',attempts=0) for name in ('inventory','skills')}
        self.skill_refresh_requested.clear()
        protocol=profile.get('packet_protocol','raw')
        for model in self._models(): model.reset(session_id)
        try:
            self.update(state='synchronizing',message='Подключение открытого захвата клиента',
                        active_source='client',capture_backend='client-tap',process=process,endpoint=endpoint,
                        interface=dict(id='client',name='Client plaintext'),session_id=session_id,
                        profile=profile['id'],profile_supported=True,protocol=protocol,
                        actions_supported=False,skill_actions_supported=bool(profile.get('skill_requests')),
                        detected_cipher=profile['algorithm'],verification=None,last_verified=None,
                        log_directory=str(run_dir),last_error=None,
                        inventory_auto_open=dict(state='waiting',attempts=0))
            tap.start()
            self.update(state='live',message='Захват открытых пакетов клиента работает',
                        verification=dict(method='native-client-plaintext',cipher_end_states_verified=False))
            menu=profile.get('skill_requests',{}).get('community_menu')
            if menu:
                request_skill_menu(self.status(),profile,menu['root'])
            dropped=invalid=0
            next_identity=0
            while not self.stop_event.is_set():
                if time.monotonic()>=next_identity:
                    current,current_endpoint=select_process(process['pid'])
                    if current['create_time']!=process['create_time'] or current_endpoint!=endpoint:
                        raise ValueError('Игровое соединение изменилось; повторное подключение монитора')
                    next_identity=time.monotonic()+1
                records=tap.read()
                counters=tap.snapshot()
                if not counters['active']:
                    raise ValueError('Открытый захват клиента остановлен')
                loss=counters['dropped']!=dropped or counters['invalid']!=invalid
                if loss:
                    for model in self._models(): model.gap()
                    jobs={name:dict(state='waiting',attempts=0) for name in ('inventory','skills')}
                    self.update(sync_errors=self.status()['sync_errors']+1)
                dropped,invalid=counters['dropped'],counters['invalid']
                packets=[decode_packet(self.catalog,row['direction'],bytes.fromhex(row['raw_hex']),
                    row['timestamp'],row['sequence'],session_id,protocol,cipher=profile['algorithm'],
                    capture_source='client',data_layer='game-packet',plaintext_verified=True,
                    cipher_end_state_verified=False,actions_supported=False) for row in records]
                if packets:
                    self._publish(packets,f"{endpoint['remote_ip']}:{endpoint['remote_port']}",profile['id'],log)
                    self.update(validated_windows=self.status()['validated_windows']+1,
                                last_verified=datetime.now(timezone.utc).isoformat())
                self.update(captured_frames=counters['consumed'],plaintext_capture=counters)
                self._list_jobs_tick(profile,jobs)
                if self.stop_event.wait(.05): break
        finally:
            try:
                tap.close()
            finally:
                handler.close();log.removeHandler(handler)

    def _list_jobs_tick(self, profile, jobs):
        if not profile.get('list_requests'):
            return
        if self.skill_refresh_requested.is_set():
            jobs['skills']=dict(state='waiting',attempts=0)
            self.skill_refresh_requested.clear()
        for name,opcode,observed,enabled in (
                ('inventory',0x14,self.inventory.snapshot(),self.auto_inventory_enabled),
                ('skills',0x50,self.skills.snapshot(),True)):
            job=jobs[name]
            if (observed['full_list_received'] and not observed['coverage_gap'] and job['state']=='requested'
                    and observed['revision']>job.get('before_revision',-1)):
                job['state']='received'
            elif job['state']=='requested' and time.monotonic()>job['deadline']:
                job.update(state='failed',error='Сервер не подтвердил полный список')
            elif enabled and job['state']=='waiting':
                try:
                    result=request_list(self.status(),profile,opcode)
                    job.update(state='requested',attempts=job['attempts']+1,deadline=time.monotonic()+20,
                               call_thread=result['thread'],before_revision=observed['revision'])
                except Exception as error:
                    job.update(state='failed',error=str(error))
        self.update(inventory_auto_open=dict(jobs['inventory']),
                    list_requests={key:dict(value) for key,value in jobs.items()})

    def _session(self, process, endpoint, interface, classic_profile=None):
        session_id = f"{process['pid']}:{process['create_time']}:{endpoint['local_port']}:{uuid.uuid4().hex[:8]}"
        run_dir = DATA_ROOT / 'reports' / ('monitor-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
        run_dir.mkdir(parents=True)
        log = logging.getLogger(session_id)
        log.setLevel(logging.INFO)
        log.propagate = False
        handler = logging.handlers.RotatingFileHandler(run_dir / 'packets.jsonl', maxBytes=5*1024*1024,
                                                       backupCount=2, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        log.addHandler(handler)
        live = capture = oracle = None
        try:
            profile = classic_profile or load_profile()
            if classic_profile:
                if self.options['cipher'] not in ('auto', 'l2xor16-u64'):
                    raise ValueError('Выбранный шифр не соответствует проверенному профилю клиента; выберите Авто')
                live = ClassicLiveState(process['pid'], process['exe'], classic_profile)
            else:
                live = LiveState(process['pid'], process['exe'])
                oracle = NativeCipherOracle([ROOT / p for p in profile['snapshot_dirs']],
                                            ROOT / profile['runtime_path'],
                                            run_dir / 'new-pages' if profile['snapshot_dirs'] else None,
                                            process['pid'])
            capture = (NativeCapture if self.capture_backend == 'npcap' else Capture)(endpoint, interface, run_dir)
            self.world.reset(session_id)
            self.inventory.reset(session_id)
            self.skills.reset(session_id)
            self.skill_menu.reset(session_id)
            self.buffs.reset(session_id)
            self.character.reset(session_id)
            inventory_opener = AutoInventoryOpen()
            list_jobs = {name:dict(state='waiting', attempts=0) for name in ('inventory','skills')}
            self.skill_refresh_requested.clear()
            self.update(state='synchronizing', message='Синхронизация ключей и словаря', process=process,
                        active_source='network',capture_backend=self.capture_backend,
                        protocol='classic-h5' if classic_profile else 'asterios-448',
                        inventory_auto_open=dict(state='waiting', attempts=0, error=None),
                        profile=profile['id'], profile_supported=True, detected_cipher=None, last_verified=None, verification=None,
                        actions_supported=not bool(classic_profile),
                        skill_actions_supported=not bool(classic_profile) or bool(classic_profile.get('skill_requests')),
                        endpoint=endpoint, interface=interface, session_id=session_id,
                        log_directory=str(run_dir), last_error=None)
            if self.stop_event.wait(3):
                return
            before = live.snapshot()
            cursors = None
            if classic_profile and classic_profile.get('list_requests'):
                clear_client_anchors(process, endpoint)
                result = request_list(self.status(), classic_profile, 0x50)
                list_jobs['skills'].update(state='requested', attempts=1, before_revision=0,
                                          deadline=time.monotonic()+20, call_thread=result['thread'])
                menu = classic_profile.get('skill_requests', {}).get('community_menu')
                if menu:
                    request_skill_menu(self.status(), classic_profile, menu['root'])
            while not self.stop_event.wait(self.interval):
                if capture.process.poll() is not None:
                    raise ValueError('Захват завершён: ' + ' '.join(capture.diagnostics)[-1000:])
                current, current_endpoint = select_process(process['pid'])
                if current['create_time'] != process['create_time'] or current_endpoint != endpoint:
                    raise ValueError('Игровое соединение изменилось; повторное подключение монитора')
                after = live.snapshot()
                advance_checkpoint = True
                if self.stop_event.wait(1.2):
                    return
                try:
                    for attempt in range(4):
                        try:
                            if classic_profile:
                                packets, verification = decode_classic_window(capture.read_rows(), before, after,
                                    endpoint, self.catalog, session_id, cursors,
                                    client_anchors=client_anchors(process, endpoint))
                            else:
                                packets, verification = decode_window(capture.read_rows(), before, after, oracle,
                                    endpoint['remote_ip'], self.catalog, session_id, self.options['cipher'], cursors)
                            break
                        except ValueError:
                            if attempt == 3:
                                raise
                            if self.stop_event.wait(0.4):
                                return
                    cursors = verification['wire_cursors']
                    self.world.apply(packets)
                    self.inventory.apply(packets)
                    self.skills.apply(packets)
                    self.skill_menu.apply(packets)
                    self.buffs.apply(packets)
                    self.character.apply(packets)
                    self.store.add(packets)
                    self.library.observe(packets, f"{endpoint['remote_ip']}:{endpoint['remote_port']}", profile['id'])
                    for packet in packets:
                        log.info(json.dumps(packet, ensure_ascii=False))
                    with self.lock:
                        self.state['validated_windows'] += 1
                        self.state['compressed_blocks'] += verification['compressed_blocks']
                        self.state['expanded_bytes'] += verification['expanded_bytes']
                    self.update(state='live', message=('Расшифровка работает; ключи обоих направлений проверены'
                                                      if classic_profile else 'Ключи и словарь проверены'), last_error=None,
                                last_verified=datetime.now(timezone.utc).isoformat(),
                                verification=verification, captured_frames=capture.received,
                                detected_cipher=verification['cipher'])
                except (ValueError, IndexError, RuntimeError) as error:
                    waiting = (bool(classic_profile) and str(error).startswith('Waiting')
                               and time.time_ns()-before['read_end_ns'] < 20_000_000_000)
                    if waiting:
                        advance_checkpoint = False
                    else:
                        cursors = None
                        self.world.gap()
                        self.inventory.gap()
                        self.skills.gap()
                        self.skill_menu.gap()
                        self.buffs.gap()
                        self.character.gap()
                        if classic_profile:
                            list_jobs = {name:dict(state='waiting', attempts=0) for name in ('inventory','skills')}
                            menu = classic_profile.get('skill_requests', {}).get('community_menu')
                            if menu:
                                request_skill_menu(self.status(), classic_profile, menu['root'])
                    with self.lock:
                        if waiting:
                            self.state['capture_waits'] = self.state.get('capture_waits', 0) + 1
                        else:
                            self.state['sync_errors'] += 1
                            recent = self.state.setdefault('recent_errors', [])
                            recent.append(dict(time=datetime.now(timezone.utc).isoformat(), message=str(error)))
                            del recent[:-8]
                    self.update(state='synchronizing', message='Повторная синхронизация: ' + str(error),
                                last_error=str(error), captured_frames=capture.received)
                if advance_checkpoint:
                    before = after
                capture.trim(before['read_start_ns'])
                if self.state['state'] == 'live' and not self.stop_event.is_set():
                    if classic_profile and classic_profile.get('list_requests'):
                        if self.skill_refresh_requested.is_set():
                            list_jobs['skills'] = dict(state='waiting', attempts=0)
                            self.skill_refresh_requested.clear()
                        for name, opcode, observed, enabled in (
                                ('inventory',0x14,self.inventory.snapshot(),self.auto_inventory_enabled),
                                ('skills',0x50,self.skills.snapshot(),True)):
                            job = list_jobs[name]
                            if (observed['full_list_received'] and not observed['coverage_gap'] and job['state'] == 'requested'
                                    and observed['revision'] > job.get('before_revision', -1)):
                                job['state'] = 'received'
                            elif job['state'] == 'requested' and time.monotonic() > job['deadline']:
                                job.update(state='failed', error='Сервер не подтвердил полный список')
                            elif enabled and job['state'] == 'waiting':
                                try:
                                    result = request_list(self.status(), classic_profile, opcode)
                                    job.update(state='requested', attempts=job['attempts']+1,
                                               deadline=time.monotonic()+20, call_thread=result['thread'],
                                               before_revision=observed['revision'])
                                except Exception as error:
                                    job.update(state='failed', error=str(error))
                        self.update(inventory_auto_open=dict(list_jobs['inventory']),
                                    list_requests={key:dict(value) for key,value in list_jobs.items()})
                    else:
                        self.update(inventory_auto_open=inventory_opener.tick(
                            process['pid'], self.inventory.snapshot(), self.auto_inventory_enabled))
        finally:
            if capture:
                capture.close()
            if oracle:
                oracle.close()
            if live:
                live.close()
            handler.close()
            log.removeHandler(handler)
