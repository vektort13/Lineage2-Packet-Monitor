"""Ordered inventory drops, advancing only after the server confirms each step."""
import collections
import math
import threading
import time

from .inventory_drop import NativeInventoryDrop
from .queue_runner import queue_active


class InventoryDropQueue:
    def __init__(self, monitor, transport=None, confirmation_timeout=25):
        self.monitor = monitor
        self.transport = transport or NativeInventoryDrop()
        self.confirmation_timeout = confirmation_timeout
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.closed = threading.Event()
        self.thread = None
        self.jobs = collections.deque()
        self.history = collections.deque(maxlen=100)
        self.current = None
        self.generation = 0
        self.sequence = 0
        self.paused = False

    def _inventory(self, session):
        status = self.monitor.status()
        inventory = self.monitor.inventory.snapshot()
        if status.get('state') != 'live' or not status.get('running'):
            raise ValueError('Дождитесь синхронизации захвата')
        if status.get('session_id') != session or inventory.get('session_id') != session:
            raise ValueError('Игровое подключение изменилось')
        if not inventory.get('full_list_received') or inventory.get('coverage_gap'):
            raise ValueError('Нужен актуальный полный список инвентаря')
        return status, inventory

    def enqueue(self, object_id, amount, mode='single', interval_ms=500):
        if type(object_id) is not int or type(amount) is not int or not 0 < object_id <= 0xffffffff or not 0 < amount <= 0x7fffffffffffffff:
            raise ValueError('Введите положительное количество предметов')
        if mode not in ('single', 'bulk') or type(interval_ms) is not int or not 100 <= interval_ms <= 30000:
            raise ValueError('Неверный режим или интервал выброса')
        session = self.monitor.status().get('session_id')
        _, inventory = self._inventory(session)
        item = next((row for row in inventory['items'] if row['object_id'] == object_id), None)
        if not item:
            raise ValueError('Предмета больше нет в инвентаре')
        with self.lock:
            if self.closed.is_set():
                raise ValueError('Очередь остановлена')
            reserved = sum(job['amount'] - job['dropped'] for job in [self.current, *self.jobs]
                           if job and job['object_id'] == object_id and job['generation'] == self.generation)
            if amount > item['amount'] - reserved:
                raise ValueError('Количество превышает доступный остаток с учётом очереди')
            self.sequence += 1
            job = dict(id=self.sequence, object_id=object_id, item_id=item['item_id'], amount=amount,
                       dropped=0, mode=mode, interval_ms=interval_ms, state='queued', error=None,
                       session_id=session, generation=self.generation, destination=None)
            self.jobs.append(job)
            if not self.thread:
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()
            self.wake.set()
            return self.sequence

    def pause(self, paused=True):
        with self.lock:
            self.paused = bool(paused)
        self.wake.set()

    def stop(self):
        with self.lock:
            self.generation += 1
            while self.jobs:
                job = self.jobs.popleft()
                job['state'] = 'stopped'
                self.history.append(job)
            self.paused = False
        self.wake.set()

    def close(self):
        self.stop()
        self.closed.set()
        self.wake.set()
        if self.thread:
            self.thread.join(timeout=9)

    def snapshot(self):
        with self.lock:
            jobs = [*self.history, *([self.current] if self.current else []), *self.jobs]
            return dict(paused=self.paused, active=bool(self.current or self.jobs),
                        stopping=bool(self.current and self.current['generation'] != self.generation),
                        jobs=[{key: value for key, value in job.items() if key != 'generation'} for job in jobs])

    def _cancelled(self, job):
        with self.lock:
            return self.closed.is_set() or job['generation'] != self.generation

    def _wait_to_send(self, job):
        while not self._cancelled(job):
            with self.lock:
                paused = self.paused
            pickup = getattr(self.monitor, 'auto_pickup', None)
            buffs = getattr(self.monitor, 'newbie_buff', None)
            if not paused and not queue_active(self.monitor) and not (pickup and pickup.snapshot()['pending']) and not (buffs and buffs.snapshot()['active']):
                return True
            self.wake.wait(.1)
            self.wake.clear()
        return False

    def _confirm(self, job, step, before, cursor, destination):
        deadline = time.monotonic() + self.confirmation_timeout
        request_seen = ground_seen = False
        server_message = None
        while time.monotonic() < deadline and not self.closed.is_set():
            _, inventory = self._inventory(job['session_id'])
            result = self.monitor.store.query(after=cursor, limit=1000)
            if result.get('history_truncated'):
                raise ValueError('История подтверждения выброса потеряна')
            for packet in result['packets']:
                fields = packet.get('fields') or {}
                if packet['direction'] == 'client' and fields.get('event') == 'drop_request':
                    request_seen |= fields.get('object_id') == job['object_id'] and fields.get('amount') == step
                if packet['direction'] == 'server' and fields.get('event') in ('drop_item', 'spawn_item'):
                    xyz = fields.get('xyz', [])
                    ground_seen |= (fields.get('template_value') == job['item_id'] and fields.get('amount') == step
                                    and len(xyz) == 3 and math.dist(xyz, destination) < 100)
                if packet['direction'] == 'server' and fields.get('event') == 'system_message':
                    server_message = fields.get('message_id')
            cursor = result['cursor']
            current = next((row['amount'] for row in inventory['items'] if row['object_id'] == job['object_id']), 0)
            if request_seen and ground_seen and current == before - step:
                return
            if current != before and current != before - step:
                raise ValueError('Остаток предмета изменился во время выброса')
            self.closed.wait(.1)
        suffix = f' (сообщение сервера: {server_message})' if server_message is not None else ''
        raise ValueError('Сервер не подтвердил выброс; повтор отменён' + suffix)

    def _execute(self, job):
        while job['dropped'] < job['amount']:
            if not self._wait_to_send(job):
                break
            status, inventory = self._inventory(job['session_id'])
            item = next((row for row in inventory['items'] if row['object_id'] == job['object_id']), None)
            step = 1 if job['mode'] == 'single' else job['amount'] - job['dropped']
            if not item or item['item_id'] != job['item_id'] or item['amount'] < step:
                raise ValueError('Выбранного количества больше нет в инвентаре')
            cursor = self.monitor.store.stats()['total']
            with self.lock:
                job['state'] = 'sending'
            if self._cancelled(job):
                break
            native = self.transport.send(status, job['object_id'], step)
            with self.lock:
                job['destination'] = native['destination']
                job['state'] = 'confirming'
            self._confirm(job, step, item['amount'], cursor, native['destination'])
            with self.lock:
                job['dropped'] += step
                job['state'] = 'running'
            deadline = time.monotonic() + job['interval_ms'] / 1000
            while not self._cancelled(job) and time.monotonic() < deadline:
                self.closed.wait(min(.1, max(0, deadline - time.monotonic())))
        with self.lock:
            job['state'] = 'completed' if job['dropped'] == job['amount'] else 'stopped'

    def _run(self):
        while not self.closed.is_set():
            with self.lock:
                job = self.jobs.popleft() if self.jobs and not self.paused else None
                self.current = job
            if not job:
                self.wake.wait(.2)
                self.wake.clear()
                continue
            try:
                self._execute(job)
            except Exception as error:
                with self.lock:
                    job['state'], job['error'] = 'failed', str(error)
                self.stop()
            finally:
                with self.lock:
                    self.history.append(job)
                    self.current = None
