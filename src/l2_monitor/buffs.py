"""NPC support-buff batches, with separate dispatch and server confirmation counts."""
import collections
import math
import re
import threading
import time
from datetime import datetime

from .live_state import load_profile
from .queue_runner import queue_active


def support_dialog(fields, profile):
    html = fields.get('html', '')
    command = re.escape(profile['command'])
    return (fields.get('event') == 'npc_html' and profile['html_title'] in html
            and profile['html_link'] in html
            and bool(re.search(r'action=[\'\"]bypass\s+-h\s+' + command + r'[\'\"]', html)))


class Buffs:
    def __init__(self):
        self.lock = threading.RLock()
        self.profile = load_profile()['npc_buffs']
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id = session_id
            self.items = []
            self.full_list_received = self.coverage_gap = False
            self.npc_id = self.profile['object_id']
            self.npc_position = list(self.profile['xyz'])
            self.positions = collections.OrderedDict()

    def gap(self):
        with self.lock:
            self.coverage_gap = True

    def apply(self, packets):
        with self.lock:
            for packet in packets:
                if packet.get('direction') != 'server':
                    continue
                fields = packet.get('fields') or {}
                event = fields.get('event')
                if event == 'npc_info':
                    self.positions[fields['object_id']] = fields['xyz']
                    while len(self.positions) > 1000:
                        self.positions.popitem(last=False)
                elif support_dialog(fields, self.profile):
                    if fields['object_id'] != self.npc_id:
                        self.npc_id = fields['object_id']
                        self.npc_position = self.positions.get(self.npc_id)
                elif event == 'skill_use' and fields.get('caster_id') == self.npc_id and fields.get('skill_id') in self.profile['skills']:
                    self.npc_position = fields['xyz']
                elif event == 'buff_list':
                    observed = datetime.fromisoformat(packet['time']).timestamp() if packet.get('time') else time.time()
                    self.items = [dict(row, expires_at=None if row['remaining_seconds'] < 0 else observed + row['remaining_seconds'])
                                  for row in fields['buffs']]
                    self.full_list_received, self.coverage_gap = True, False

    def snapshot(self):
        with self.lock:
            now = time.time()
            rows = [dict(row, remaining_seconds=None if row['expires_at'] is None else max(0, math.ceil(row['expires_at'] - now)))
                    for row in self.items]
            return dict(buffs=rows, session_id=self.session_id, full_list_received=self.full_list_received,
                        coverage_gap=self.coverage_gap, npc_object_id=self.npc_id,
                        npc_position=self.npc_position, npc_name=self.profile['name'])


class NewbieBuffBatch:
    def __init__(self, monitor, transport, confirmation_timeout=25):
        self.monitor, self.transport = monitor, transport
        self.confirmation_timeout = confirmation_timeout
        self.profile = load_profile()['npc_buffs']
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.thread = None
        self.job = None
        self.history = collections.deque(maxlen=30)

    def snapshot(self):
        with self.lock:
            return dict(active=bool(self.job), job=dict(self.job) if self.job else None,
                        history=[dict(job) for job in self.history])

    def start(self, count):
        if type(count) is not int or not 1 <= count <= 1000:
            raise ValueError('Количество повторов: от 1 до 1000')
        status, buffs = self.monitor.status(), self.monitor.buffs.snapshot()
        if queue_active(self.monitor):
            raise ValueError('Дождитесь завершения очереди пакетов')
        if not status.get('running') or status.get('state') != 'live' or status.get('actions_supported') is False:
            raise ValueError('Дождитесь синхронизации захвата')
        if status.get('session_id') != buffs['session_id'] or not buffs['npc_position']:
            raise ValueError('Откройте Newbie Guide и получите бафы один раз')
        if (self.monitor.inventory_drop.snapshot()['active'] or self.monitor.skill_actions.snapshot()['active']
            or self.monitor.auto_pickup.snapshot()['pending']):
            raise ValueError('Дождитесь завершения текущего действия')
        with self.lock:
            if self.job:
                raise ValueError('Newbie Buff уже выполняется')
            self.job = dict(count=count, sent=0, requests_seen=0, confirmed=0, state='opening', error=None,
                            npc_object_id=buffs['npc_object_id'], npc_position=buffs['npc_position'],
                            session_id=status['session_id'])
            self.thread = threading.Thread(target=self._run, args=(self.job,), daemon=True)
            self.thread.start()

    def close(self):
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=9)

    def _status(self, job):
        status = self.monitor.status()
        if self.closed.is_set() or self.monitor.stop_event.is_set() or not status.get('running'):
            raise ValueError('Захват остановлен')
        if status.get('session_id') != job['session_id']:
            raise ValueError('Игровое подключение изменилось')
        reader = getattr(self.monitor, 'auto_heal', None)
        health = reader.snapshot()['health'] if reader else None
        if health and health['hp'] <= 0:
            raise ValueError('Персонаж погиб')
        return status

    def _execute(self, job):
        status = self._status(job)
        reader = getattr(self.monitor, 'auto_heal', None)
        if reader:
            job['own_object_id'] = reader.reader.read(status)['object_id']
        settling = time.monotonic() + self.confirmation_timeout
        while self.monitor.skill_actions.snapshot().get('state') == 'refreshing':
            self._status(job)
            if time.monotonic() >= settling:
                raise ValueError('Дождитесь обновления списка скиллов')
            self.closed.wait(.1)
        cursor = self.monitor.store.stats()['total']
        native = self.transport.pickup(status, job['npc_object_id'], job['npc_position'], 300)
        if not native['sent']:
            raise ValueError('Подойдите к Newbie Guide ближе (до 300 единиц)')
        deadline, dialog_seen = time.monotonic() + self.confirmation_timeout, False
        while time.monotonic() < deadline and not dialog_seen:
            self._status(job)
            result = self.monitor.store.query(after=cursor, limit=1000)
            if result.get('history_truncated'):
                raise ValueError('История диалога NPC потеряна')
            for packet in result['packets']:
                fields = packet.get('fields') or {}
                if packet['direction'] == 'client' and fields.get('event') == 'action' and fields.get('object_id') != job['npc_object_id']:
                    raise ValueError('Цель изменена во время открытия NPC')
                if packet['direction'] == 'server' and fields.get('event') == 'npc_html':
                    if fields.get('object_id') != job['npc_object_id'] or not support_dialog(fields, self.profile):
                        raise ValueError('NPC вернул другое меню')
                    dialog_seen = True
            cursor = result['cursor']
            if not dialog_seen:
                self.closed.wait(.1)
        if not dialog_seen:
            raise ValueError('Сервер не подтвердил меню Newbie Guide')
        status = self._status(job)
        with self.lock:
            job['state'] = 'sending'
        cursor = self.monitor.store.stats()['total']
        native = self.transport.newbie_buff(status, job['count'])
        with self.lock:
            job.update(sent=native['sent'], state='confirming')
        deadline, cast_skills = time.monotonic() + self.confirmation_timeout, set()
        cast_bundles, effects_seen = 0, False
        expected = set(self.profile['skills'])
        while time.monotonic() < deadline:
            self._status(job)
            result = self.monitor.store.query(after=cursor, limit=1000)
            if result.get('history_truncated'):
                raise ValueError('История подтверждения бафов потеряна')
            for packet in result['packets']:
                fields = packet.get('fields') or {}
                if packet['direction'] == 'client' and fields.get('event') == 'bypass_request' and fields.get('command') == self.profile['command']:
                    with self.lock:
                        job['requests_seen'] += 1
                if (packet['direction'] == 'server' and fields.get('event') == 'skill_use'
                    and fields.get('caster_id') == job['npc_object_id'] and fields.get('skill_id') in expected
                    and (job.get('own_object_id') is None or fields.get('target_id') == job['own_object_id'])):
                    cast_skills.add(fields['skill_id'])
                    if expected <= cast_skills:
                        cast_bundles += 1
                        cast_skills.clear()
                if packet['direction'] == 'server' and fields.get('event') == 'buff_list':
                    active = {row['skill_id'] for row in fields['buffs'] if row['skill_level'] >= self.profile['level'] and row['remaining_seconds'] != 0}
                    if expected <= active:
                        effects_seen = True
                if effects_seen:
                    with self.lock:
                        job['confirmed'] = min(cast_bundles, job['requests_seen'], job['count'])
            cursor = result['cursor']
            if job['requests_seen'] >= job['count'] and job['confirmed'] >= job['count']:
                return
            self.closed.wait(.1)
        raise ValueError(f"Отправлено: {job['sent']}. Запросов в захвате: {job['requests_seen']}. Подтверждено сервером: {job['confirmed']} из {job['count']}")

    def _run(self, job):
        try:
            self._execute(job)
            job['state'] = 'completed'
        except Exception as error:
            job.update(state='partial' if job['confirmed'] else 'failed', error=str(error))
        finally:
            with self.lock:
                self.history.append(dict(job))
                self.job = None
