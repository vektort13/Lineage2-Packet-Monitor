"""Owned skills and ordinary client learning, confirmed by server SkillList."""
import collections
import threading
import time
from .queue_runner import queue_active


_UNSUPPORTED_LEARNING = 'Обучение скиллов для этой сборки клиента пока не подключено'


def _skill_actions_supported(status):
    return status.get('skill_actions_supported', status.get('actions_supported') is not False)


class Skills:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id = session_id
            self.items = {}
            self.full_list_received = self.coverage_gap = False
            self.revision = 0

    def gap(self):
        with self.lock:
            self.coverage_gap = True

    def apply(self, packets):
        with self.lock:
            for packet in packets:
                fields = packet.get('fields') or {}
                if packet.get('direction') != 'server' or fields.get('event') != 'skill_list':
                    continue
                self.items = {row['skill_id']: dict(row, last_time=packet.get('time')) for row in fields['skills']}
                self.full_list_received, self.coverage_gap = True, False
                self.revision += 1

    def snapshot(self):
        with self.lock:
            return dict(skills=[dict(row) for _, row in sorted(self.items.items())], session_id=self.session_id,
                        full_list_received=self.full_list_received, coverage_gap=self.coverage_gap, revision=self.revision)


class SkillActions:
    def __init__(self, monitor, transport, confirmation_timeout=30):
        self.monitor, self.transport = monitor, transport
        self.confirmation_timeout = confirmation_timeout
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.thread = None
        self.job = None
        self.history = collections.deque(maxlen=30)
        self.refresh_pending = False
        self.next_refresh = 0
        self.session = None
        self.state, self.error = 'waiting', None

    def start(self):
        with self.lock:
            if not self.thread:
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

    def close(self):
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=9)

    def snapshot(self):
        with self.lock:
            return dict(active=bool(self.job), state=self.state, error=self.error,
                        job=dict(self.job) if self.job else None, history=[dict(row) for row in self.history])

    def refresh(self):
        status = self.monitor.status()
        if not status.get('running') or status.get('state') != 'live':
            raise ValueError('Дождитесь синхронизации захвата')
        if not _skill_actions_supported(status):
            raise ValueError(_UNSUPPORTED_LEARNING)
        with self.lock:
            self.refresh_pending = True
        self.start()

    def learn(self, skill_id, level):
        if type(skill_id) is not int or type(level) is not int or not 0 < skill_id <= 0x7fffffff or not 0 < level <= 0x7fffffff:
            raise ValueError('Введите положительный целый уровень скилла')
        status, skills = self.monitor.status(), self.monitor.skills.snapshot()
        if not status.get('running') or status.get('state') != 'live':
            raise ValueError('Дождитесь синхронизации захвата')
        if not _skill_actions_supported(status):
            raise ValueError(_UNSUPPORTED_LEARNING)
        if skills['session_id'] != status.get('session_id') or not skills['full_list_received'] or skills['coverage_gap']:
            raise ValueError('Сначала обновите список скиллов')
        item = next((row for row in skills['skills'] if row['skill_id'] == skill_id), None)
        before = item['skill_level'] if item else 0
        if level <= before:
            raise ValueError('Новый уровень должен быть выше текущего')
        with self.lock:
            if self.job:
                raise ValueError('Дождитесь завершения обучения')
            self.job = dict(skill_id=skill_id, level=level, before=before, actual=before,
                            step=before + 1,
                            session_id=status['session_id'], state='queued', error=None)
            self.state, self.error = 'queued', None
        self.start()

    def _finish(self, state, error=None):
        with self.lock:
            self.job.update(state=state, error=error)
            self.history.append(dict(self.job))
            self.job = None
            self.state, self.error = state, error

    def tick(self):
        stopping = getattr(self.monitor, 'stop_event', None)
        if stopping and stopping.is_set():
            if self.job:
                self._finish('failed', 'Захват остановлен')
            return
        status, skills = self.monitor.status(), self.monitor.skills.snapshot()
        if self.session != status.get('session_id'):
            if self.job and self.job['session_id'] != status.get('session_id'):
                self._finish('failed', 'Игровое подключение изменилось')
            self.session = status.get('session_id')
            self.next_refresh = 0
        if not status.get('running') or status.get('state') != 'live':
            if self.job:
                self._finish('failed', 'Захват остановлен' if not status.get('running') or status.get('state') == 'stopped'
                             else 'Синхронизация захвата потеряна')
            return
        if not _skill_actions_supported(status):
            if self.job:
                self._finish('failed', _UNSUPPORTED_LEARNING)
            elif self.state != 'failed':
                self.state, self.error = 'unsupported', _UNSUPPORTED_LEARNING
            self.refresh_pending = False
            return
        with self.lock:
            job = self.job
        if queue_active(self.monitor):
            return
        if not job and getattr(self.monitor, 'newbie_buff', None) and self.monitor.newbie_buff.snapshot()['active']:
            return
        now = time.monotonic()
        if job:
            if job['state'] == 'queued':
                if getattr(self.monitor, 'newbie_buff', None) and self.monitor.newbie_buff.snapshot()['active']:
                    return
                if self.monitor.inventory_drop.snapshot()['active'] or self.monitor.auto_pickup.snapshot()['pending']:
                    return
                job.update(cursor=self.monitor.store.stats()['total'], request_seen=False,
                           deadline=now + self.confirmation_timeout, refresh_at=now + 1, state='confirming')
                self.state, self.error = 'confirming', None
                self.transport.skill(status, 'learn', job['skill_id'], job['step'], 0)
                dispatched = time.monotonic()
                job.update(deadline=dispatched + self.confirmation_timeout, refresh_at=dispatched + 1)
                return
            result = self.monitor.store.query(after=job['cursor'], limit=1000)
            for packet in result['packets']:
                fields = packet.get('fields') or {}
                if (packet['direction'] == 'client' and fields.get('event') == 'skill_learn_request'
                    and fields.get('skill_id') == job['skill_id'] and fields.get('skill_level') == job['step']
                    and fields.get('list_type') == 0):
                    job['request_seen'] = True
                if packet['direction'] == 'server' and fields.get('event') == 'skill_list' and job['request_seen']:
                    actual = next((row['skill_level'] for row in fields['skills'] if row['skill_id'] == job['skill_id']), 0)
                    job['actual'] = actual
                    if actual == job['level']:
                        self._finish('completed')
                        return
                    if actual == job['step'] and actual < job['level']:
                        job.update(step=actual + 1, state='queued')
                        return
            job['cursor'] = result['cursor']
            if result.get('history_truncated') or now >= job['deadline']:
                self._finish('failed', f"Сервер не подтвердил уровень {job['level']}. Текущий уровень: {job['actual']}")
            elif job.get('refresh_at') and now >= job['refresh_at']:
                job['refresh_at'] = None
                self.transport.skill(status, 'list')
            return
        if self.refresh_pending or ((not skills['full_list_received'] or skills['coverage_gap']) and now >= self.next_refresh):
            self.refresh_pending = False
            self.next_refresh = now + 20
            self.state, self.error = 'refreshing', None
            self.transport.skill(status, 'list')
        elif skills['full_list_received'] and self.state in ('waiting', 'refreshing', 'unsupported'):
            self.state, self.error = 'ready', None

    def _run(self):
        while not self.closed.is_set():
            try:
                self.tick()
            except Exception as error:
                if self.job:
                    self._finish('failed', str(error))
                else:
                    self.state, self.error = 'failed', str(error)
                    self.next_refresh = time.monotonic() + 30
            self.closed.wait(.2)
