"""Queue execution with whole-queue validation, repeats and interruptible delays."""
import threading
import time

from .sender import NativeSender


def queue_active(monitor):
    runner = getattr(monitor, 'packet_queue_runner', None)
    sender = getattr(monitor, 'sender', None)
    return bool((runner and runner.snapshot()['active']) or (sender and sender.pending))


class QueueRunner:
    def __init__(self, monitor, queue, sender=None):
        self.monitor, self.queue = monitor, queue
        self.sender = sender or NativeSender(monitor)
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.thread = None
        self.state, self.error = 'idle', None
        self.completed = self.total = self.position = self.cycle = 0
        self.paused = False

    def snapshot(self):
        with self.lock:
            return dict(state=self.state, error=self.error, completed=self.completed, total=self.total,
                        position=self.position, cycle=self.cycle, paused=self.paused,
                        active=bool(self.thread and self.thread.is_alive()))

    def start(self, repeats=1, interval_ms=250):
        if type(repeats) is not int or not 1 <= repeats <= 10000 or type(interval_ms) is not int or not 0 <= interval_ms <= 60000:
            raise ValueError('Некорректное число циклов или интервал')
        rows = self.queue.items()
        if not rows:
            raise ValueError('Очередь пуста')
        packets = self._prepare(rows)
        if not self.sender.status()['available']:
            raise ValueError(self.sender.status()['reason'])
        if self.sender.status().get('pending'):
            raise ValueError('Предыдущая отправка ещё выполняется')
        for name in ('inventory_drop', 'auto_pickup', 'skill_actions', 'newbie_buff'):
            activity = getattr(self.monitor, name).snapshot()
            if activity.get('active') or activity.get('pending'):
                raise ValueError('Дождитесь завершения текущего действия клиента')
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('Очередь уже выполняется')
            self.cancel = threading.Event()
            self.paused, self.state, self.error = False, 'running', None
            self.completed, self.total = 0, len(packets) * repeats
            self.position = self.cycle = 0
            status = self.monitor.status()
            session = (status.get('session_id'), status.get('sync_errors', 0))
            self.thread = threading.Thread(target=self._run, args=(packets, repeats, interval_ms, session), daemon=True)
            self.thread.start()

    def _prepare(self, rows):
        packets = []
        for index, row in enumerate(rows):
            try:
                raw = bytes.fromhex(row['raw_hex'])
                self.sender.prepare(raw, row)
            except (ValueError, UnicodeError) as error:
                raise ValueError(f'Строка {index + 1}: {error}') from error
            packets.append((raw, row))
        return packets

    def validation_error(self, rows=None):
        try:
            self._prepare(self.queue.items() if rows is None else rows)
        except (ValueError, UnicodeError) as error:
            return str(error)
        return None

    def pause(self, paused):
        with self.lock:
            if self.thread and self.thread.is_alive() and self.state in ('running', 'paused'):
                self.paused = bool(paused)
                self.state = 'paused' if paused else 'running'

    def stop(self):
        self.cancel.set()

    def close(self):
        self.stop()
        if self.thread:
            self.thread.join(timeout=9)

    def _wait(self, seconds, session):
        remaining = seconds
        while True:
            status = self.monitor.status()
            if self.cancel.is_set():
                raise InterruptedError('Очередь остановлена')
            if not status.get('running') or status.get('state') != 'live' or (status.get('session_id'), status.get('sync_errors', 0)) != session:
                raise RuntimeError('Игровое подключение изменилось; очередь остановлена')
            if not self.paused and remaining <= 0:
                return
            start = time.monotonic()
            self.cancel.wait(min(.05, remaining) if remaining > 0 and not self.paused else .05)
            if not self.paused:
                remaining -= time.monotonic() - start

    def _run(self, packets, repeats, interval_ms, session):
        try:
            for cycle in range(repeats):
                for position, (raw, row) in enumerate(packets):
                    self._wait(interval_ms / 1000 if self.completed else 0, session)
                    with self.lock:
                        self.cycle, self.position = cycle + 1, position + 1
                    self.sender.send(raw, row, self.cancel)
                    with self.lock:
                        self.completed += 1
            with self.lock:
                self.state = 'completed'
        except InterruptedError:
            with self.lock:
                self.state = 'stopped'
        except Exception as error:
            with self.lock:
                self.state, self.error = 'failed', str(error)
