"""Optional nearby-item pickup through ordinary client actions."""
import math
import threading
import time
from .queue_runner import queue_active


class AutoPickup:
    def __init__(self, monitor, transport, confirmation_timeout=25):
        self.monitor, self.transport = monitor, transport
        self.confirmation_timeout = confirmation_timeout
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.thread = None
        self.enabled = False
        self.radius, self.interval_ms = 200, 750
        self.pending = None
        self.cooldowns = {}
        self.next_action = 0
        self.session = None
        self.position = None
        self.picked_items = self.picked_amount = self.attempts = self.failures = 0
        self.state, self.last_error = 'disabled', None
        self.blocked = False

    def configure(self, enabled, radius=200, interval_ms=750):
        if type(enabled) is not bool or type(radius) is not int or not 50 <= radius <= 1500:
            raise ValueError('Неверный радиус автоподбора')
        if type(interval_ms) is not int or not 250 <= interval_ms <= 30000:
            raise ValueError('Неверная пауза автоподбора')
        with self.lock:
            if enabled != self.enabled:
                self.blocked = False
                self.last_error = None
            self.enabled, self.radius, self.interval_ms = enabled, radius, interval_ms
            if enabled and not self.thread:
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

    def close(self):
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=9)

    def snapshot(self):
        with self.lock:
            return dict(enabled=self.enabled, radius=self.radius, interval_ms=self.interval_ms,
                        pending=bool(self.pending), target=self.pending['object_id'] if self.pending else None,
                        picked_items=self.picked_items, picked_amount=self.picked_amount,
                        attempts=self.attempts, failures=self.failures, state=self.state,
                        last_error=self.last_error, position=self.position)

    @staticmethod
    def _total(inventory, item_id):
        return sum(item['amount'] for item in inventory['items'] if item['item_id'] == item_id)

    def _poll_pending(self, inventory):
        pending = self.pending
        result = self.monitor.store.query(after=pending['cursor'], limit=1000)
        for packet in result['packets']:
            fields = packet.get('fields') or {}
            if packet['direction'] == 'client' and fields.get('event') == 'action' and fields.get('object_id') == pending['object_id']:
                pending['request_seen'] = True
            if packet['direction'] == 'server' and fields.get('event') in ('get_item', 'delete_object') and fields.get('object_id') == pending['object_id']:
                pending['pickup_seen'] = True
        pending['cursor'] = result['cursor']
        confirmed = (pending['request_seen'] and pending['pickup_seen'] and
                     self._total(inventory, pending['item_id']) >= pending['before'] + pending['amount'])
        if confirmed:
            with self.lock:
                self.picked_items += 1
                self.picked_amount += pending['amount']
                self.pending = None
                self.state, self.last_error = 'watching', None
                self.next_action = time.monotonic() + self.interval_ms / 1000
        elif time.monotonic() >= pending['deadline'] or result.get('history_truncated'):
            with self.lock:
                self.failures += 1
                self.cooldowns[pending['object_id']] = time.monotonic() + 15
                self.pending = None
                self.state = 'watching'
                self.last_error = 'Сервер не подтвердил подбор предмета'

    def tick(self):
        status = self.monitor.status()
        inventory = self.monitor.inventory.snapshot()
        with self.lock:
            enabled, radius = self.enabled, self.radius
        if status.get('session_id') != self.session:
            with self.lock:
                self.session = status.get('session_id')
                self.pending = None
                self.cooldowns.clear()
                self.position = None
                self.blocked = False
        if status.get('state') != 'live' or not status.get('running') or status.get('actions_supported') is False:
            with self.lock:
                self.state = 'waiting' if enabled else 'disabled'
                self.pending = None
            return
        if self.pending:
            self._poll_pending(inventory)
            return
        if not enabled:
            with self.lock:
                self.state = 'disabled'
            return
        if self.blocked:
            return
        if not inventory.get('full_list_received') or inventory.get('coverage_gap'):
            with self.lock:
                self.state = 'waiting'
            return
        if queue_active(self.monitor) or self.monitor.inventory_drop.snapshot()['active']:
            with self.lock:
                self.state = 'dropping'
            return
        if getattr(self.monitor, 'skill_actions', None) and self.monitor.skill_actions.snapshot()['active']:
            with self.lock:
                self.state = 'learning'
            return
        if getattr(self.monitor, 'newbie_buff', None) and self.monitor.newbie_buff.snapshot()['active']:
            with self.lock:
                self.state = 'buffing'
            return
        with self.lock:
            self.state = 'watching'
        if time.monotonic() < self.next_action:
            return
        world = self.monitor.world.snapshot()
        center = self.position or world.get('own_position')
        candidates = [row for row in world['items'] if row.get('state') == 'present' and row.get('amount', 0) > 0
                      and row.get('template_value') is not None and len(row.get('xyz', [])) == 3
                      and self.cooldowns.get(row['object_id'], 0) <= time.monotonic()]
        if center:
            candidates.sort(key=lambda row: math.dist(row['xyz'], center))
        if not candidates:
            return
        item = candidates[0]
        with self.lock:
            # Mark the in-flight action before dispatch so a new drop queue waits.
            if not self.enabled:
                return
            self.pending = dict(object_id=item['object_id'], item_id=item['template_value'], amount=item['amount'],
                                before=self._total(inventory, item['template_value']),
                                cursor=self.monitor.store.stats()['total'], request_seen=False, pickup_seen=False,
                                deadline=time.monotonic() + self.confirmation_timeout)
            self.state = 'confirming'
        try:
            native = self.transport.pickup(status, item['object_id'], item['xyz'], radius)
        except Exception as error:
            with self.lock:
                self.pending = None
                self.blocked = True
                self.state, self.last_error = 'failed', str(error)
            return
        with self.lock:
            self.position = native['destination']
            if native['sent']:
                self.attempts += 1
            else:
                self.pending = None
                self.cooldowns[item['object_id']] = time.monotonic() + 3
                self.state = 'watching'
            self.next_action = time.monotonic() + self.interval_ms / 1000

    def _run(self):
        while not self.closed.is_set():
            try:
                self.tick()
            except Exception as error:
                with self.lock:
                    self.pending = None
                    self.blocked = True
                    self.state, self.last_error = 'failed', str(error)
            self.closed.wait(.1)
