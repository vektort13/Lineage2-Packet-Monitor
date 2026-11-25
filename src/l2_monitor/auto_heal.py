"""Current character stats and optional selected-potion healing."""
import collections
import math
import re
import struct
import threading
import time
from datetime import datetime

from .client_data import ClientData
from .client_catalog import ClientCatalog
from .queue_runner import queue_active


def healing_potion(name):
    return bool(re.search(r'healing\s+potion|(?:elixir|potion).*life|(?:hp|health).*potion|potion.*(?:hp|health)|'
                          r'(?:зель|эликсир|банка).*(?:жизн|исцел|лечен|здоров|hp)|(?:лечеб|целеб).*зель', name, re.I))


def recovery_potion(name, resource):
    if resource == 'hp':
        return healing_potion(name)
    pattern = (r'cp.*(?:potion|elixir)|(?:potion|elixir).*cp|combat.*potion|'
               r'(?:зель|эликсир|банка).*(?:cp|цп|боев)|(?:cp|цп).*(?:зель|эликсир)' if resource == 'cp' else
               r'(?:mana|mp|mental).*?(?:potion|elixir)|(?:potion|elixir).*(?:mana|mp|mental)|'
               r'(?:зель|эликсир|банка).*(?:ман|магич|mp)|(?:ман|магич).*(?:зель|эликсир)')
    return bool(re.search(pattern, name, re.I))


class AutoHeal:
    def __init__(self, monitor, transport, reader=None, resource='hp'):
        if resource not in ('hp', 'cp', 'mp'):
            raise ValueError('Unknown recovery resource')
        self.resource = resource
        self.monitor, self.transport = monitor, transport
        self.reader = reader or ClientData(transport)
        self.catalog = getattr(self.reader, 'catalog', None) or ClientCatalog()
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.thread = None
        self.enabled, self.item_id, self.threshold = False, None, 80
        self.interval_ms = 11000
        self.health, self.names, self.potions = None, {}, []
        self.session = None
        self.active = self.blocked = False
        self.next_use = self.next_read = 0
        self.last_use = 0
        self.attempts = 0
        self.state, self.error = 'disabled', None
        self.reuse_until, self.packet_cursor = 0, 0

    def start(self):
        with self.lock:
            if not self.thread:
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

    def configure(self, enabled, item_id=None, threshold=80, interval_ms=11000):
        if type(enabled) is not bool or (item_id is not None and (type(item_id) is not int or not 0 < item_id <= 0x7fffffff)):
            raise ValueError('Выберите зелье из инвентаря')
        if type(threshold) is not int or not 1 <= threshold <= 99:
            raise ValueError('Порог восстановления: от 1 до 99%')
        if enabled and item_id is None:
            raise ValueError('Выберите зелье из инвентаря')
        if type(interval_ms) is not int or not 1000 <= interval_ms <= 3600000 or interval_ms % 1000:
            raise ValueError('Интервал применения: от 1 до 3600 секунд')
        with self.lock:
            if (enabled, item_id, threshold, interval_ms) != (self.enabled, self.item_id, self.threshold, self.interval_ms):
                if not enabled or item_id != self.item_id:
                    self.active = False
                self.blocked = False
                self.error = None
                self.next_use = self.last_use + interval_ms / 1000 if self.last_use else 0
            self.enabled, self.item_id, self.threshold = enabled, item_id, threshold
            self.interval_ms = interval_ms

    def snapshot(self):
        with self.lock:
            return dict(enabled=self.enabled, item_id=self.item_id, threshold=self.threshold, healing=self.active,
                        health=dict(self.health) if self.health else None, item_names=dict(self.names),
                        potions=[dict(row) for row in self.potions], attempts=self.attempts,
                        state=self.state, error=self.error, interval_ms=self.interval_ms,
                        resource=self.resource,
                        cooldown_seconds=max(0, math.ceil(max(self.reuse_until - time.time(), self.next_use - time.monotonic()))))

    def close(self):
        self.closed.set()
        if self.thread:
            self.thread.join(timeout=9)

    def tick(self):
        status = self.monitor.status()
        if status.get('session_id') != self.session:
            with self.lock:
                self.session = status.get('session_id')
                self.health, self.names, self.potions = None, {}, []
                self.active = self.blocked = False
                self.reuse_until = 0
                self.packet_cursor = self.monitor.store.stats()['total']
        if self.closed.is_set() or self.monitor.stop_event.is_set() or not status.get('running') or status.get('state') != 'live':
            with self.lock:
                self.state = 'waiting' if self.enabled else 'disabled'
                self.active = False
                self.health = None
            return
        inventory = self.monitor.inventory.snapshot()
        observed = self.monitor.store.query(after=self.packet_cursor, limit=1000)
        for packet in observed['packets']:
            fields = packet.get('fields') or {}
            if packet['direction'] == 'server' and fields.get('reuse_item_id') == self.item_id and 'retry_after_seconds' in fields:
                when = datetime.fromisoformat(packet['time']).timestamp() if packet.get('time') else time.time()
                self.reuse_until = when + fields['retry_after_seconds']
        self.packet_cursor = observed['cursor']
        ids = {row['item_id'] for row in inventory['items']}
        now = time.monotonic()
        if now < self.next_read:
            return
        self.next_read = now + .5
        packet_health = self.monitor.character.snapshot() if hasattr(self.monitor, 'character') else None
        packet_path = status.get('actions_supported') is False or self.resource != 'hp'
        if packet_path:
            data = dict(packet_health or {}, names={item: self.catalog.item_name(item) for item in ids})
        else:
            data = self.reader.read(status, ids)
        health = {k: v for k, v in data.items() if k != 'names'}
        health['updated_at'] = time.time()
        totals = collections.Counter()
        for row in inventory['items']:
            if recovery_potion(data['names'].get(row['item_id'], ''), self.resource):
                totals[row['item_id']] += row['amount']
        with self.lock:
            self.health, self.names = health if 'hp' in health else None, data['names']
            self.potions = [dict(item_id=item, name=data['names'][item], amount=amount) for item, amount in sorted(totals.items())]
            enabled, item_id, threshold, interval_ms = self.enabled, self.item_id, self.threshold, self.interval_ms
            current, maximum = health.get(self.resource), health.get('max_' + self.resource)
            valid = (type(current) in (int, float) and type(maximum) in (int, float)
                     and math.isfinite(current) and math.isfinite(maximum) and 0 <= current <= maximum and maximum > 0
                     and health.get('hp') is not None and health['hp'] >= 0
                     and (health.get('session_id') in (None, self.session)))
            if not valid or health['hp'] <= 0 or current >= maximum:
                self.active = False
            elif enabled and 100 * current / maximum < threshold:
                self.active = True
            if not enabled:
                self.state = 'disabled'
                self.active = False
                return
            if not valid:
                self.state = 'waiting'
                return
            if self.blocked:
                return
            if health['hp'] <= 0:
                self.state = 'dead'
                return
            if not self.active:
                self.state, self.error = 'watching', None
                return
            active = self.active
        if not inventory['full_list_received'] or inventory['coverage_gap'] or inventory.get('session_id', self.session) != self.session:
            self.state = 'waiting'
            return
        potion = next((row for row in inventory['items'] if row['item_id'] == item_id and row['amount'] > 0), None)
        if not potion or item_id not in totals:
            self.state = 'empty'
            return
        if queue_active(self.monitor) or any(getattr(self.monitor, name).snapshot().get('active') for name in ('inventory_drop', 'newbie_buff', 'skill_actions', 'auto_pickup') if hasattr(self.monitor, name)):
            self.state = 'paused'
            return
        if now < self.next_use or time.time() < self.reuse_until:
            self.state = 'healing'
            return
        if status.get('actions_supported') is False:
            sender = getattr(self.monitor, 'sender', None)
            capability = sender.status() if sender else {}
            if (status.get('detected_cipher') != 'l2xor16-u64' or status.get('active_source') == 'server'
                    or not capability.get('available')):
                self.state, self.error = 'waiting', capability.get('reason')
                return
        self.last_use, self.next_use = now, now + interval_ms / 1000
        try:
            # Configuration and connection may have changed while a previous channel sent.
            with self.lock:
                if (self.closed.is_set() or self.monitor.stop_event.is_set() or not self.enabled
                        or item_id != self.item_id or self.monitor.status().get('session_id') != self.session):
                    return
            if status.get('actions_supported') is False:
                raw = struct.pack('<HBII', 11, 0x19, potion['object_id'], 0)
                self.monitor.sender.send(raw, cancel=self.closed)
                native = dict(sent=True, healing=True)
            elif self.resource == 'hp':
                native = self.transport.heal(status, potion['object_id'], threshold, active)
            else:
                native = dict(self.transport.use_item(status, potion['object_id']), healing=True)
        except Exception as error:
            with self.lock:
                self.blocked = True
                self.state, self.error = 'failed', str(error)
            return
        with self.lock:
            self.active = bool(native['healing'])
            self.attempts += int(bool(native['sent']))
            self.state, self.error = 'healing' if self.active else 'watching', None

    def _run(self):
        while not self.closed.is_set():
            try:
                self.tick()
            except Exception as error:
                with self.lock:
                    self.state, self.error = 'waiting', str(error)
                    self.health = None
                    self.active = False
                self.next_read = time.monotonic() + 2
            self.closed.wait(.1)


class AutoRecovery(AutoHeal):
    """One worker serializes HP, CP and MP; legacy HP API remains compatible."""
    def __init__(self, monitor, transport):
        super().__init__(monitor, transport)
        self.channels = {'hp': self}
        for resource in ('cp', 'mp'):
            channel = AutoHeal(monitor, transport, self.reader, resource=resource)
            channel.catalog = self.catalog
            self.channels[resource] = channel

    def _run(self):
        while not self.closed.is_set():
            for channel in self.channels.values():
                if self.closed.is_set():
                    break
                try:
                    channel.tick()
                except Exception as error:
                    with channel.lock:
                        channel.state, channel.error = 'waiting', str(error)
                        channel.health, channel.active = None, False
                    channel.next_read = time.monotonic() + 2
            self.closed.wait(.1)

    def close(self):
        for channel in self.channels.values():
            channel.closed.set()
        super().close()
