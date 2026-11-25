"""Passive inventory state reconstructed from verified server packets.

This module only consumes decoded observations. It never creates, edits, or
sends a game packet. Inventory rows are therefore evidence of what the server
reported during the captured session, not a live client-side inventory API.
"""
import collections
import threading


class Inventory:
    """Maintain the latest observed item records for the current session."""

    def __init__(self):
        self.lock = threading.RLock()
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id = session_id
            self.items = collections.OrderedDict()
            self.events = collections.deque(maxlen=200)
            self.coverage_gap = False
            self.full_list_received = False
            self.revision = 0

    def gap(self):
        with self.lock:
            self.coverage_gap = True

    def apply(self, packets):
        """Apply only server ``inventory_update`` observations."""
        with self.lock:
            for packet in packets:
                if packet.get('direction') != 'server':
                    continue
                fields = packet.get('fields') or {}
                if fields.get('event') != 'inventory_update':
                    continue
                if 'list_type' in fields and (fields.get('record_size') == 74
                                              or (fields.get('full_list') is True and fields.get('record_size') == 68)):
                    self.items.clear()
                    self.full_list_received = True
                    self.revision += 1
                    self.coverage_gap = False
                for record in fields.get('items', []):
                    object_id = int(record['object_id'])
                    action = int(record.get('action', 0))
                    action_name = record.get('action_name', 'unknown')
                    item = dict(
                        object_id=object_id,
                        item_id=int(record['item_id']),
                        slot=int(record['slot']),
                        amount=int(record['amount']),
                        action=action,
                        action_name=action_name,
                        last_time=packet.get('time'),
                        last_frame=packet.get('frame'),
                        packet_id=packet.get('id'),
                    )
                    if action == 3 or item['amount'] <= 0:
                        self.items.pop(object_id, None)
                    else:
                        self.items[object_id] = item
                        self.items.move_to_end(object_id)
                    self.events.appendleft(dict(
                        event='inventory_update',
                        object_id=object_id,
                        item_id=item['item_id'],
                        slot=item['slot'],
                        amount=item['amount'],
                        action=action,
                        action_name=action_name,
                        time=packet.get('time'),
                        frame=packet.get('frame'),
                    ))
            while len(self.items) > 10000:
                self.items.popitem(last=False)

    def snapshot(self):
        with self.lock:
            rows = list(self.items.values())
            rows.sort(key=lambda item: (item['slot'], item['item_id'], item['object_id']))
            return dict(items=[dict(row) for row in rows], events=list(self.events),
                        session_id=self.session_id, coverage_gap=self.coverage_gap,
                        full_list_received=self.full_list_received,
                        revision=self.revision,
                        source='observed-server-inventory')
