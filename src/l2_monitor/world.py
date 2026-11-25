"""Observed ground-item state, separate requests and server confirmations."""
import collections
import math
import threading

from .protocol import CATEGORIES


class World:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id = session_id
            self.items = collections.OrderedDict()
            self.events = collections.deque(maxlen=200)
            self.own_position = None
            self.own_id = None
            self.coverage_gap = False

    def gap(self):
        with self.lock:
            self.coverage_gap = True
            for item in self.items.values():
                if item['state'] == 'present':
                    item['state'] = 'uncertain'

    def apply(self, packets):
        with self.lock:
            for packet in packets:
                fields = packet['fields']
                event, oid = fields.get('event'), fields.get('object_id')
                server = packet['direction'] == 'server'
                if event in ('character_selected', 'self_info') and server:
                    self.own_id = oid
                    if 'xyz' in fields:
                        self.own_position = fields['xyz']
                if not server and event in ('action', 'position_report', 'move_request'):
                    self.own_position = fields['xyz']
                item = self.items.get(oid)
                if not server and event == 'action' and item and item['state'] in ('present', 'uncertain'):
                    key = 'item_action'
                    packet.update(category=key, category_label=CATEGORIES[key][0], color=CATEGORIES[key][1])
                    fields['item_target'] = True
                    fields['item_template'] = item.get('template_value')
                if server and event in ('drop_item', 'spawn_item'):
                    item = dict(object_id=oid, template_value=fields['template_value'],
                                amount=fields['amount'], xyz=fields['xyz'], state='present',
                                source=event, last_time=packet['time'], last_frame=packet['frame'])
                    if 'dropper_id' in fields:
                        item['dropper_id'] = fields['dropper_id']
                    self.items[oid] = item
                    self.items.move_to_end(oid)
                elif server and event == 'get_item':
                    if item is None:
                        item = dict(object_id=oid, template_value=None, amount=None, xyz=fields['xyz'])
                        self.items[oid] = item
                    item.update(state='picked_up', owner_id=fields['owner_id'], last_time=packet['time'],
                                last_frame=packet['frame'])
                elif server and event == 'delete_object' and item:
                    item.update(state='removed', last_time=packet['time'], last_frame=packet['frame'])
                if event in ('drop_request', 'drop_item', 'spawn_item', 'get_item') or (event == 'delete_object' and item):
                    labels = {'drop_request':'Запрос: выбросить', 'drop_item':'Сервер: выброшен',
                              'spawn_item':'Предмет появился', 'get_item':'Сервер: поднят',
                              'delete_object':'Предмет удалён'}
                    self.events.appendleft(dict(kind=event, label=labels[event], object_id=oid,
                        template_value=item.get('template_value') if item else None,
                        amount=fields.get('amount', item.get('amount') if item else None),
                        owner_id=fields.get('owner_id'), dropper_id=fields.get('dropper_id'),
                        time=packet['time'], frame=packet['frame'], direction=packet['direction']))
                while len(self.items) > 10000:
                    self.items.popitem(last=False)

    def snapshot(self):
        with self.lock:
            rows = []
            for item in self.items.values():
                if item['state'] not in ('present', 'uncertain'):
                    continue
                row = dict(item, distance_xy=None)
                if self.own_position and item.get('xyz'):
                    row['distance_xy'] = round(math.hypot(item['xyz'][0] - self.own_position[0],
                                                          item['xyz'][1] - self.own_position[1]), 1)
                rows.append(row)
            rows.sort(key=lambda x: (x['state'] != 'present', x['distance_xy'] if x['distance_xy'] is not None else float('inf'), x['object_id']))
            return dict(items=rows, events=list(self.events), own_position=self.own_position,
                        own_object_id=self.own_id, session_id=self.session_id,
                        coverage_gap=self.coverage_gap, source='observed-packets')
