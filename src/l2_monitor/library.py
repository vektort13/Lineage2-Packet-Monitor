"""Persistent, server-scoped IDs and packet evidence for items and skills."""
import csv
import hashlib
import io
import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

from .live_state import DATA_ROOT


class Library:
    def __init__(self, path=None):
        self.path = Path(path) if path else DATA_ROOT / 'reports/monitor-library/catalog.sqlite'
        self.lock = threading.RLock()

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.executescript('''
            CREATE TABLE IF NOT EXISTS entries (
              server TEXT, profile TEXT, kind TEXT, entity_id INTEGER, level INTEGER,
              name TEXT, first_seen TEXT, last_seen TEXT, observations INTEGER, sample TEXT,
              PRIMARY KEY(server, profile, kind, entity_id, level));
            CREATE TABLE IF NOT EXISTS evidence (
              fingerprint TEXT PRIMARY KEY);
        ''')
        return db

    def observe(self, packets, server, profile):
        records = []
        for packet in packets:
            f = packet['fields']
            if f.get('event') == 'inventory_update':
                entities = [('item', item['item_id'], 0) for item in f['items']]
            elif f.get('event') in ('spawn_item', 'drop_item'):
                entities = [('item', f['template_value'], 0)]
            elif f.get('event') in ('skill_use', 'skill_launched'):
                entities = [('skill', f['skill_id'], f['skill_level'])]
            elif f.get('event') == 'skill_list':
                entities = [('skill', item['skill_id'], item['skill_level']) for item in f['skills']]
            else:
                continue
            for kind, entity_id, level in set(entities):
                if not 0 < entity_id <= 0xffffffff or not 0 <= level <= 0xffffffff:
                    continue
                fingerprint = hashlib.sha256(json.dumps([server, profile, kind, entity_id, level,
                    packet['session_id'], packet['frame'], packet['sha256'],
                    packet.get('outer_ordinal'), packet.get('inner_index')]).encode()).hexdigest()
                name = {4356:'Gold',4357:'Silver'}.get(entity_id) if (
                    kind == 'item' and server == '146.59.110.40:2110'
                    and profile == 'asterios-prime-observed-20261121') else None
                sample = {k:packet[k] for k in ('direction','opcode','name','frame','time','session_id','sha256','raw_hex','fields')}
                records.append((fingerprint, server, profile, kind, entity_id, level,
                                name, packet['time'], json.dumps(sample, ensure_ascii=False)))
        if not records:
            return
        with self.lock, closing(self.connect()) as db, db:
            for fingerprint, server, profile, kind, entity_id, level, name, timestamp, sample in records:
                if not db.execute('INSERT OR IGNORE INTO evidence VALUES (?)', (fingerprint,)).rowcount:
                    continue
                db.execute('''INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(server,profile,kind,entity_id,level) DO UPDATE SET
                      first_seen=MIN(first_seen,excluded.first_seen),
                      last_seen=MAX(last_seen,excluded.last_seen), observations=observations+1,
                      name=COALESCE(entries.name,excluded.name)''',
                    (server,profile,kind,entity_id,level,name,timestamp,timestamp,1,sample))

    def query(self, kind=None, server=None, search='', include_samples=False):
        if kind not in (None, 'item', 'skill'):
            raise ValueError('kind: item or skill')
        conditions, arguments = [], []
        if kind:
            conditions.append('kind=?')
            arguments.append(kind)
        if server:
            conditions.append('server=?')
            arguments.append(server)
        if search:
            conditions.append("(CAST(entity_id AS TEXT) LIKE ? OR COALESCE(name,'') LIKE ?)")
            arguments.extend(['%' + search + '%'] * 2)
        where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
        with self.lock, closing(self.connect()) as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM entries' + where +
                     ' ORDER BY kind,entity_id,level,server,profile', arguments)]
        for row in rows:
            sample = row.pop('sample')
            if include_samples:
                row['sample'] = json.loads(sample)
        return rows

    def export(self, format='json', **filters):
        rows = self.query(include_samples=format == 'json', **filters)
        if format == 'json':
            return json.dumps(dict(version=1, entries=rows), ensure_ascii=False, indent=2).encode('utf-8')
        if format != 'csv':
            raise ValueError('format: json or csv')
        output = io.StringIO(newline='')
        writer = csv.DictWriter(output, ['server','profile','kind','entity_id','level','name','first_seen','last_seen','observations'])
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue().encode('utf-8-sig')
