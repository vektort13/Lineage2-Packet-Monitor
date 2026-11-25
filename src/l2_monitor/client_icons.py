"""Lazy, bounded Qt icon loading from the bundled client assets."""
import json
import zipfile
from collections import OrderedDict
from pathlib import Path

from PySide6.QtGui import QIcon, QPixmap

from .live_state import ROOT


class ClientIcons:
    def __init__(self, path=None, capacity=512):
        self.path = Path(path) if path is not None else ROOT / 'assets/client-icons.zip'
        self.capacity, self.cache = capacity, OrderedDict()
        self.manifest = dict(items={}, skills={}, skill_defaults={}, images={})
        self.archive = None
        if self.path.is_file():
            self.archive = zipfile.ZipFile(self.path)
            self.manifest = json.loads(self.archive.read('manifest.json'))

    def reference(self, kind, entity_id, level=None):
        if entity_id is None:
            return None
        if kind == 'item':
            return self.manifest['items'].get(str(entity_id))
        if kind != 'skill':
            return None
        return (self.manifest['skills'].get(f'{entity_id}:{level}')
                or self.manifest['skill_defaults'].get(str(entity_id)))

    def icon(self, kind, entity_id, level=None):
        reference = self.reference(kind, entity_id, level)
        name = self.manifest['images'].get(reference)
        if not name or not self.archive:
            return None
        if name in self.cache:
            self.cache.move_to_end(name)
            return self.cache[name]
        pixmap = QPixmap()
        if not pixmap.loadFromData(self.archive.read(name), 'PNG'):
            return None
        result = QIcon(pixmap)
        self.cache[name] = result
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
        return result

    def close(self):
        if self.archive:
            self.archive.close()
            self.archive = None
        self.cache.clear()
