"""Editable packet copies, executed by the separate QueueRunner.

The queue stores data only. It has no playback clock or network side effects.
"""
import copy
import threading
import uuid


class PacketQueue:
    def __init__(self):
        self.lock = threading.RLock()
        self.entries = []

    def add(self, packet):
        entry = copy.deepcopy(packet)
        bytes.fromhex(entry['raw_hex'])
        with self.lock:
            if len(self.entries) >= 1000:
                raise ValueError('В очереди не более 1000 пакетов')
            entry['queue_id'] = uuid.uuid4().hex
            self.entries.append(entry)
            return entry['queue_id']

    def items(self):
        with self.lock:
            return copy.deepcopy(self.entries)

    def remove(self, entry_id):
        with self.lock:
            self.entries = [entry for entry in self.entries if entry['queue_id'] != entry_id]

    def clear(self):
        with self.lock:
            self.entries.clear()

    def move(self, entry_id, delta):
        with self.lock:
            index = next((i for i, entry in enumerate(self.entries) if entry['queue_id'] == entry_id), None)
            if index is None:
                return
            destination = max(0, min(len(self.entries) - 1, index + int(delta)))
            self.entries.insert(destination, self.entries.pop(index))
