"""Bounded, conservative TCP reassembly for u16LE length-prefixed records.

``TcpRecords(endpoint).feed(npcap_rows)`` returns complete records. ``wire``
(also ``raw``) includes the two-byte total length; ``body`` excludes it.
``seq`` is the first prefix byte's TCP sequence modulo 2**32. ``frame`` and
``time``/``ts_epoch`` identify that byte's first capture, not the completing
segment. ``completion_frame``/``completion_time`` identify when the entire
ordered prefix through this record became available; those fields preserve
wire order when a missing prefix arrives after a later record's tail.
Direction is ``client`` or ``server``.

A stream requires a captured SYN or an explicit ``seed(direction, seq)`` at a
known record boundary. No scanning for plausible lengths is performed. Gaps
wait for missing bytes; conflicts, invalid lengths and limits stop that stream
until it is explicitly seeded again. Previously emitted bytes are immutable.
Recent emitted bytes are retained to check retransmissions; older duplicates
are ignored and counted as unverifiable, never used to construct new data.
"""
from collections import OrderedDict


_MASK = (1 << 32) - 1
_HALF = 1 << 31
_FAILED = {'conflict', 'invalid_length', 'overflow'}


class _Stream:
    def __init__(self, max_buffer, history_bytes):
        self.max_buffer = max_buffer
        self.history_bytes = history_bytes
        self.generation = 0
        self.seed(None)

    def seed(self, seq):
        self.generation += 1
        self.origin = None if seq is None else int(seq) & _MASK
        self.cursor = 0
        self.frontier = 0
        self.completion = None
        self.pending = {}
        self.history = OrderedDict()
        self.status = 'unsynchronized' if seq is None else 'ready'
        self.reason = None
        self.records = 0
        self.duplicate_bytes = 0
        self.unverifiable_bytes = 0
        self.syn_boundary = None

    def fail(self, status, reason):
        self.status, self.reason = status, reason
        # A stopped stream has no useful speculative data to retain.
        self.pending.clear()

    def snapshot(self):
        return dict(synchronized=self.origin is not None and self.status not in _FAILED,
                    status=self.status, reason=self.reason,
                    next_seq=None if self.origin is None else (self.origin + self.cursor) & _MASK,
                    buffered_bytes=len(self.pending), history_bytes=len(self.history),
                    records=self.records, duplicate_bytes=self.duplicate_bytes,
                    unverifiable_bytes=self.unverifiable_bytes, generation=self.generation)

    def add(self, seq, payload, metadata, direction):
        if self.origin is None or self.status in _FAILED or not payload:
            return []
        # Nearest signed sequence distance from the current record boundary.
        delta = (seq - ((self.origin + self.cursor) & _MASK)) & _MASK
        if delta == _HALF:
            self.fail('overflow', 'ambiguous TCP sequence distance')
            return []
        offset = self.cursor + (delta if delta < _HALF else delta - (1 << 32))
        if offset + len(payload) > self.cursor + self.max_buffer:
            self.fail('overflow', 'TCP gap exceeds bounded receive window')
            return []

        # Validate the entire segment before accepting any new bytes from it.
        # This prevents a conflicting overlap from partly changing the stream.
        additions = []
        duplicates = unverifiable = 0
        for index, value in enumerate(payload):
            position = offset + index
            if position < self.cursor:
                previous = self.history.get(position)
                if previous is None:
                    unverifiable += 1
                elif previous != value:
                    self.fail('conflict', 'retransmission changes an emitted byte')
                    return []
                else:
                    duplicates += 1
            elif position in self.pending:
                if self.pending[position][0] != value:
                    self.fail('conflict', 'overlapping segments disagree')
                    return []
                duplicates += 1
            else:
                additions.append((position, value))
        if len(self.pending) + len(additions) > self.max_buffer:
            self.fail('overflow', 'buffer byte limit exceeded')
            return []
        for position, value in additions:
            self.pending[position] = (value, metadata)
        while self.frontier in self.pending:
            self.frontier += 1
        self.duplicate_bytes += duplicates
        self.unverifiable_bytes += unverifiable

        result = []
        while self.cursor in self.pending and self.cursor + 1 in self.pending:
            length = self.pending[self.cursor][0] | (self.pending[self.cursor + 1][0] << 8)
            if not 3 <= length <= 65535:
                self.fail('invalid_length', 'record total length must be 3..65535')
                break
            end = self.cursor + length
            if end > self.frontier:
                break
            first = self.pending[self.cursor][1]
            last = self.pending[end - 1][1]
            completion = max((self.pending[position][1]
                              for position in range(self.cursor, end)), key=lambda value: value[0])
            if self.completion is not None and self.completion[0] > completion[0]:
                completion = self.completion
            self.completion = completion
            wire = bytes(self.pending[position][0] for position in range(self.cursor, end))
            result.append(dict(direction=direction, raw=wire, wire=wire, body=wire[2:],
                               length=length, seq=(self.origin + self.cursor) & _MASK,
                               frame=first[0], time=first[1], ts_epoch=first[1],
                               end_frame=last[0], end_time=last[1],
                               completion_frame=completion[0], completion_time=completion[1],
                               generation=self.generation))
            for position in range(self.cursor, end):
                self.history[position] = self.pending.pop(position)[0]
            while len(self.history) > self.history_bytes:
                self.history.popitem(last=False)
            self.cursor = end
            self.records += 1
        if self.status not in _FAILED:
            if not self.pending:
                self.status = 'ready'
            else:
                # All buffered bytes must be contiguous from the boundary to
                # call it a partial record; an internal missing byte is a gap.
                self.status = ('partial' if self.frontier - self.cursor == len(self.pending)
                               else 'gap')
        return result


class TcpRecords:
    """One selected four-tuple, independent ordered streams per direction.

    Limits apply per direction and are strict byte counts. ``max_buffer`` also
    bounds the distance ahead of the current boundary, preventing sparse
    attacker-controlled sequence numbers from allocating an unbounded map.
    ``state()`` returns both snapshots, or ``state(direction)`` one snapshot.
    Repeated capture rows and retransmissions do not re-emit records.
    """
    def __init__(self, endpoint, *, max_buffer=262144, history_bytes=65535):
        if not 65535 <= max_buffer < _HALF:
            raise ValueError('max_buffer must be between 65535 and 2**31-1')
        if not 0 <= history_bytes <= max_buffer:
            raise ValueError('history_bytes must be between 0 and max_buffer')
        self.local = (endpoint['local_ip'], int(endpoint['local_port']))
        self.remote = (endpoint['remote_ip'], int(endpoint['remote_port']))
        self.streams = {name: _Stream(max_buffer, history_bytes) for name in ('client', 'server')}

    def seed(self, direction, seq):
        """Discard buffered state and set a confirmed prefix sequence boundary.

        ``seq=None`` explicitly returns this direction to unsynchronized mode.
        The caller must not seed from an arbitrary captured TCP segment.
        """
        self.streams[direction].seed(seq)

    def state(self, direction=None):
        if direction is not None:
            return self.streams[direction].snapshot()
        return {name: stream.snapshot() for name, stream in self.streams.items()}

    def feed(self, rows):
        result = []
        for row in rows:
            try:
                source = (row['ip.src'], int(row['tcp.srcport']))
                destination = (row['ip.dst'], int(row['tcp.dstport']))
                if (source, destination) == (self.local, self.remote):
                    direction = 'client'
                elif (source, destination) == (self.remote, self.local):
                    direction = 'server'
                else:
                    continue
                seq = int(row['tcp.seq_raw'])
                if not 0 <= seq <= _MASK:
                    continue
                payload = bytes.fromhex(row.get('tcp.payload', '').replace(':', ''))
                metadata = (int(row['frame.number']), row['frame.time_epoch'])
            except (KeyError, TypeError, ValueError):
                continue
            stream = self.streams[direction]
            if str(row.get('tcp.flags.syn', '0')).lower() in ('1', 'true'):
                boundary = (seq + 1) & _MASK
                if stream.syn_boundary != boundary:
                    stream.seed(boundary)
                    stream.syn_boundary = boundary
                seq = boundary  # SYN consumes a sequence number, even with data.
            result.extend(stream.add(seq, payload, metadata, direction))
        return result
