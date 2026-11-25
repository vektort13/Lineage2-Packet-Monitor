"""Continue from verified TCP sequence cursors instead of timestamp guesses."""
from decimal import Decimal

from analyze_prime_timeline import transport


def wire_slice(rows, direction, server, before, after, cursor=None):
    selected = [r for r in rows if r['tcp.payload']
                and (r['ip.src'] == server if direction == 'server' else r['ip.dst'] == server)]
    if not selected:
        return b'', [], {}, None
    data, ready, integrity = transport(rows, 0, server, direction == 'server')
    anchor = int(selected[0]['tcp.seq_raw'])
    offsets = [(int(r['tcp.seq_raw']) - anchor + 2**31) % 2**32 - 2**31 for r in selected]
    base = (anchor + min(offsets)) & 0xffffffff
    if cursor is not None:
        offset = (cursor - base + 2**31) % 2**32 - 2**31
        if not 0 <= offset <= len(data):
            raise ValueError('Потерян TCP-префикс после последнего проверенного пакета')
        return data[offset:], ready[offset:], integrity, cursor
    timestamps = {int(r['frame.number']): int(Decimal(r['frame.time_epoch']) * 10**9) for r in rows}
    included = [i for i, frame in enumerate(ready)
                if before['read_end_ns'] < timestamps[frame] < after['read_start_ns']]
    if not included:
        return b'', [], integrity, None
    start, end = included[0], included[-1] + 1
    return data[start:end], ready[start:end], integrity, (base + start) & 0xffffffff


def record_prefix(data, count):
    offset = 0
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError('Ожидание TCP-данных для заголовка')
        size = int.from_bytes(data[offset:offset + 2], 'little')
        if size < 3:
            raise ValueError('Недопустимая длина записи')
        if offset + size > len(data):
            raise ValueError('Ожидание TCP-хвоста сообщения')
        offset += size
    return data[:offset]
