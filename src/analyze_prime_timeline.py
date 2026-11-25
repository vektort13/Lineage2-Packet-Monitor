"""Build a passive packet/object timeline from a verified, decoded Prime capture.

Times describe when an ordered TCP prefix was captured, never client rendering or
server KnownList state. Only a small, explicitly selected set of fields is parsed.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
import struct
import subprocess
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from reference_xor import reassemble_direction, split_records
from verify_prime_exchange import utf16_string


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def transport(rows, stream, server, from_server):
    """Attribute bytes to first capture frames, including ordered-prefix delays."""
    data, integrity = reassemble_direction(rows, stream, server, from_server)
    selected = [r for r in rows if r['tcp.stream'] == str(stream) and r['tcp.payload']
                and (r['ip.src'] == server if from_server else r['ip.dst'] == server)]
    selected.sort(key=lambda r: int(r['frame.number']))
    if any(r['tcp.flags.syn'] == '1' for r in selected):
        raise ValueError('TCP payload on SYN is not supported by this adapter')
    anchor = int(selected[0]['tcp.seq_raw'])
    offsets = [(int(r['tcp.seq_raw']) - anchor + 2**31) % 2**32 - 2**31 for r in selected]
    start = min(offsets)
    first_frame = [0] * len(data)
    for row, relative in zip(selected, offsets):
        offset = relative - start
        payload = bytes.fromhex(row['tcp.payload'])
        if data[offset:offset + len(payload)] != payload:
            raise ValueError('TCP attribution content mismatch')
        for index in range(offset, offset + len(payload)):
            if not first_frame[index]:
                first_frame[index] = int(row['frame.number'])
    if not all(first_frame):
        raise ValueError('A reconstructed byte has no capture frame')
    # A late missing prefix also delays records whose own bytes arrived earlier.
    ready, latest = [], 0
    for frame in first_frame:
        latest = max(latest, frame)
        ready.append(latest)
    return data, ready, integrity


def parse_fields(direction, packet):
    """Return a partial schema; fail on incompatible shapes instead of guessing."""
    op, length = packet[2], len(packet)

    def exact(expected):
        if length != expected:
            raise ValueError(f'{direction} opcode {op:02X}: expected {expected}, got {length}')

    def oid(offset=3):
        return struct.unpack_from('<I', packet, offset)[0]

    def xyz(offset):
        return list(struct.unpack_from('<3i', packet, offset))

    if direction == 'server':
        if op == 0x0b:
            name, offset = utf16_string(packet, 3)
            return dict(event='character_selected', object_id=oid(offset), character=name)
        if op == 0x32:
            name, _ = utf16_string(packet, 23)
            return dict(event='self_info', object_id=oid(19), xyz=xyz(3), character=name)
        if op == 0x0c:
            if length < 27:
                raise ValueError('Incomplete NpcInfo prefix')
            return dict(event='npc_info', object_id=oid(), template_value=oid(7), xyz=xyz(15))
        if op == 0x08:
            exact(11)
            return dict(event='delete_object', object_id=oid(), tail_u32=oid(7))
        if op == 0x16:
            exact(43)
            return dict(event='drop_item', object_id=oid(7), dropper_id=oid(),
                        template_value=oid(11), xyz=xyz(15),
                        amount=struct.unpack_from('<Q', packet, 31)[0])
        if op == 0x05:
            exact(39)
            return dict(event='spawn_item', object_id=oid(), template_value=oid(7),
                        xyz=xyz(11), amount=struct.unpack_from('<Q', packet, 27)[0])
        if op == 0x17:
            exact(23)
            return dict(event='get_item', object_id=oid(7), owner_id=oid(), xyz=xyz(11))
        if op == 0x2f:
            exact(31)
            return dict(event='move', object_id=oid(), destination=xyz(7), xyz=xyz(19))
        if op == 0x79:
            exact(23)
            return dict(event='position', object_id=oid(), xyz=xyz(7))
        if op == 0x22:
            exact(27)
            return dict(event='teleport', object_id=oid(), xyz=xyz(7))
        if op == 0x47:
            exact(23)
            return dict(event='stop_move', object_id=oid(), xyz=xyz(7))
        if op == 0x24:
            exact(23)
            return dict(event='target_unselected', object_id=oid(), xyz=xyz(7))
    else:
        if op == 0x17:
            exact(27)
            return dict(event='drop_request', object_id=oid(),
                        amount=struct.unpack_from('<Q', packet, 7)[0], destination=xyz(15))
        if op == 0x1f:
            exact(20)
            return dict(event='action', object_id=oid(), xyz=xyz(7), shift=packet[19])
        if op == 0x0f:
            exact(31)
            return dict(event='move_request', destination=xyz(3), xyz=xyz(15), movement_kind=oid(27))
        if op == 0x59:
            exact(23)
            return dict(event='position_report', xyz=xyz(3), heading=oid(15), vehicle_id=oid(19))
    return {}


def read_decoded(root, direction, capture_hash):
    data = (root / f'{direction}-packets.bin').read_bytes()
    meta = json.loads((root / f'{direction}-packets.json').read_text('utf-8'))
    packets = split_records(data)
    if (meta['capture_sha256'] != capture_hash or meta['decoded_sha256'] != sha256(data)
            or meta['decoded_packets'] != len(packets) or len(meta['packets']) != len(packets)):
        raise ValueError(f'{direction}: decoded input identity mismatch')
    for packet, row in zip(packets, meta['packets']):
        if sha256(packet) != row.get('plaintext_sha256', row.get('sha256')):
            raise ValueError(f'{direction}: packet hash mismatch')
    return packets, meta


def make_timeline(rows, decoded_dir, opcode_table, capture_hash, stream, server):
    if not any(r['tcp.stream'] == str(stream) and r['tcp.flags.syn'] == '1' for r in rows):
        raise ValueError('Connection start is missing')
    with opcode_table.open(encoding='utf-8-sig', newline='') as source:
        names = {(r['direction'], r['opcode']): r['name'] for r in csv.DictReader(source)}
    frame_rows = {int(r['frame.number']): r for r in rows}
    origin = min(Decimal(r['frame.time_epoch']) for r in rows if r['tcp.stream'] == str(stream))
    events, identities = [], {}
    for direction in ('client', 'server'):
        packets, meta = read_decoded(decoded_dir, direction, capture_hash)
        wire, ready, integrity = transport(rows, stream, server, direction == 'server')
        identities[direction] = dict(decoded_sha256=meta['decoded_sha256'],
                                     metadata_sha256=sha256((decoded_dir / f'{direction}-packets.json').read_bytes()),
                                     decoded_packets=len(packets), wire_bytes=len(wire), integrity=integrity)
        if direction == 'server':
            wire_records = split_records(wire)
            ends, offset = [], 0
            for record in wire_records:
                offset += len(record)
                ends.append(offset)
            expected = collections.Counter(row['outer_record_index'] for row in meta['packets'])
            if set(expected) != set(range(1, len(wire_records))):
                raise ValueError('Server outer record coverage mismatch')
            source_order = [(r['outer_record_index'], r['inner_index']) for r in meta['packets']]
            expected_order = [(outer, inner) for outer in range(1, len(wire_records))
                              for inner in range(expected[outer])]
            if source_order != expected_order:
                raise ValueError('Server inner packet order mismatch')
        else:
            offset = meta['initial_plain_record_bytes']
            for row in meta['packets']:
                if row['wire_offset'] != offset:
                    raise ValueError('Client wire record coverage mismatch')
                offset += row['wire_length']
            if offset != len(wire):
                raise ValueError('Client wire bytes left unattributed')
        for ordinal, (packet, meta_row) in enumerate(zip(packets, meta['packets']), 1):
            source_record = meta_row.get('outer_record_index', meta_row.get('record_index'))
            end = (ends[source_record] if direction == 'server'
                   else meta_row['wire_offset'] + meta_row['wire_length'])
            frame = ready[end - 1]
            timestamp = frame_rows[frame]['frame.time_epoch']
            opcode = f'{packet[2]:02X}'
            if packet[2] == (0xd0 if direction == 'client' else 0xfe):
                if len(packet) < 5:
                    raise ValueError('Incomplete extended opcode')
                opcode += f' {packet[3]:02X} {packet[4]:02X}'
            events.append(dict(schema_version=1, session_id=f'{capture_hash}:tcp:{stream}',
                               direction=direction, ordinal=ordinal, opcode=opcode,
                               reference_name=names.get((direction, opcode), ''),
                               decoded_length=len(packet), source_record=source_record,
                               inner_index=meta_row.get('inner_index'), completion_frame=frame,
                               ts_epoch=timestamp,
                               ts_utc=datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat(),
                               relative_seconds=float(Decimal(timestamp) - origin),
                               **parse_fields(direction, packet)))
    events.sort(key=lambda e: (e['completion_frame'], e['direction'], e['ordinal']))
    for sequence, event in enumerate(events, 1):
        event['timeline_seq'] = sequence
    return events, identities


def lifecycle(events, own_id):
    """Track packet descriptions/withdrawals, preserving unknown observations."""
    objects, actions = {}, []
    counts = collections.Counter()
    positions = []
    for event in events:
        kind, object_id = event.get('event'), event.get('object_id')
        if (event['direction'] == 'server' and object_id != own_id
                and kind in ('position', 'move', 'teleport', 'stop_move')):
            state = objects.get(object_id)
            status = state['packet_state'] if state else 'unknown'
            event['object_packet_state_before'] = status
            counts['other_object_updates_while_' + status] += 1
        if kind == 'action':
            state = objects.get(object_id)
            status = state['packet_state'] if state else 'unknown'
            actions.append(dict(timeline_seq=event['timeline_seq'],
                                completion_frame=event['completion_frame'],
                                relative_seconds=event['relative_seconds'], object_id=object_id,
                                object_kind=state['object_kind'] if state else 'unknown',
                                packet_state_before_action=status,
                                last_description_seq=state['last_description_seq'] if state else None,
                                visible=None, targetable=None, interaction_result=None))
            counts['actions_' + status] += 1
        if event['direction'] == 'server' and kind in ('npc_info', 'drop_item', 'spawn_item',
                                                      'delete_object', 'get_item'):
            state = objects.setdefault(object_id, dict(object_id=object_id, object_kind='unknown',
                                       packet_state='unknown', descriptions=0, appearance_intervals=0,
                                       delete_packets=0, get_item_packets=0,
                                       first_seen_seq=event['timeline_seq'], last_description_seq=None))
            if kind in ('npc_info', 'drop_item', 'spawn_item'):
                if state['packet_state'] == 'withdrawn':
                    counts['descriptions_after_withdrawal'] += 1
                if state['packet_state'] == 'described':
                    counts['description_refreshes'] += 1
                else:
                    state['appearance_intervals'] += 1
                state.update(packet_state='described', object_kind='npc' if kind == 'npc_info' else 'item',
                             last_description_seq=event['timeline_seq'])
                state['descriptions'] += 1
            else:
                counts[kind + '_from_' + state['packet_state']] += 1
                state['delete_packets' if kind == 'delete_object' else 'get_item_packets'] += 1
                state['packet_state'] = 'withdrawn'
            state['last_seen_seq'] = event['timeline_seq']
        if 'xyz' in event and ((event['direction'] == 'server' and object_id == own_id)
                               or (event['direction'] == 'client' and kind in
                                   ('position_report', 'move_request', 'action'))):
            positions.append({k: event[k] for k in ('timeline_seq', 'direction', 'event',
                              'completion_frame', 'relative_seconds', 'xyz', 'destination') if k in event})
    return objects, actions, positions, dict(counts)


def write_csv(path, rows):
    if not rows:
        path.write_text('', 'utf-8')
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w', encoding='utf-8-sig', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--decoded-dir', type=Path, required=True)
    parser.add_argument('--opcode-table', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    parser.add_argument('--stream', type=int, default=0)
    parser.add_argument('--server', default='146.59.110.40')
    args = parser.parse_args()
    fields = ['frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.stream',
              'tcp.seq_raw', 'tcp.flags.syn', 'tcp.payload']
    command = [args.tshark, '-n', '-r', str(args.capture), '-T', 'fields', '-E', 'header=y']
    for field in fields:
        command.extend(['-e', field])
    result = subprocess.run(command, capture_output=True, check=True, timeout=60)
    rows = list(csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), delimiter='\t'))
    capture_hash = sha256(args.capture.read_bytes())
    events, identities = make_timeline(rows, args.decoded_dir, args.opcode_table,
                                      capture_hash, args.stream, args.server)
    selected = [e for e in events if e.get('event') == 'character_selected']
    if len(selected) != 1:
        raise ValueError('Expected exactly one selected-character session')
    own_id = selected[0]['object_id']
    objects, actions, positions, counts = lifecycle(events, own_id)
    histogram = collections.Counter(e.get('event', 'unparsed') for e in events)
    first_descriptions = {}
    for event in events:
        if event.get('event') in ('npc_info', 'drop_item', 'spawn_item'):
            first_descriptions.setdefault(event['object_id'], event['timeline_seq'])
    early_updates = [{k: e[k] for k in ('timeline_seq', 'ordinal', 'source_record',
                                      'completion_frame', 'relative_seconds', 'event', 'object_id')}
                     | dict(first_description_seq=first_descriptions.get(e['object_id']))
                     for e in events if e.get('object_packet_state_before') == 'unknown']
    report = dict(capture_sha256=capture_hash, tcp_stream=args.stream,
                  character=selected[0]['character'], own_object_id=own_id,
                  inputs=identities, timeline_packets=len(events), parsed_events=dict(histogram),
                  unique_objects_by_description=dict(collections.Counter(s['object_kind'] for s in objects.values())),
                  lifecycle_counts=counts, actions=actions,
                  updates_before_description=early_updates,
                  opcode_table_sha256=sha256(args.opcode_table.read_bytes()),
                  other_player_char_info_packets=sum(e['direction'] == 'server' and e['opcode'] == '31' for e in events),
                  own_delete_packets=sum(e.get('event') == 'delete_object' and e['object_id'] == own_id for e in events),
                  own_position_events=len(positions),
                  evidence_scope='Captured packet descriptions and withdrawals in one TCP connection',
                  unknown_evidence=['server KnownList', 'server expected visibility', 'client rendering',
                                    'other observer connection', 'client packet processing time'],
                  timing='Ordered TCP prefix completion at local capture; inner packet order retained. '
                         'Cross-direction capture order is not proof of server/client processing causality.')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'packet-timeline.jsonl').write_text(
        ''.join(json.dumps(e, ensure_ascii=False) + '\n' for e in events), 'utf-8')
    (args.output_dir / 'lifecycle-summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    write_csv(args.output_dir / 'packet-timeline.csv', events)
    write_csv(args.output_dir / 'object-lifecycle.csv', sorted(objects.values(), key=lambda s: s['object_id']))
    write_csv(args.output_dir / 'actions.csv', actions)
    write_csv(args.output_dir / 'own-positions.csv', positions)
    print(json.dumps({k: report[k] for k in ('timeline_packets', 'parsed_events',
                     'unique_objects_by_description', 'lifecycle_counts',
                     'other_player_char_info_packets', 'own_delete_packets', 'own_position_events')}))


if __name__ == '__main__':
    main()
