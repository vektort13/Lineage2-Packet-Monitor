"""Represent unprofiled clients as captured TCP data, without guessing opcodes."""
import hashlib
from datetime import datetime, timezone


def wire_packet(row, endpoint, session_id):
    source = (row['ip.src'], int(row['tcp.srcport']))
    destination = (row['ip.dst'], int(row['tcp.dstport']))
    local = (endpoint['local_ip'], endpoint['local_port'])
    remote = (endpoint['remote_ip'], endpoint['remote_port'])
    if (source, destination) == (local, remote):
        direction = 'client'
    elif (source, destination) == (remote, local):
        direction = 'server'
    else:
        return None
    raw = bytes.fromhex(row['tcp.payload'])
    if not raw:
        return None
    return dict(direction=direction, opcode='TCP', name='Undecoded TCP payload', category='unknown',
                category_label='Неизвестный', color='#6e7681', length=len(raw),
                ts_epoch=row['frame.time_epoch'],
                time=datetime.fromtimestamp(float(row['frame.time_epoch']), timezone.utc).isoformat(timespec='milliseconds'),
                frame=int(row['frame.number']), session_id=session_id, status='wire',
                data_layer='tcp-payload', schema_status='unprofiled', schema_error=None,
                fields=dict(event='tcp_payload', source_ip=source[0], source_port=source[1],
                            destination_ip=destination[0], destination_port=destination[1],
                            tcp_sequence=int(row['tcp.seq_raw'])),
                sha256=hashlib.sha256(raw).hexdigest(), raw_hex=raw.hex())
