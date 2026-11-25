"""Offline reference L2 XOR probe. Output is a hypothesis, not validated Asterios data."""
import argparse
import csv
import hashlib
import io
import json
import subprocess
from pathlib import Path

from capture_summary import contiguous_chunks


class ReferenceXor:
    """16-byte running XOR, counter at bytes 8..11; one instance per direction."""

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError('The reference implementation requires a 16-byte key')
        self.key = bytearray(key)

    def decrypt(self, body):
        previous = 0
        output = bytearray()
        for index, value in enumerate(body):
            output.append(value ^ self.key[index % 16] ^ previous)
            previous = value
        counter = (int.from_bytes(self.key[8:12], 'little') + len(body)) & 0xffffffff
        self.key[8:12] = counter.to_bytes(4, 'little')
        return bytes(output)


def split_records(data):
    """Strict full-length u16 LE framing. Never infer or repair alignment."""
    records = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError(f'Incomplete length header at stream offset {offset}')
        size = int.from_bytes(data[offset:offset + 2], 'little')
        if size < 3 or offset + size > len(data):
            raise ValueError(f'Invalid or incomplete record at stream offset {offset}: {size}')
        records.append(data[offset:offset + size])
        offset += size
    return records


def extract_rows(capture, tshark):
    fields = ['frame.number', 'ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport',
              'tcp.stream', 'tcp.seq_raw', 'tcp.flags.syn', 'tcp.payload']
    command = [str(tshark), '-n', '-r', str(capture), '-T', 'fields', '-E', 'header=y']
    for field in fields:
        command.extend(['-e', field])
    result = subprocess.run(command, capture_output=True, check=True, timeout=60)
    return list(csv.DictReader(io.StringIO(result.stdout.decode('utf-8')), delimiter='\t'))


def reassemble_direction(rows, stream, server, from_server):
    selected = [r for r in rows if r['tcp.stream'] == str(stream)
                and (r['ip.src'] == server if from_server else r['ip.dst'] == server)]
    segments = [(int(r['tcp.seq_raw']), bytes.fromhex(r['tcp.payload']))
                for r in selected if r['tcp.payload']]
    chunks, integrity = contiguous_chunks(segments)
    if len(chunks) != 1 or integrity['gap_bytes'] or integrity['conflicting_bytes']:
        raise ValueError(f'Cannot probe an incomplete or conflicting direction: {integrity}')
    return chunks[0], integrity


def probe(rows, stream, server, character):
    relevant = [r for r in rows if r['tcp.stream'] == str(stream)]
    if not any(r['tcp.flags.syn'] == '1' for r in relevant):
        raise ValueError('A capture from connection establishment is required')
    server_data, integrity = reassemble_direction(rows, stream, server, True)
    records = split_records(server_data)
    first = records[0]
    if len(first) < 20 or first[2:4] != b'\x2e\x01':
        raise ValueError('Expected initial candidate KeyInit at the captured stream start')
    cipher = ReferenceXor(first[4:20])
    candidates = [cipher.decrypt(record[2:]) for record in records[1:]]
    client_data, client_integrity = reassemble_direction(rows, stream, server, False)
    client_size = int.from_bytes(client_data[:2], 'little')
    client_tail = client_data[client_size:]
    try:
        client_records = split_records(client_tail)
        client_status = 'framing_candidate_only'
    except ValueError as error:
        client_records = []
        client_status = str(error)
    return {
        'hypothesis': 'First server record bytes 4..19 as key; standard running XOR; counter 8..11 += body size',
        'implementation_source': 'https://github.com/eldarkg/lineage2wireshark/blob/master/decrypt/xor.lua',
        'validated_decryption': False,
        'semantic_validation': 'No Asterios packet schema or field values have been established',
        'server_integrity': integrity,
        'client_integrity': client_integrity,
        'initial_server_length': len(first),
        'server_candidate_count': len(candidates),
        'candidate_character_matches': {
            enc: [i + 2 for i, data in enumerate(candidates) if character.encode(enc) in data]
            for enc in ('ascii', 'utf-16le')},
        'first_candidate_prefixes': [data[:32].hex() for data in candidates[:6]],
        'client_after_initial': {'bytes': len(client_tail), 'framing_status': client_status,
                                 'candidate_count': len(client_records), 'decrypted': False},
    }, candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    parser.add_argument('--stream', type=int, default=0)
    parser.add_argument('--server', default='146.59.110.40')
    parser.add_argument('--character', default='X501')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report, _ = probe(extract_rows(args.capture, args.tshark), args.stream, args.server, args.character)
    report['capture_sha256'] = hashlib.sha256(args.capture.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Saved {args.output}; validated_decryption=false')


if __name__ == '__main__':
    main()
