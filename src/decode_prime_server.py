"""Decode the recorded Prime server direction offline, without opening the game."""
import argparse
import collections
import hashlib
import json
import struct
import zlib
from pathlib import Path

from asterios_game_cipher import AsteriosServerCipher
from reference_xor import extract_rows, reassemble_direction, split_records


def decode_records(records):
    if len(records[0]) != 34 or records[0][2:4] != b'\x2e\x01':
        raise ValueError('Unexpected handshake; this decoder is specific to the observed client')
    cipher = AsteriosServerCipher(records[0][4:20])
    inflate = zlib.decompressobj(-15)
    for ordinal, record in enumerate(records[1:], 1):
        body = cipher.decrypt(record[2:])
        if body[0] == 0x8d:
            expanded = inflate.decompress(body[1:], 131073)
            if len(expanded) > 131072 or inflate.unconsumed_tail or inflate.unused_data:
                raise ValueError(f'Unexpected inflate size/tail at record {ordinal}')
            packets = split_records(expanded)
        else:
            packets = [struct.pack('<H', len(body) + 2) + body]
        yield ordinal, body[0] == 0x8d, packets, bytes(cipher.key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--native-reference', type=Path,
                        help='Optional independent isolated x86 execution report for comparison')
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    args = parser.parse_args()
    rows = extract_rows(args.capture, args.tshark)
    raw, integrity = reassemble_direction(rows, 0, '146.59.110.40', True)
    records = split_records(raw)
    reference = None
    if args.native_reference:
        reference = json.loads(args.native_reference.read_text('utf-8'))['record_results']
        if len(reference) != len(records) - 1:
            raise ValueError('Native reference record count differs')
        check_cipher = AsteriosServerCipher(records[0][4:20])
        for index, (packet, expected) in enumerate(zip(records[1:], reference), 1):
            output = check_cipher.decrypt(packet[2:])
            if (not expected['returned'] or expected['record_index'] != index
                    or expected['output_sha256'] != hashlib.sha256(output).hexdigest()
                    or expected['key_struct_after'] != '00' + bytes(check_cipher.key).hex()):
                raise ValueError(f'Native output/key mismatch at record {index}')
    args.output_dir.mkdir(exist_ok=True, parents=True)
    index_rows = []
    concatenated = bytearray()
    compressed_records = 0
    for ordinal, compressed, packets, _ in decode_records(records):
        compressed_records += compressed
        for inner_index, packet in enumerate(packets):
            entry = {'outer_record_index': ordinal, 'inner_index': inner_index,
                     'offset': len(concatenated), 'length': len(packet),
                     'opcode': f'{packet[2]:02x}', 'compressed': compressed,
                     'sha256': hashlib.sha256(packet).hexdigest()}
            if packet[2] == 0xfe:
                if len(packet) < 5:
                    raise ValueError('Truncated extended opcode')
                entry['extension'] = int.from_bytes(packet[3:5], 'little')
            if 'X501'.encode('utf-16le') in packet:
                entry['character_X501'] = True
            index_rows.append(entry)
            concatenated.extend(packet)
    summary = {'capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
               'server_integrity': integrity, 'encrypted_outer_records': len(records) - 1,
               'compressed_outer_records': compressed_records, 'decoded_packets': len(index_rows),
               'decoded_bytes': len(concatenated), 'decoded_sha256': hashlib.sha256(concatenated).hexdigest(),
               'native_reference_matched': bool(reference),
               'opcodes': dict(collections.Counter(x['opcode'] for x in index_rows)),
               'packets': index_rows}
    (args.output_dir / 'server-packets.bin').write_bytes(concatenated)
    (args.output_dir / 'server-packets.json').write_text(json.dumps(summary, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('packets', 'opcodes')}))


if __name__ == '__main__':
    main()
