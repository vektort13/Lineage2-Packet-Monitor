"""Reproduce the verified first server packet decode from the X501 capture."""
import argparse
import hashlib
import json
import zlib
from pathlib import Path

from reference_xor import ReferenceXor, extract_rows, reassemble_direction, split_records


def decode_first(rows, stream, server, character):
    relevant = [r for r in rows if r['tcp.stream'] == str(stream)]
    if not any(r['tcp.flags.syn'] == '1' for r in relevant):
        raise ValueError('Connection-start capture required')
    data, integrity = reassemble_direction(rows, stream, server, True)
    records = split_records(data)
    if len(records) < 2 or records[0][2:4] != b'\x2e\x01' or len(records[0]) < 20:
        raise ValueError('Initial KeyInit candidate not found at stream start')
    candidate = ReferenceXor(records[0][4:20]).decrypt(records[1][2:])
    if candidate[:1] != b'\x8d':
        raise ValueError('This first-packet layout does not match the verified capture')
    inflater = zlib.decompressobj(-15)
    plain = inflater.decompress(candidate[1:], 65536)
    if len(plain) > 65535 or inflater.unconsumed_tail or inflater.unused_data:
        raise ValueError('Incomplete, trailing or oversized decompression output')
    packets = split_records(plain)
    summaries = []
    for packet in packets:
        name_offset = packet.find(character.encode('utf-16le') + b'\x00\x00')
        summary = {'total_length': len(packet), 'opcode': hex(packet[2]),
                   'sha256': hashlib.sha256(packet).hexdigest(),
                   'character_utf16le_offset': name_offset if name_offset >= 0 else None}
        if packet[2] == 0x09 and len(packet) >= 12:
            summary.update({'reference_name': 'CharacterSelectionInfo',
                            'created_character_count': int.from_bytes(packet[3:7], 'little'),
                            'max_character_count': int.from_bytes(packet[7:11], 'little')})
        summaries.append(summary)
    verified = (len(packets) == 1 and packets[0][2] == 0x09
                and int.from_bytes(packets[0][3:7], 'little') == 1
                and summaries[0]['character_utf16le_offset'] == 17)
    if not verified:
        raise ValueError('Decoded data does not meet the verified first-packet criteria')
    report = {
        'status': 'partial_decryption',
        'verified_server_outer_record_indices': [2],
        'verified_server_logical_packet_count': 1,
        'verified_client_packet_count': 0,
        'entire_conversation_decrypted': False,
        'pipeline': ['TCP sequence reassembly', 'u16 LE outer record length',
                     'standard running XOR using initial 16-byte key at KeyInit offsets 4..19',
                     'skip first decoded byte 0x8d', 'raw DEFLATE (wbits=-15)',
                     'u16 LE inner packet length'],
        'server_integrity': integrity,
        'outer_record_length': len(records[1]),
        'inflated_bytes': len(plain),
        'inflate_end_of_stream': inflater.eof,
        'inflate_unused_bytes': len(inflater.unused_data),
        'inflate_unconsumed_bytes': len(inflater.unconsumed_tail),
        'logical_packets': summaries,
        'character': character,
        'limitations': ['The first decoded byte is observed here, not a global opcode assignment.',
                        'A complete DEFLATE stream has not ended; this block uses a flush boundary.',
                        'The continuation cipher/compression state has not been established.',
                        'The full CharacterSelectionInfo schema for this Asterios build is not established.'],
        'reference_opcode_table': 'https://github.com/acmi/NetPro',
    }
    return report, plain


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--tshark', default='C:/Program Files/Wireshark/tshark.exe')
    parser.add_argument('--stream', type=int, default=0)
    parser.add_argument('--server', default='146.59.110.40')
    parser.add_argument('--character', default='X501')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--packet-output', type=Path, required=True)
    args = parser.parse_args()
    report, packet = decode_first(extract_rows(args.capture, args.tshark), args.stream,
                                  args.server, args.character)
    report['capture_sha256'] = hashlib.sha256(args.capture.read_bytes()).hexdigest()
    args.packet_output.write_bytes(packet)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Verified first server packet: bytes={len(packet)}; opcode=0x09; character={args.character}; conversation=partial')


if __name__ == '__main__':
    main()
