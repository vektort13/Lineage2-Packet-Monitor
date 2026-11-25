"""Verify decoded packet boundaries, identities and a small set of semantic fields."""
import argparse
import collections
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from reference_xor import split_records


def utf16_string(data, offset):
    end = offset
    while end + 2 <= len(data):
        if data[end:end + 2] == b'\0\0':
            return data[offset:end].decode('utf-16le'), end + 2
        end += 2
    raise ValueError('Unterminated UTF-16 field')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decoded-dir', type=Path, required=True)
    parser.add_argument('--opcode-table', type=Path, required=True)
    args = parser.parse_args()
    root = args.decoded_dir
    metadata = {}
    packet_sets = {}
    for direction in ('client', 'server'):
        data = (root / f'{direction}-packets.bin').read_bytes()
        meta = json.loads((root / f'{direction}-packets.json').read_text('utf-8'))
        packets = split_records(data)
        if (len(packets) != meta['decoded_packets']
                or hashlib.sha256(data).hexdigest() != meta['decoded_sha256']):
            raise ValueError(f'{direction} output identity/framing mismatch')
        for packet, row in zip(packets, meta['packets']):
            expected = row.get('plaintext_sha256', row.get('sha256'))
            if hashlib.sha256(packet).hexdigest() != expected:
                raise ValueError(f'{direction} packet hash mismatch')
        metadata[direction], packet_sets[direction] = meta, packets
    client, server = packet_sets['client'], packet_sets['server']
    login = next(p for p in client if p[2] == 0x2b)
    account, _ = utf16_string(login, 3)
    char_list = next(p for p in server if p[2] == 9)
    selected = next(p for p in server if p[2] == 0x0b)
    character, object_offset = utf16_string(selected, 3)
    object_id = struct.unpack_from('<I', selected, object_offset)[0]
    list_name, _ = utf16_string(char_list, 17)
    slot = struct.unpack_from('<I', next(p for p in client if p[2] == 0x12), 3)[0]
    count = struct.unpack_from('<I', char_list, 3)[0]
    user_infos = [p for p in server if p[2] == 0x32]
    user_info_matches = sum(utf16_string(p, 23)[0] == character
                            and struct.unpack_from('<I', p, 19)[0] == object_id
                            for p in user_infos)
    npc_ids = {struct.unpack_from('<I', p, 3)[0] for p in server if p[2] == 0x0c}
    targets = [struct.unpack_from('<I', p, 3)[0] for p in client if p[2] == 0x1f]
    checks = {'login_account_matches_server_character_list': account.encode('utf-16le') in char_list,
              'selected_character': character, 'character_list_name_matches': list_name == character,
              'character_count': count, 'selected_slot': slot, 'selected_slot_in_range': slot < count,
              'world_object_id': object_id, 'user_info_packets': len(user_infos),
              'user_info_name_and_object_id_matches': user_info_matches,
              'enter_world_requests': sum(p[2] == 0x11 for p in client),
              'client_move_requests': sum(p[2] == 0x0f for p in client),
              'server_moves_for_own_object': sum(p[2] == 0x2f and struct.unpack_from('<I', p, 3)[0] == object_id
                                                  for p in server),
              'client_actions': len(targets), 'action_targets_seen_in_server_npc_info': sum(t in npc_ids for t in targets),
              'client_position_reports': sum(p[2] == 0x59 for p in client)}
    if not (checks['login_account_matches_server_character_list'] and character == 'X501'
            and list_name == character and slot < count and user_infos
            and user_info_matches == len(user_infos)):
        raise ValueError('Semantic validation failed')
    if not all(row['ciphertext_reproduced'] for row in metadata['client']['packets']):
        raise ValueError('Missing independent native ciphertext verification')
    with args.opcode_table.open(encoding='utf-8-sig', newline='') as source:
        names = {(r['direction'], r['opcode']): r['name'] for r in csv.DictReader(source)}
    csv_text = io.StringIO(newline='')
    writer = csv.DictWriter(csv_text, fieldnames=['direction', 'ordinal', 'opcode', 'reference_name',
                                                 'decoded_length', 'source_record'])
    writer.writeheader()
    for direction, packets in packet_sets.items():
        for ordinal, (packet, row) in enumerate(zip(packets, metadata[direction]['packets']), 1):
            prefix = f'{packet[2]:02X}'
            if packet[2] == (0xd0 if direction == 'client' else 0xfe):
                prefix += f' {packet[3]:02X} {packet[4]:02X}'
            writer.writerow({'direction': direction, 'ordinal': ordinal, 'opcode': prefix,
                             'reference_name': names.get((direction, prefix), ''),
                             'decoded_length': len(packet),
                             'source_record': row.get('outer_record_index', row.get('record_index'))})
    (root / 'packet-index.csv').write_text(csv_text.getvalue(), 'utf-8-sig')
    report = {'validated': True, 'scope': 'Exact supplied capture; semantic checks cover the fields listed below',
              'decoded_server_packets': len(server), 'decoded_client_packets': len(client),
              'client_encrypted_bytes_consumed': metadata['client']['encrypted_bytes_consumed'],
              'all_client_bodies_reencrypted_identically': True,
              'server_python_matches_native': metadata['server']['native_reference_matched'],
              'checks': checks,
              'limitations': 'Opcode names use generic NetPro 448; individual fields of every packet are not fully documented'}
    (root / 'exchange-verification.json').write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
