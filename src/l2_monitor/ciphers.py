"""Selectable body transforms; live detection is validated by complete states."""
import hashlib
import struct

from asterios_game_cipher import AsteriosServerCipher
from reference_xor import ReferenceXor, split_records


CIPHERS = {
    'auto': dict(name='Авто', description='Профиль клиента и проверка конечных состояний'),
    'asterios': dict(name='Asterios · адаптивный', description='Режим зависит от длины и счётчика; C→S — оригинальная функция'),
    'l2xor16': dict(name='L2 · XOR16', description='Стандартный running XOR с 16-байтовым ключом'),
    'l2xor16-u64': dict(name='L2 · XOR16 / 64', description='Running XOR16 с проверенным 64-битным счётчиком клиента'),
    'plain': dict(name='Открытые данные', description='Без преобразования тела'),
}


def server_variant(size, counter):
    if size <= 32:
        return 'asterios:short-xor'
    if size <= 84 or (size <= 111 and counter % 12 == 0):
        return 'asterios:medium-xor'
    if (size <= 111 and counter % 4 == 0) or (size > 111 and counter > 52 and counter % 3 == 0):
        return 'asterios:plain-cyclic'
    return 'asterios:running-xor16'


def xor_encrypt(plain, key):
    output, previous = bytearray(), 0
    for i, value in enumerate(plain):
        previous = value ^ key[i & 15] ^ previous
        output.append(previous)
    return bytes(output)


def alternative(direction, mode, data, frames, before, after):
    if mode not in ('l2xor16', 'plain'):
        raise ValueError('Неизвестный альтернативный шифр')
    records = split_records(data)
    expected = (after[direction + '_counter'] - before[direction + '_counter']) & 0xffffffff
    if len(records) != expected:
        raise ValueError(f'{mode}: число записей {direction} не совпало со счётчиком')
    field = 'incoming_key' if direction == 'server' else 'outgoing_key'
    cipher = ReferenceXor(bytes.fromhex(before[field]))
    packets, index, offset = [], [], 0
    for ordinal, record in enumerate(records, 1):
        old_key = bytes(cipher.key)
        body = cipher.decrypt(record[2:]) if mode == 'l2xor16' else record[2:]
        if direction == 'client' and mode == 'l2xor16' and xor_encrypt(body, old_key) != record[2:]:
            raise ValueError('XOR16: обратное шифрование не совпало')
        packet = struct.pack('<H', len(body) + 2) + body
        packets.append(packet)
        index.append(dict(ordinal=ordinal, completion_frame=frames[offset + len(record) - 1],
                          compressed=direction == 'server' and body[0] == 0x8d,
                          mode=mode, ciphertext_reproduced=direction == 'client'))
        offset += len(record)
    if cipher.key.hex() != after[field]:
        raise ValueError(f'{mode}: конечный ключ {direction} не совпал')
    if direction == 'client' and before['client_header_state'] & 0xffff != after['client_header_state'] & 0xffff:
        raise ValueError(f'{mode}: состояние длины не соответствует открытому заголовку')
    return packets, index


def decrypt_body(body, mode, key, counter=0):
    if mode == 'auto':
        raise ValueError('Автоопределение требует интервала пакетов и контрольных состояний клиента')
    if mode not in CIPHERS:
        raise ValueError('Неизвестный шифр')
    if mode == 'plain':
        return body, key, counter
    if len(key) != 16:
        raise ValueError('Требуется ключ из 16 байт')
    if mode == 'asterios':
        cipher = AsteriosServerCipher(key, counter)
        result = cipher.decrypt(body)
        return result, bytes(cipher.key), cipher.packet_counter
    if mode == 'l2xor16-u64':
        from .classic_cipher import RunningXor64
        cipher = RunningXor64(key)
        result = cipher.decrypt(body)
        return result, bytes(cipher.key), (counter + 1) & 0xffffffff
    cipher = ReferenceXor(key)
    result = cipher.decrypt(body)
    return result, bytes(cipher.key), (counter + 1) & 0xffffffff
