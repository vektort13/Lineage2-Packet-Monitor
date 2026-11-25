"""Offline server-to-client transform observed in the supplied Prime client.

Derived from the captured x86 routine at 0x053867ac, not a retail L2 cipher.
The initial counter of zero is validated against the complete saved connection.
No networking or process access is performed by this module.
"""


class AsteriosServerCipher:
    def __init__(self, key, packet_counter=0):
        if len(key) != 16:
            raise ValueError('Expected the 16-byte handshake key')
        self.key = bytearray(key)
        self.packet_counter = packet_counter

    def decrypt(self, body):
        size = len(body)
        if not size:
            raise ValueError('Empty body')
        self.packet_counter = (self.packet_counter + 1) & 0xffffffff
        count = self.packet_counter
        if size <= 32:
            value = (count * size) & 0xffffffff
            result = bytes(b ^ self.key[5 + ((value + i) & 7)] for i, b in enumerate(body))
            for index in range(3, 8):
                self.key[index] ^= ((value & 127) + 32) & 255
            return result
        if size <= 84 or (size <= 111 and count % 12 == 0):
            value = (count * 59 + size) & 0xffffffff
            result = bytes(b ^ self.key[2 + ((value + i) & 7)] for i, b in enumerate(body))
            for index in range(2, 5):
                self.key[index] ^= value & 127
            return result
        if size <= 111 and count % 4 == 0:
            return body
        if size > 111 and count > 52 and count % 3 == 0:
            return body
        result = bytearray(size)
        previous = 0
        for index, value in enumerate(body):
            result[index] = value ^ self.key[index & 15] ^ previous
            previous = value
        counter = (int.from_bytes(self.key[8:12], 'little') + size) & 0xffffffff
        self.key[8:12] = counter.to_bytes(4, 'little')
        return bytes(result)
