"""Retained offline ABI experiment. This module never accesses a live process."""
import struct


def call_stub(entry, socket, format_address, body_address, size, done_address):
    return (b'\x55\x8b\xec' + b'\x68' + struct.pack('<I', body_address)
        + b'\x68' + struct.pack('<I', size) + b'\x68' + struct.pack('<I', format_address)
        + b'\x68' + struct.pack('<I', socket) + b'\xb8' + struct.pack('<I', entry)
        + b'\xff\xd0\x83\xc4\x10\xc7\x05' + struct.pack('<I', done_address)
        + b'\x01\x00\x00\x00\x33\xc0\x8b\xe5\x5d\xc2\x04\x00')
