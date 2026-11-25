"""Decode recorded client diagnostics without assigning undocumented semantics."""
import re


_THREAD = re.compile(
    r'Packet Fake Send Thrd \[0x([0-9a-fA-F]{1,2})\] '
    r'([0-9]+) != ([0-9]+) \| Error \[([0-9a-fA-F]{8})\]')
_CMPF0 = re.compile(r'CMPF0: ([0-9a-fA-F]{8}) \[0x([0-9a-fA-F]{1,2})\]')


def parse_client_diagnostic(packet):
    """Return fields for the observed FF/04/02 envelope, or None.

    The two numbers in the thread message are deliberately named left/right:
    the text alone does not establish where either number was obtained.
    CMPF0's number is retained as a value, not labelled as a return address.
    """
    if packet[2:5] != b'\xff\x04\x02':
        return None
    payload = packet[5:]
    if not payload.endswith(b'\x00'):
        raise ValueError('Client diagnostic message is not terminated')
    if b'\x00' in payload[:-1]:
        raise ValueError('Unexpected data after client diagnostic terminator')
    message = payload[:-1].decode('ascii')
    kind = ('thread' if message.startswith('Packet Fake Send Thrd') else
            'cmpf0' if message.startswith('CMPF0:') else 'unknown')
    result = dict(event='client_diagnostic', message=message,
                  diagnostic_type=kind, diagnostic_format_verified=False)
    match = _THREAD.fullmatch(message)
    if match:
        opcode, left, right, error = match.groups()
        result.update(diagnostic_format_verified=True,
                      reported_opcode=f'0x{int(opcode, 16):02X}',
                      thread_id_left=int(left), thread_id_right=int(right),
                      thread_ids_differ=int(left) != int(right),
                      error_code=f'0x{error.upper()}')
    elif (match := _CMPF0.fullmatch(message)):
        value, opcode = match.groups()
        result.update(diagnostic_format_verified=True,
                      reported_opcode=f'0x{int(opcode, 16):02X}',
                      diagnostic_value=f'0x{value.upper()}')
    return result
