"""Read the validated client layout and its actual DEFLATE dictionary."""
import hashlib
import json
import struct
import time
import os
import sys
from pathlib import Path

from emulate_capture_function import ReadOnlyProcess


ROOT = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
ASSET_ROOT = ROOT
DATA_ROOT = (Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local'))) / 'L2PacketMonitor'
             if getattr(sys, 'frozen', False) else ROOT)


def load_profile():
    return json.loads((ROOT / 'config/monitor-profile.json').read_text('utf-8'))


def supports_profile(executable, profile=None):
    profile = profile or load_profile()
    engine = Path(executable).parent / 'Engine.dll'
    return engine.is_file() and hashlib.sha256(engine.read_bytes()).hexdigest() == profile['engine_sha256']


class LiveState:
    def __init__(self, pid, executable, profile=None):
        self.profile = profile or load_profile()
        engine = Path(executable).parent / 'Engine.dll'
        if hashlib.sha256(engine.read_bytes()).hexdigest() != self.profile['engine_sha256']:
            raise ValueError('Сборка Engine.dll не совпадает с проверенным профилем')
        self.process = ReadOnlyProcess(pid)
        try:
            for item in self.profile['fingerprints']:
                data = self.process.read(item['address'], item['size'])
                if hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('Расположение или код шифра изменились; нужен другой профиль')
        except Exception:
            self.close()
            raise

    def _read(self):
        p, config = self.process, self.profile
        root = struct.unpack('<I', p.read(config['root_pointer'], 4))[0]
        socket = struct.unpack('<I', p.read(root + config['socket_offset'], 4))[0]
        if struct.unpack('<I', p.read(socket, 4))[0] != config['socket_vtable']:
            raise ValueError('Сетевая структура клиента не соответствует профилю')
        counters = p.read(config['counter_address'], 8)
        outgoing = p.read(socket + config['outgoing_key_offset'] + 1, 16)
        incoming = p.read(socket + config['incoming_key_offset'] + 1, 16)
        header = p.read(config['header_address'], 4)
        state = struct.unpack('<I', p.read(config['zstream_address'] + 28, 4))[0]
        raw = p.read(state, 64)
        mode, last, wrap = struct.unpack_from('<3I', raw)
        wbits, size, have, write, window, hold, bits = struct.unpack_from('<7I', raw, 36)
        if (wbits != 15 or size not in (0, 32768) or have > size or write >= max(size, 1)
                or bits != 0 or hold != 0 or mode != 11 or wrap != 0 or last != 0):
            raise ValueError('Контекст DEFLATE ещё не находится на проверенной границе блока')
        dictionary = b''
        if have:
            ring = p.read(window, size)
            dictionary = (ring[write:] + ring[:write])[-have:]
        return socket, counters, outgoing, incoming, header, raw, dictionary

    def snapshot(self):
        for _ in range(30):
            start = time.time_ns()
            try:
                first = self._read()
                time.sleep(0.003)
                second = self._read()
            except ValueError:
                time.sleep(0.01)
                continue
            end = time.time_ns()
            if first == second:
                socket, counters, outgoing, incoming, header, raw, dictionary = first
                server_count, client_count = struct.unpack('<II', counters)
                return dict(read_start_ns=start, read_end_ns=end, socket=hex(socket),
                            server_counter=server_count, client_counter=client_count,
                            outgoing_key=outgoing.hex(), incoming_key=incoming.hex(),
                            client_header_state=struct.unpack('<I', header)[0],
                            dictionary=dictionary, dictionary_sha256=hashlib.sha256(dictionary).hexdigest(),
                            inflate_total=struct.unpack_from('<I', raw, 28)[0])
        raise ValueError('Не удалось получить согласованное состояние клиента; повтор синхронизации')

    def close(self):
        self.process.close()
