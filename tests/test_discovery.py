import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from l2_monitor import discovery
from l2_monitor.sender import NativeSender
from l2_monitor.wire_capture import wire_packet


def endpoint(port=43129):
    return dict(local_ip='192.0.2.1', local_port=50123, remote_ip='198.51.100.2', remote_port=port)


def client(pid=1, port=43129):
    return dict(pid=pid, profile_candidate=False, connections=[endpoint(port)])


class DiscoveryTests(unittest.TestCase):
    def test_unprofiled_client_on_custom_port_is_detected(self):
        with patch.object(discovery, 'processes', return_value=[client()]):
            process, connection = discovery.select_process()
        self.assertEqual(process['pid'], 1)
        self.assertEqual(connection['remote_port'], 43129)

    def test_multiple_clients_require_selection_and_explicit_pid_works(self):
        with patch.object(discovery, 'processes', return_value=[client(), client(2, 7777)]):
            with self.assertRaises(ValueError):
                discovery.select_process()
            self.assertEqual(discovery.select_process(1)[0]['pid'], 1)

    def test_known_game_port_disambiguates_auxiliary_connection(self):
        process = client(port=2106)
        process['connections'].append(endpoint(7777))
        with patch.object(discovery, 'processes', return_value=[process]):
            self.assertEqual(discovery.select_process()[1]['remote_port'], 7777)

    def test_unknown_ambiguous_connections_are_not_guessed(self):
        process = client()
        process['connections'].append(endpoint(45001))
        with patch.object(discovery, 'processes', return_value=[process]):
            with self.assertRaises(ValueError):
                discovery.select_process()

    def test_adapter_follows_local_address_and_loopback(self):
        physical = dict(id='1', device='physical', name='Ethernet', recommended=True, addresses=['192.0.2.3'])
        virtual = dict(id='2', device='virtual', name='VM', recommended=False, addresses=['192.0.2.1'])
        loopback = dict(id='3', device='NPF_Loopback', name='loopback', recommended=False)
        with patch.object(discovery, 'interfaces', return_value=[physical, virtual, loopback]):
            self.assertEqual(discovery.select_interface(endpoint=endpoint()), virtual)
            self.assertEqual(discovery.select_interface(endpoint=dict(endpoint(), remote_ip='127.0.0.1')), loopback)
            self.assertEqual(discovery.select_interface('1', endpoint()), physical)


class WireCaptureTests(unittest.TestCase):
    def row(self):
        return {'ip.src':'192.0.2.1', 'tcp.srcport':'50123', 'ip.dst':'198.51.100.2',
                'tcp.dstport':'43129', 'tcp.payload':'030050', 'frame.number':'7',
                'frame.time_epoch':'100.5', 'tcp.seq_raw':'123'}

    def test_bytes_remain_tcp_data_without_invented_opcode_or_fields(self):
        packet = wire_packet(self.row(), endpoint(), 'session')
        self.assertEqual(packet['raw_hex'], '030050')
        self.assertEqual(packet['opcode'], 'TCP')
        self.assertEqual(packet['status'], 'wire')
        self.assertEqual(packet['direction'], 'client')
        self.assertEqual(packet['fields']['event'], 'tcp_payload')
        with self.assertRaises(ValueError):
            NativeSender.validate_source(bytes.fromhex(packet['raw_hex']), packet)

    def test_remote_direction_empty_ack_and_unrelated_connection(self):
        row = self.row()
        row['ip.src'], row['ip.dst'] = row['ip.dst'], row['ip.src']
        row['tcp.srcport'], row['tcp.dstport'] = row['tcp.dstport'], row['tcp.srcport']
        self.assertEqual(wire_packet(row, endpoint(), 's')['direction'], 'server')
        self.assertIsNone(wire_packet(dict(row, **{'tcp.payload':''}), endpoint(), 's'))
        self.assertIsNone(wire_packet(dict(row, **{'tcp.dstport':'50124'}), endpoint(), 's'))
