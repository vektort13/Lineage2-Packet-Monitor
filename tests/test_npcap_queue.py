import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from l2_monitor.npcap import packet_row
from l2_monitor.packet_queue import PacketQueue


class PacketReaderTests(unittest.TestCase):
    def frame(self,pppoe=False,vlan=False):
        payload=b'\x03\x00\x7d'
        tcp=struct.pack('!HHIIBBHHH',2110,26087,0xfffffff0,100,0x50,0x18,2048,0,0)+payload
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0x4000,64,6,0,
                       socket.inet_aton('146.59.110.40'),socket.inet_aton('2.49.171.25'))+tcp
        protocol=0x8864 if pppoe else 0x0800
        body=struct.pack('!BBHHH',0x11,0,1,len(ip)+2,0x21)+ip if pppoe else ip
        if vlan:body=struct.pack('!HH',7,protocol)+body;protocol=0x8100
        return bytes(12)+struct.pack('!H',protocol)+body

    def test_ethernet_vlan_and_pppoe_keep_tcp_payload_exact(self):
        for pppoe in (False,True):
            for vlan in (False,True):
                with self.subTest(pppoe=pppoe,vlan=vlan):
                    row=packet_row(self.frame(pppoe,vlan),1,'123.456789',7)
                    self.assertEqual(row['tcp.payload'],'03007d')
                    self.assertEqual(row['tcp.seq_raw'],str(0xfffffff0))
                    self.assertEqual(row['ip.src'],'146.59.110.40')
                    self.assertEqual(row['tcp.dstport'],'26087')

    def test_truncation_and_fragments_do_not_invent_bytes(self):
        frame=self.frame()
        self.assertIsNone(packet_row(frame[:-1],1,'1',1))
        fragmented=bytearray(frame);fragmented[14+6:14+8]=b'\x20\x00'
        self.assertIsNone(packet_row(fragmented,1,'1',1))
        self.assertIsNone(packet_row(frame,999,'1',1))


class PacketQueueTests(unittest.TestCase):
    def test_copies_reorder_and_remove(self):
        queue=PacketQueue()
        packet=dict(raw_hex='03007d',fields={'value':1},name='Test')
        first=queue.add(packet);second=queue.add(packet)
        packet['fields']['value']=9
        self.assertEqual(queue.items()[0]['fields']['value'],1)
        queue.move(second,-1)
        self.assertEqual(queue.items()[0]['queue_id'],second)
        queue.remove(first)
        self.assertEqual(len(queue.items()),1)
        queue.clear()
        self.assertEqual(queue.items(),[])

    def test_queue_has_no_local_playback_or_transport(self):
        queue=PacketQueue()
        queue.add(dict(raw_hex='03007d'))
        self.assertFalse(hasattr(queue,'start'))
        self.assertFalse(hasattr(queue,'send'))


if __name__=='__main__':unittest.main()
