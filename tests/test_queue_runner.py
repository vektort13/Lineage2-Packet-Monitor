import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from l2_monitor.packet_queue import PacketQueue
from l2_monitor.queue_runner import QueueRunner
from l2_monitor.sender import NativeSender


class Sender:
    def __init__(self):
        self.sent = []
        self.fail_at = None
        self.entered, self.release = threading.Event(), threading.Event()
        self.hold = False
    prepare = staticmethod(NativeSender.prepare_legacy)
    def status(self):
        return dict(available=True)
    def send(self, raw, source, cancel):
        self.sent.append((raw, time.monotonic()))
        self.entered.set()
        if self.hold:
            self.release.wait(2)
        if len(self.sent) == self.fail_at:
            raise RuntimeError('unconfirmed')


class QueueRunnerTests(unittest.TestCase):
    def setUp(self):
        self.session = 'one'
        monitor = SimpleNamespace(status=lambda: dict(running=True, state='live', session_id=self.session))
        for name in ('inventory_drop', 'auto_pickup', 'skill_actions', 'newbie_buff'):
            setattr(monitor, name, SimpleNamespace(snapshot=lambda: dict(active=False)))
        self.queue, self.sender = PacketQueue(), Sender()
        self.runner = QueueRunner(monitor, self.queue, self.sender)
    def tearDown(self):
        self.sender.release.set()
        self.runner.close()
    def add(self, raw='030050', direction='client'):
        self.queue.add(dict(raw_hex=raw, direction=direction))
    def wait(self):
        self.runner.thread.join(3)
        self.assertFalse(self.runner.snapshot()['active'])

    def test_cycles_preserve_order_and_interval(self):
        self.add()
        self.add('0f0073040000000100000000000000')
        self.runner.start(2, 60)
        self.wait()
        self.assertEqual([r[0][2] for r in self.sender.sent], [0x50, 0x73, 0x50, 0x73])
        self.assertTrue(all(b[1] - a[1] >= .05 for a, b in zip(self.sender.sent, self.sender.sent[1:])))
        self.assertEqual(self.runner.snapshot()['completed'], 4)
        self.assertEqual(self.runner.snapshot()['state'], 'completed')

    def test_pause_blocks_next_packet_and_resume_continues(self):
        self.add()
        self.sender.hold = True
        self.runner.start(3, 0)
        self.assertTrue(self.sender.entered.wait(1))
        self.runner.pause(True)
        self.sender.release.set()
        time.sleep(.12)
        self.assertEqual(len(self.sender.sent), 1)
        self.runner.pause(False)
        self.wait()
        self.assertEqual(len(self.sender.sent), 3)

    def test_stop_during_pause_cancels_remaining(self):
        self.add()
        self.sender.hold = True
        self.runner.start(10, 0)
        self.assertTrue(self.sender.entered.wait(1))
        self.runner.pause(True)
        self.runner.stop()
        self.sender.release.set()
        self.wait()
        self.assertEqual(len(self.sender.sent), 1)
        self.assertEqual(self.runner.snapshot()['state'], 'stopped')

    def test_whole_queue_rejects_server_packets_before_any_send(self):
        self.add()
        self.add(direction='server')
        with self.assertRaisesRegex(ValueError, '2:'):
            self.runner.start()
        self.assertEqual(self.sender.sent, [])
        self.assertIn('Строка 2:',self.runner.validation_error())
        self.assertIn('S→C',self.runner.validation_error())

    def test_failure_stops_without_retry(self):
        self.add()
        self.sender.fail_at = 2
        self.runner.start(5, 0)
        self.wait()
        self.assertEqual(len(self.sender.sent), 2)
        self.assertEqual(self.runner.snapshot()['completed'], 1)
        self.assertEqual(self.runner.snapshot()['state'], 'failed')


    def test_session_change_cancels_remaining_packets(self):
        self.add()
        self.sender.hold = True
        self.runner.start(5, 0)
        self.assertTrue(self.sender.entered.wait(1))
        self.session = 'two'
        self.sender.release.set()
        self.wait()
        self.assertEqual(len(self.sender.sent), 1)
        self.assertEqual(self.runner.snapshot()['state'], 'failed')


class SenderTests(unittest.TestCase):
    def setUp(self):
        self.items = [dict(id=1, direction='client', raw_hex='030050')]
        store = SimpleNamespace(lock=threading.RLock(), items=self.items, stats=lambda: dict(total=len(self.items)))
        self.calls = []
        def skill(status, *args):
            self.calls.append(args)
            if self.capture:
                self.items.append(dict(id=len(self.items) + 1, direction='client', raw_hex='030050'))
            return dict(sent=1)
        self.capture = True
        transport = SimpleNamespace(skill=skill)
        monitor = SimpleNamespace(store=store, inventory_drop=SimpleNamespace(transport=transport),
            status=lambda: dict(running=True, state='live', session_id='one', sync_errors=0))
        self.sender = NativeSender(monitor)

    def test_new_outgoing_bytes_confirm_transmission(self):
        result = self.sender.send(bytes.fromhex('030050'), dict(direction='client'))
        self.assertEqual(result['packet_id'], 2)
        self.assertEqual(result['confirmation'], 'client-capture')
        self.assertEqual(self.calls, [('list',)])

    def test_old_capture_does_not_confirm_a_new_call(self):
        self.capture = False
        with patch('l2_monitor.sender.time.monotonic', side_effect=[0, 21]):
            with self.assertRaisesRegex(RuntimeError, 'без повтора'):
                self.sender.send(bytes.fromhex('030050'))
        self.assertEqual(len(self.calls), 1)

    def test_cancel_before_call_has_no_side_effect(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(InterruptedError):
            self.sender.send(bytes.fromhex('030050'), cancel=cancel)
        self.assertEqual(self.calls, [])

    def test_client_diagnostic_is_reported_without_retry(self):
        def rejected(*args):
            self.calls.append(args)
            self.items.append(dict(id=2, direction='client', fields=dict(event='client_diagnostic',
                diagnostic_format_verified=True, reported_opcode='0x50', message='CMPF0: 6B8C11AD [0x50]')))
            return dict(sent=1)
        self.sender.monitor.inventory_drop.transport.skill = rejected
        with self.assertRaisesRegex(RuntimeError, 'CMPF0'):
            self.sender.send(bytes.fromhex('030050'))
        self.assertEqual(len(self.calls), 1)

    def test_arbitrary_and_extended_client_bodies_remain_exact(self):
        for raw in ('060099ff0010', '0700d0f100aabb', '0f0073000000000000000003000000', '07002300d80000'):
            packet = bytes.fromhex(raw)
            self.assertEqual(self.sender.prepare(packet, dict(direction='client')), ('send_packet', (packet[2:],)))
        with self.assertRaises(ValueError):
            self.sender.prepare(bytes.fromhex('030050'), dict(direction='server'))

    def test_history_remains_bounded_across_many_calls(self):
        for _ in range(110):
            self.sender.send(bytes.fromhex('030050'))
        self.assertEqual(len(self.sender.history), 100)
        self.assertFalse(self.sender.status()['pending'])

    def test_direct_send_cannot_interleave_with_paused_queue(self):
        self.sender.monitor.packet_queue_runner = SimpleNamespace(thread=None, snapshot=lambda: dict(active=True))
        with self.assertRaisesRegex(ValueError, 'очереди пакетов'):
            self.sender.send(bytes.fromhex('030050'))
        self.assertEqual(self.calls, [])

    def test_simultaneous_send_is_rejected(self):
        self.sender.lock.acquire()
        try:
            with self.assertRaisesRegex(ValueError, 'Предыдущая'):
                self.sender.send(bytes.fromhex('030050'))
            self.assertEqual(self.calls, [])
        finally:
            self.sender.lock.release()

    def classic(self):
        status=dict(running=True,state='live',session_id='one',sync_errors=0,
                    detected_cipher='l2xor16-u64',profile='verified-classic',actions_supported=False)
        self.sender.monitor.status=lambda:dict(status)
        profile=dict(packet_requests=dict(sender='list_requests',format='cb',max_body_bytes=32766),
                     opcode_map_count=209,extended_map_count=152)
        return status,profile

    def test_classic_queue_uses_its_own_capability_and_exact_raw_dispatch(self):
        status,profile=self.classic()
        raw=bytes.fromhex('0f007c4b1200000100000000000000')
        def dispatch(initial,selected,body):
            self.assertEqual(selected,profile)
            self.assertEqual(body,raw[2:])
            self.items.append(dict(id=2,direction='client',raw_hex=raw.hex()))
            return dict(sent=1)
        with patch('l2_monitor.sender._queue_profile',return_value=profile), \
             patch('l2_monitor.sender.request_packet',side_effect=dispatch) as send:
            self.assertTrue(self.sender.status()['available'])
            self.assertTrue(self.sender.status()['generic_packets'])
            self.assertEqual(self.sender.prepare(raw,dict(direction='client')),('classic_packet',(raw[2:],)))
            result=self.sender.send(raw,dict(direction='client'))
            self.assertEqual(result['packet_id'],2)
            send.assert_called_once()
        self.assertEqual(self.calls,[])  # No menu search, alternate request, or legacy transport.

    def test_classic_queue_cannot_fall_back_to_another_build_or_server_direction(self):
        status,profile=self.classic()
        with patch('l2_monitor.sender._queue_profile',return_value=None), \
             patch('l2_monitor.sender.request_packet') as send:
            self.assertFalse(self.sender.status()['available'])
            with self.assertRaises(ValueError):self.sender.send(bytes.fromhex('030050'))
            send.assert_not_called()
        with patch('l2_monitor.sender._queue_profile',return_value=profile):
            for raw,source in ((bytes.fromhex('030050'),dict(direction='server')),
                               (bytes.fromhex('0300ff'),dict(direction='client')),
                               (bytes.fromhex('0500d09800'),dict(direction='client')),
                               (bytes.fromhex('030050'),dict(direction='client',data_layer='tcp-payload'))):
                with self.assertRaises(ValueError):self.sender.prepare(raw,source)
        self.assertEqual(self.calls,[])

    def test_classic_zero_interval_cycles_confirm_each_new_packet_in_order(self):
        status,profile=self.classic()
        monitor=self.sender.monitor
        for name in ('inventory_drop','auto_pickup','skill_actions','newbie_buff'):
            obj=getattr(monitor,name,None) or SimpleNamespace()
            obj.snapshot=lambda:dict(active=False)
            setattr(monitor,name,obj)
        queue=PacketQueue()
        for raw in ('030014','030050'):
            queue.add(dict(raw_hex=raw,direction='client'))
        runner=QueueRunner(monitor,queue,self.sender)
        monitor.packet_queue_runner=runner
        sent=[]
        def dispatch(initial,selected,body):
            sent.append(body)
            self.items.append(dict(id=len(self.items)+1,direction='client',raw_hex=(len(body)+2).to_bytes(2,'little').hex()+body.hex()))
            return dict(sent=1)
        with patch('l2_monitor.sender._queue_profile',return_value=profile), \
             patch('l2_monitor.sender.request_packet',side_effect=dispatch):
            runner.start(3,0)
            runner.thread.join(3)
            self.assertEqual(runner.snapshot()['state'],'completed')
            self.assertEqual(runner.snapshot()['completed'],6)
            self.assertEqual(sent,[b'\x14',b'\x50']*3)
        runner.close()

