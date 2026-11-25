import http.client
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

from l2_monitor.engine import Monitor
from l2_monitor.http_api import ApiServer


class SourceApiTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.monitor=Monitor(library_path=Path(self.folder.name)/'library.json')
        self.server=ApiServer(('127.0.0.1',0),self.monitor)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.05},daemon=True)
        self.thread.start()

    def tearDown(self):
        self.monitor.stop()
        self.monitor.bridge_stop()
        self.monitor.skill_actions.close()
        self.monitor.auto_heal.close()
        self.server.shutdown();self.server.server_close();self.thread.join(2)
        self.folder.cleanup()

    def request(self,method,path,data=None,authorized=True):
        client=http.client.HTTPConnection(*self.server.server_address,timeout=5)
        headers={'Content-Type':'application/json'}
        if authorized:headers['X-Monitor-Token']=self.server.token
        client.request(method,path,json.dumps(data).encode() if data is not None else None,headers)
        response=client.getresponse(); raw=response.read();status=response.status
        client.close()
        return status,raw

    def test_source_selection_is_authenticated_and_rejects_unknown_modes(self):
        self.assertEqual(self.request('POST','/api/source',{'mode':'server'},False)[0],403)
        self.assertEqual(self.monitor.source_mode,'auto')
        self.assertEqual(self.request('POST','/api/source',{'mode':'guess-any-cipher'})[0],400)
        status,raw=self.request('POST','/api/source',{'mode':'server'})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(raw)['mode'],'server')

    def test_resource_recovery_has_independent_authenticated_settings(self):
        status, raw = self.request('GET', '/api/recovery')
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(raw)), {'cp', 'hp', 'mp'})
        config = dict(resource='mp', enabled=True, item_id=728, threshold=60, interval_ms=3000)
        self.assertEqual(self.request('POST', '/api/recovery', config, False)[0], 403)
        status, raw = self.request('POST', '/api/recovery', config)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)['enabled'])
        self.assertFalse(self.monitor.auto_heal.enabled)
        self.assertFalse(self.monitor.recovery['cp'].enabled)
        config['resource'] = 'other'
        self.assertEqual(self.request('POST', '/api/recovery', config)[0], 400)
        config.update(resource='hp', enabled=False, item_id=1539)
        self.assertEqual(self.request('POST', '/api/auto-heal', config)[0], 200)
        self.assertEqual(self.monitor.recovery['hp'].item_id, 1539)

    def test_api_start_selects_server_mode_without_game_or_network_capture(self):
        status,raw=self.request('POST','/api/start',{'source':'server'})
        self.assertEqual(status,202)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline and not self.monitor.bridge.snapshot()['running']:
            time.sleep(.01)
        self.assertEqual(self.monitor.status()['active_source'],'server')
        self.assertTrue(self.monitor.bridge.snapshot()['running'])
        self.assertEqual(self.request('POST','/api/source',{'mode':'network'})[0],400)
        self.assertEqual(self.monitor.source_mode,'server')

    def test_bridge_export_contains_current_sdk_and_secret_only_in_explicit_config(self):
        status,raw=self.request('POST','/api/bridge/export',{})
        self.assertEqual(status,200)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertTrue({'bridge.json','bridge_sender.py','L2PlaintextBridge.java','README.md'}<=set(archive.namelist()))
            config=json.loads(archive.read('bridge.json'))
            self.assertTrue(config['token'])
            self.assertTrue(config['endpoint'].startswith('http://127.0.0.1:'))
        status,sources=self.request('GET','/api/sources')
        self.assertEqual(status,200)
        self.assertNotIn(config['token'].encode(),sources)
        self.assertEqual(self.request('POST','/api/bridge/configuration',{},False)[0],403)
        status,explicit=self.request('POST','/api/bridge/configuration',{})
        self.assertEqual(json.loads(explicit)['token'],config['token'])
        self.assertEqual(self.request('POST','/api/bridge/stop',{})[0],200)
        self.assertFalse(self.monitor.bridge.snapshot()['running'])

    def test_profile_export_preserves_both_verified_algorithms_without_session_keys(self):
        status,raw=self.request('GET','/api/profiles/export')
        self.assertEqual(status,200)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            manifest=json.loads(archive.read('registry.json'))
            self.assertTrue({'asterios','l2xor16-u64'} <= {row['algorithm'] for row in manifest['profiles']})
            for row in manifest['profiles']:
                profile=json.loads(archive.read(row['profile']))
                self.assertEqual(profile['engine_sha256'],row['engine_sha256'])
                self.assertNotIn('incoming_key',profile)
                self.assertNotIn('outgoing_key',profile)


if __name__=='__main__':unittest.main()
