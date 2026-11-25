"""Exercise the local dashboard in an isolated headless Chrome instance."""
import base64
import json
import subprocess
import socket
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / 'reports/monitor-browser-test'
    output.mkdir(exist_ok=True)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    debug = f'http://127.0.0.1:{port}'
    profile = tempfile.mkdtemp(prefix='l2-monitor-browser-')
    browser_log = (output / 'browser.log').open('wb')
    chrome = subprocess.Popen(['C:/Program Files/Google/Chrome/Application/chrome.exe',
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--do-not-de-elevate',
        '--user-data-dir=' + profile, f'--remote-debugging-port={port}',
        '--remote-allow-origins=' + debug, '--window-size=1600,1050', 'about:blank'],
        stdout=browser_log, stderr=browser_log,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    ws = None
    try:
        for _ in range(50):
            try:
                request = urllib.request.Request(debug + '/json/new?http://127.0.0.1:8765', method='PUT')
                target = json.load(urllib.request.urlopen(request, timeout=1))
                break
            except OSError:
                if chrome.poll() not in (None, 0):
                    raise RuntimeError('Browser exited: ' + str(chrome.returncode))
                time.sleep(0.2)
        else:
            raise RuntimeError('Chrome DevTools did not start')
        ws = websocket.create_connection(target['webSocketDebuggerUrl'], timeout=10,
                                         origin=debug)
        sequence = 0

        def call(method, params=None):
            nonlocal sequence
            sequence += 1
            ws.send(json.dumps(dict(id=sequence, method=method, params=params or {})))
            while True:
                response = json.loads(ws.recv())
                if response.get('id') == sequence:
                    if 'error' in response:
                        raise RuntimeError(response['error'])
                    return response['result']

        def evaluate(expression):
            result = call('Runtime.evaluate', dict(expression=expression, returnByValue=True, awaitPromise=True))
            if 'exceptionDetails' in result:
                raise RuntimeError(result['exceptionDetails'])
            return result['result'].get('value')

        def wait_for(expression, timeout=30):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if evaluate(expression):
                    return
                time.sleep(0.3)
            raise RuntimeError('Browser condition failed: ' + expression)

        wait_for("document.querySelectorAll('#packets tr').length > 0", 40)
        ui = evaluate("({rows:document.querySelectorAll('#packets tr').length,status:document.querySelector('#connection').textContent,colors:[...new Set([...document.querySelectorAll('#packets tr')].map(x=>x.style.getPropertyValue('--category')))],cipherOptions:document.querySelector('#cipher').options.length,overflow:document.documentElement.scrollWidth>innerWidth})")
        assert not ui['overflow'], ui
        assert ui['cipherOptions'] == 4, ui
        (output / 'dashboard.png').write_bytes(base64.b64decode(call('Page.captureScreenshot', {'format':'png'})['data']))
        evaluate("document.querySelector('#packets tr').click()")
        wait_for("!document.querySelector('#editCopy').hidden")
        evaluate("document.querySelector('#editCopy').click()")
        wait_for("document.querySelector('#hex').value.length>0")
        source = evaluate("({id:state.editorSource.id,hex:state.editorSource.raw_hex})")
        evaluate("document.querySelector('#hex').value=document.querySelector('#hex').value.trim().slice(0,-2)+(parseInt(document.querySelector('#hex').value.trim().slice(-2),16)^1).toString(16).padStart(2,'0');document.querySelector('#hex').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#saveDraft').click()")
        wait_for("!document.querySelector('#downloadDraft').hidden")
        draft_url = evaluate("document.querySelector('#downloadDraft').getAttribute('href')")
        binary = urllib.request.urlopen('http://127.0.0.1:8765' + draft_url).read()
        original = json.load(urllib.request.urlopen('http://127.0.0.1:8765/api/packets/' + str(source['id'])))
        assert original['raw_hex'] == source['hex']
        assert binary[-1] == (bytes.fromhex(source['hex'])[-1] ^ 1)
        assert binary != bytes.fromhex(source['hex'])
        (output / 'editor.png').write_bytes(base64.b64decode(call('Page.captureScreenshot', {'format':'png'})['data']))
        evaluate("document.querySelector('#newBuffer').click();document.querySelector('#encoding').value='utf-16le';document.querySelector('#text').value='X501\\\\0';document.querySelector('#text').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#toHex').click()")
        wait_for("document.querySelector('#hex').value==='58 00 35 00 30 00 31 00 00 00'")
        evaluate("document.querySelector('#noTypes').click()")
        time.sleep(1.5)
        assert evaluate("document.querySelectorAll('#packets tr').length===0")
        evaluate("document.querySelector('#allTypes').click()")
        wait_for("document.querySelectorAll('#packets tr').length>0")
        evaluate("document.querySelector('#categories input').click()")
        time.sleep(1.5)
        assert evaluate("document.querySelectorAll('#packets tr').length===0")
        evaluate("document.querySelector('#categories input').click()")
        wait_for("document.querySelectorAll('#packets tr').length>0")
        wait_for("document.querySelectorAll('#libraryRows tr').length>0")
        library = evaluate("({rows:document.querySelectorAll('#libraryRows tr').length,types:document.querySelectorAll('#packetTypes input').length})")
        assert evaluate("document.querySelector('#sendPacket').disabled && document.querySelector('#sendStatus').textContent.includes('Fake Send Thrd')")
        evaluate("document.querySelector('.library-panel').scrollIntoView()")
        (output / 'library.png').write_bytes(base64.b64decode(call('Page.captureScreenshot', {'format':'png'})['data']))
        result = dict(dashboard=ui, editor_saved_bin=True, original_unchanged=True,
                      utf16_text_to_hex=True, draft_url=draft_url,
                      checkbox_filters_verified=True, library=library, rejected_sender_disabled=True)
        (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', 'utf-8')
        print(json.dumps(result), flush=True)
    finally:
        if ws:
            try:
                ws.send(json.dumps(dict(id=99999, method='Browser.close')))
            except OSError:
                pass
            ws.close()
        try:
            chrome.wait(timeout=8)
        except subprocess.TimeoutExpired:
            chrome.terminate()
            chrome.wait(timeout=5)
        browser_log.close()


if __name__ == '__main__':
    main()
