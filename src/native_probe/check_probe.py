"""Exercise the message hook in a temporary process owned by this script."""
import ctypes
import subprocess
from pathlib import Path


def main():
    folder = Path(__file__).resolve().parents[2] / 'build' / 'native-probe'
    controller = folder / 'controller.exe'
    probe = folder / 'probe.dll'
    target = subprocess.Popen([str(controller), '--target'], stdout=subprocess.PIPE,
                              text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        pid, thread, entry, root = target.stdout.readline().split()
        result = subprocess.run([str(controller), pid, thread, str(probe)],
                                capture_output=True, text=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or result.stdout.strip() != 'observed':
            raise RuntimeError(f'probe failed: {result.returncode}: {result.stdout} {result.stderr}')
        print(f'PASS hook observed on test process {pid}, thread {thread}')
        send_controller = folder / 'send_controller.exe'
        result = subprocess.run([str(send_controller), pid, thread, str(probe),
                                 '0x' + entry, '0x' + root, '72'], input='50\n',
                                capture_output=True, text=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or target.stdout.readline().strip() != 'mock-called':
            raise RuntimeError(f'send dispatch failed: {result.returncode}: {result.stdout} {result.stderr}')
        print('PASS send dispatch reached the mock function on the target thread')
        ctypes.windll.user32.PostThreadMessageW(int(thread), 0x12, 0, 0)
        target.wait(timeout=5)
    finally:
        if target.poll() is None:
            target.terminate()
            target.wait(timeout=5)


if __name__ == '__main__':
    main()
