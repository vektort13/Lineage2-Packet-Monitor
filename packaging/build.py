"""Build the self-contained native Windows executable.

Only the public opcode catalog and a current-build layout profile are bundled.
The private cipher pages and packet captures stay outside the executable.
"""
import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from PySide6.QtCore import QLibraryInfo


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'build-assets' / 'config'

def unicorn_runtime():
    """Use the pinned wheel; retain the original local research fallback."""
    module = importlib.util.find_spec('unicorn')
    if module and module.origin:
        return Path(module.origin).resolve().parents[1]
    legacy = ROOT / 'reports' / 'decryption-20261121' / 'emulation-runtime'
    if (legacy / 'unicorn' / 'lib' / 'unicorn.dll').is_file():
        return legacy
    raise SystemExit('Install build dependencies: python -m pip install -r requirements-dev.txt')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dist-dir', type=Path, default=ROOT / 'dist',
                        help='Destination for the executable (defaults to dist)')
    args = parser.parse_args()
    dist_dir = args.dist_dir.resolve()
    runtime = unicorn_runtime()
    subprocess.run([str(ROOT / 'packaging' / 'build_drop.cmd')], cwd=ROOT, check=True)
    subprocess.run([str(ROOT / 'packaging' / 'build_tap.cmd')], cwd=ROOT, check=True)
    ASSETS.mkdir(parents=True, exist_ok=True)
    profile = json.loads((ROOT / 'config' / 'monitor-profile.json').read_text('utf-8'))
    profile['snapshot_dirs'] = []
    profile['runtime_path'] = '.'
    (ASSETS / 'monitor-profile.json').write_text(
        json.dumps(profile, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (ASSETS / 'opcodes-448.csv').write_bytes((ROOT / 'config' / 'opcodes-448.csv').read_bytes())
    (ASSETS / 'client-catalog.json').write_bytes((ROOT / 'config' / 'client-catalog.json').read_bytes())
    (ASSETS / 'cipher-profiles.json').write_bytes((ROOT / 'config' / 'cipher-profiles.json').read_bytes())
    (ASSETS / 'clients').mkdir(exist_ok=True)
    for source in (ROOT / 'config' / 'clients').glob('*.json'):
        (ASSETS / 'clients' / source.name).write_bytes(source.read_bytes())
    dll = runtime / 'unicorn' / 'lib' / 'unicorn.dll'
    if not dll.is_file():
        raise SystemExit('Missing verified Unicorn runtime: ' + str(dll))
    icon = ROOT / 'packaging' / 'L2PacketMonitor.ico'
    version = ROOT / 'packaging' / 'version.txt'
    qtbase_ru = Path(QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)) / 'qtbase_ru.qm'
    if not qtbase_ru.is_file():
        raise SystemExit('Missing Qt Russian translation: ' + str(qtbase_ru))
    # Unicorn imports its architecture module with importlib at runtime.
    # Enumerate the retained package explicitly: PyInstaller's collect hook
    # runs before --paths is applied and otherwise omits arch.intel.
    unicorn_modules = []
    for source in (runtime / 'unicorn').rglob('*.py'):
        parts = source.relative_to(runtime).with_suffix('').parts
        if parts[-1] == '__init__':
            parts = parts[:-1]
        if parts:
            unicorn_modules.append('.'.join(parts))
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
               '--onefile', '--windowed', '--name', 'L2PacketMonitor',
               '--distpath', str(dist_dir),
               '--workpath', str(ROOT / 'build' / 'pyinstaller'),
               '--specpath', str(ROOT / 'build'),
               '--paths', str(ROOT / 'src'), '--paths', str(runtime),
               '--add-binary', str(dll) + ';unicorn/lib',
               '--add-binary', str(ROOT / 'build' / 'inventory-drop' / 'drop_controller.exe') + ';native-drop',
               '--add-binary', str(ROOT / 'build' / 'inventory-drop' / 'drop_hook.dll') + ';native-drop',
               '--add-binary', str(ROOT / 'build' / 'client-tap' / 'tap_controller.exe') + ';native-tap',
               '--add-binary', str(ROOT / 'build' / 'client-tap' / 'tap_hook_v2.dll') + ';native-tap',
               '--add-data', str(ASSETS) + ';config',
               '--add-data', str(icon) + ';assets',
               '--add-data', str(ROOT / 'assets/client-icons.zip') + ';assets',
               '--add-data', str(ROOT / 'src/server_bridge_sdk') + ';src/server_bridge_sdk',
               '--add-data', str(qtbase_ru) + ';PySide6/translations',
               '--icon', str(icon), '--version-file', str(version),
               *[part for module in sorted(set(unicorn_modules))
                 for part in ('--hidden-import', module)],
               str(ROOT / 'src' / 'desktop.py')]
    subprocess.run(command, cwd=ROOT, check=True)
    result = dist_dir / 'L2PacketMonitor.exe'
    report_dir = ROOT / 'reports' / 'native-exe-test'
    subprocess.run([str(result), '--self-test', '--no-api',
                    '--self-test-output', str(report_dir)],
                   cwd=ROOT, timeout=120, check=True)
    report = json.loads((report_dir / 'self-test.json').read_text('utf-8'))
    if not report.get('passed'):
        raise SystemExit('Frozen executable self-test failed')
    print(result, result.stat().st_size)


if __name__ == '__main__':
    main()
