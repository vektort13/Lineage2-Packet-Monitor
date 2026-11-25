"""Validate public documentation links and the complete runtime resource bundle."""
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


def headings(text):
    seen, anchors = {}, set()
    for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', text, re.M):
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug + (f'-{count}' if count else ''))
    return anchors


def main():
    errors = []
    try:
        names = subprocess.check_output(
            ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
            cwd=ROOT, stderr=subprocess.DEVNULL).decode('utf-8').split('\0')
    except (FileNotFoundError, subprocess.CalledProcessError):
        # The source/resource ZIP also supports this check without Git metadata.
        excluded = {'.git', '.venv', 'build', 'build-assets', 'release', 'cache', '__pycache__'}
        names = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                 if p.is_file() and not excluded.intersection(p.relative_to(ROOT).parts)
                 and (p.relative_to(ROOT).parts[0] != 'reports' or p.name == '.gitkeep')]
    files = sorted({ROOT / name for name in names if name})
    for path in files:
        if path.stat().st_size >= 100 * 1024 * 1024:
            errors.append(f'Oversized Git file: {path.relative_to(ROOT)}')
        if path.suffix.lower() != '.md':
            continue
        text = path.read_text('utf-8')
        links = re.findall(r'\]\(([^)]+)\)', text)
        links += re.findall(r'(?:src|href)="([^"]+)"', text)
        for link in links:
            link = link.strip('<>')
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            target = path.parent / unquote(parsed.path) if parsed.path else path
            target = target.resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                errors.append(f'Link outside repository: {path.relative_to(ROOT)} -> {link}')
                continue
            if not target.exists() or (target.is_file() and target not in files):
                errors.append(f'Missing published target: {path.relative_to(ROOT)} -> {link}')
            elif parsed.fragment and target.suffix == '.md' and (
                    path.name.startswith(('README', 'BUILD', 'USER_GUIDE', 'API'))):
                if unquote(parsed.fragment) not in headings(target.read_text('utf-8')):
                    errors.append(f'Missing heading: {path.relative_to(ROOT)} -> {link}')
    manifest_path = ROOT / 'docs' / 'resource-manifest.json'
    manifest = json.loads(manifest_path.read_text('utf-8'))
    for entry in manifest['files']:
        path = ROOT / entry['path']
        if not path.is_file():
            errors.append(f'Missing resource: {entry["path"]}')
            continue
        data = path.read_bytes()
        if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            errors.append(f'Resource checksum mismatch: {entry["path"]}')
    catalog = json.loads((ROOT / 'config/client-catalog.json').read_text('utf-8'))
    if len(catalog['items']) != 28690 or len(catalog['skills']) != 84004:
        errors.append('Client catalog record counts changed')
    with zipfile.ZipFile(ROOT / 'assets/client-icons.zip') as archive:
        bad = archive.testzip()
        icons = [name for name in archive.namelist() if name.startswith('images/') and name.endswith('.png')]
        if bad or len(icons) != 4751 or 'manifest.json' not in archive.namelist():
            errors.append(f'Icon archive is incomplete: {bad}, {len(icons)} images')
    profiles = json.loads((ROOT / 'config/cipher-profiles.json').read_text('utf-8'))
    if len(profiles['profiles']) != 2 or len(profiles['algorithms']) != 4:
        errors.append('Saved client profiles or algorithms are missing')
    screenshots = list((ROOT / 'docs/images').glob('*.png'))
    if len(screenshots) != 36:
        errors.append(f'Expected 36 language/theme/tab screenshots, found {len(screenshots)}')
    if errors:
        print('\n'.join(errors))
        return 1
    print(f'OK: {len(files)} published files, {len(manifest["files"])} verified resources, '
          f'{len(screenshots)} screenshots, 28,690 items, 84,004 skill levels, 4,751 icons, '
          '2 profiles and 4 algorithms; all local documentation links resolve.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
