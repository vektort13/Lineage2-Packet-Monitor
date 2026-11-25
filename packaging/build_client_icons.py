"""Read local client groups/textures into a standalone, deduplicated icon archive."""
import collections
import hashlib
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from client_icon_extract import TexturePackage, decode_group, item_icons, skill_icons


def main():
    research = ROOT / 'reports/client-icons'
    research.mkdir(parents=True, exist_ok=True)
    group_sources = []
    for name in ('AdditionalItemGrp.dat', 'EtcItemgrp.dat', 'Armorgrp.dat', 'Weapongrp.dat', 'Skillgrp.dat'):
        source = ROOT.parent / 'asterios' / name
        (research / (name + '.bin')).write_bytes(decode_group(source))
        group_sources.append(dict(path=str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    additional = (research / 'AdditionalItemGrp.dat.bin').read_bytes()
    count = struct.unpack_from('<I', additional)[0]
    if additional[4 + count * 56:] != b'\x0cSafePackage\0':
        raise ValueError('Unexpected additional item group layout')
    expected_ids = {struct.unpack_from('<I', additional, 4 + index * 56)[0] for index in range(count)}
    items, seen_ids = {}, set()
    for name, tag in (('EtcItemgrp.dat', 2), ('Armorgrp.dat', 1), ('Weapongrp.dat', 0)):
        rows = item_icons((research / (name + '.bin')).read_bytes(), tag, strict=False, expected_ids=expected_ids)
        seen_ids.update(rows)
        for item_id, icon in rows.items():
            if icon and icon != 'none':
                if item_id in items and items[item_id] != icon:
                    raise ValueError('Conflicting item groups')
                items[item_id] = icon
    if seen_ids != expected_ids:
        raise ValueError('Missing base item prefixes')
    skills = skill_icons((research / 'Skillgrp.dat.bin').read_bytes())
    references = set(items.values()) | set(skills.values())
    package_names = {ref.split('.')[0] for ref in references}
    source_files = {p.stem.lower(): p for p in (ROOT.parent / 'SysTextures').glob('*.utx')}
    images, links, sources, errors = {}, {}, [], []
    for package in sorted(package_names):
        path = source_files.get(package)
        if path is None:
            errors.append(dict(package=package, error='Package not found'))
            continue
        decoded = TexturePackage(path)
        sources.append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        leaf_counts = collections.Counter(decoded.names[e['name']].lower() for e in decoded.exports
                                          if decoded.object_name(e['cls']) == 'Engine.Texture')
        for index, entry in enumerate(decoded.exports):
            if decoded.object_name(entry['cls']) != 'Engine.Texture':
                continue
            leaf = decoded.names[entry['name']].lower()
            keys = [package + '.' + decoded.object_name(index + 1).lower()]
            if leaf_counts[leaf] == 1:
                keys.append(package + '.' + leaf)
            if not references.intersection(keys):
                continue
            try:
                image = decoded.texture(entry)
                if image.width > 256 or image.height > 256:
                    raise ValueError('Unexpected icon dimensions')
                buffer = io.BytesIO()
                image.save(buffer, format='PNG')
                png = buffer.getvalue()
                name = 'images/' + hashlib.sha256(png).hexdigest() + '.png'
                images[name] = png
                for key in keys:
                    links[key] = name
            except (ValueError, KeyError) as error:
                errors.append(dict(icon=keys[0], error=str(error)))
        print(package, len(images), flush=True)
    defaults = collections.defaultdict(set)
    for (skill, level), ref in skills.items():
        defaults[skill].add(ref)
    manifest = dict(schema=1, source='local-client', images=links,
                    items={str(key): value for key, value in items.items() if value in links},
                    skills={f'{skill}:{level}': ref for (skill, level), ref in skills.items() if ref in links},
                    skill_defaults={str(key): next(iter(values)) for key, values in defaults.items()
                                    if len(values) == 1 and next(iter(values)) in links})
    path = ROOT / 'assets/client-icons.zip'
    path.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest, separators=(',', ':')), compress_type=zipfile.ZIP_DEFLATED)
        for name, data in sorted(images.items()):
            archive.writestr(name, data, compress_type=zipfile.ZIP_STORED)
    report = dict(source_files=sources, group_files=group_sources, base_item_ids=len(expected_ids), item_links=len(manifest['items']),
                  skill_level_links=len(manifest['skills']), skill_id_defaults=len(manifest['skill_defaults']),
                  unique_pngs=len(images), missing_references=sorted(references - links.keys()), errors=errors,
                  archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), archive_bytes=path.stat().st_size)
    (research / 'extraction.json').write_text(json.dumps(report, indent=2), 'utf-8')
    print(json.dumps({k: v for k, v in report.items() if k not in ('source_files', 'errors', 'missing_references')}))


if __name__ == '__main__':
    main()
