"""Portable data-only profile bundles, stored outside the extracted EXE."""
import json
import os
import tempfile
import uuid
import zipfile
from pathlib import Path

from .cipher_profiles import CipherProfiles, USER_PROFILE_ROOT, validate_registry

FORBIDDEN = {'incoming_key','outgoing_key','session_keys','client_key','server_key','session_id',
             'last_server_packet_hex','tx_key_before','wire_cursors','outgoing_counter','incoming_counter'}


def _profile_json(data):
    if not isinstance(data, dict):
        raise ValueError('Профиль клиента должен быть объектом JSON')
    def visit(value):
        if isinstance(value, dict):
            if set(value) & FORBIDDEN:
                raise ValueError('Сессионное состояние нельзя сохранять в профиль')
            for item in value.values(): visit(item)
        elif isinstance(value, list):
            for item in value: visit(item)
    visit(data)
    return data


def export_profiles(path, registry=None):
    registry = registry or CipherProfiles()
    manifest = dict(schema=1, algorithms=registry.algorithms, profiles=registry.profiles)
    bodies = {}
    for entry in manifest['profiles']:
        original = registry.load_profile(entry['engine_sha256'], verified_only=False)
        _profile_json(original)
        entry['profile'] = 'clients/' + entry['engine_sha256'] + '.json'
        bodies[entry['profile']] = json.dumps(original,ensure_ascii=False,indent=2)+'\n'
    target = Path(path)
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('registry.json',json.dumps(validate_registry(manifest),ensure_ascii=False,indent=2)+'\n')
        for name, body in bodies.items(): archive.writestr(name,body)
    return dict(path=str(target),profiles=len(bodies))


def import_profiles(path, *, destination=None, existing=None):
    destination = USER_PROFILE_ROOT if destination is None else Path(destination)
    existing = existing or CipherProfiles()
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if 'registry.json' not in {item.filename for item in infos}:
            raise ValueError('В пакете профилей нет registry.json')
        if len(infos) > 300 or len({i.filename for i in infos}) != len(infos) or sum(i.file_size for i in infos)>16*1024*1024:
            raise ValueError('Некорректный или слишком большой пакет профилей')
        if any(i.file_size>2*1024*1024 for i in infos):
            raise ValueError('Один из файлов профиля слишком большой')
        manifest=validate_registry(json.loads(archive.read('registry.json')))
        wanted={'registry.json'}|{entry['profile'] for entry in manifest['profiles']}
        if {i.filename for i in infos} != wanted:
            raise ValueError('Пакет профилей содержит посторонние или недостающие файлы')
        known = {entry['engine_sha256']: entry for entry in existing.profiles}
        ids = {entry['id'] for entry in existing.profiles}
        accepted, bodies = [], {}
        skipped = 0
        for entry in manifest['profiles']:
            data=_profile_json(json.loads(archive.read(entry['profile'])))
            if data.get('engine_sha256') != entry['engine_sha256'] or data.get('id') != entry['id']:
                raise ValueError('Профиль клиента не совпадает с записью реестра')
            if data.get('algorithm',entry['algorithm']) != entry['algorithm']:
                raise ValueError('Алгоритм профиля не совпадает с реестром')
            if entry['engine_sha256'] in known:
                skipped+=1
                continue
            if entry['id'] in ids:
                raise ValueError('ID профиля уже используется другой сборкой')
            ids.add(entry['id'])
            copy=dict(entry,profile='clients/'+entry['engine_sha256']+'.json')
            accepted.append(copy)
            bodies[copy['profile']]=data
    if not accepted:
        return dict(imported=0,skipped=skipped)
    installed=destination/'installed'
    installed.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.profile-',dir=destination) as temporary:
        staging=Path(temporary)/'bundle'
        (staging/'clients').mkdir(parents=True)
        for name,data in bodies.items():
            (staging/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        manifest['profiles']=accepted
        (staging/'registry.json').write_text(json.dumps(validate_registry(manifest),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        os.replace(staging,installed/uuid.uuid4().hex)
    return dict(imported=len(accepted),skipped=skipped)
