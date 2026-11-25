"""Read-only runtime lookup and explicit operator writes for cipher profiles.

An implemented algorithm does not establish support for any Engine.dll. Only
an exact SHA-256 profile match can do so. Session keys and cipher state belong
to a live connection and are deliberately excluded from this registry.
"""
import copy
import json
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath


ROOT = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
DEFAULT_PATH = ROOT / 'config/cipher-profiles.json'
USER_PROFILE_ROOT = ((Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local'))) / 'L2PacketMonitor')
                     if getattr(sys, 'frozen', False) else ROOT) / 'profiles'
SUPPORTED_ALGORITHMS = frozenset(('asterios', 'l2xor16', 'l2xor16-u64', 'plain'))
VALIDATION_STATUSES = frozenset(('verified', 'candidate', 'rejected'))
_SHA256 = re.compile(r'[0-9a-fA-F]{64}\Z')
_PROFILE_FIELDS = frozenset(('id', 'engine_sha256', 'algorithm', 'profile', 'evidence',
                             'validation', 'notes'))
_ALGORITHM_FIELDS = frozenset(('id', 'name', 'implementation', 'notes'))


def _checksum(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError('engine_sha256 must be exactly 64 hexadecimal characters')
    return value.lower()


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{name} must be nonempty text')
    return value


def _local_path(value, name):
    _text(value, name)
    windows = PureWindowsPath(value)
    portable = PurePosixPath(value.replace('\\', '/'))
    if (windows.drive or windows.root or portable.is_absolute() or
            '..' in portable.parts or ':' in value or '\0' in value or
            not portable.parts):
        raise ValueError(f'{name} must be a relative local path without parent traversal')
    return value


def _profile(entry, algorithm_ids):
    if not isinstance(entry, dict) or set(entry) - _PROFILE_FIELDS:
        raise ValueError('profile contains unsupported fields (session keys are not profiles)')
    for field in ('id', 'engine_sha256', 'algorithm', 'profile', 'evidence', 'validation'):
        if field not in entry:
            raise ValueError(f'profile is missing {field}')
    result = copy.deepcopy(entry)
    _text(result['id'], 'profile id')
    result['engine_sha256'] = _checksum(result['engine_sha256'])
    if not isinstance(result['algorithm'], str) or result['algorithm'] not in algorithm_ids:
        raise ValueError('profile algorithm is not registered and implemented')
    _local_path(result['profile'], 'profile path')
    if not isinstance(result['evidence'], list):
        raise ValueError('evidence must be a list of relative local paths')
    for path in result['evidence']:
        _local_path(path, 'evidence path')
    if not isinstance(result['validation'], str) or result['validation'] not in VALIDATION_STATUSES:
        raise ValueError('validation must be verified, candidate or rejected')
    if result['validation'] == 'verified' and not result['evidence']:
        raise ValueError('a verified profile requires retained evidence')
    if 'notes' in result:
        _text(result['notes'], 'profile notes')
    return result


def validate_registry(value):
    """Validate and copy a registry; never mutate a caller-owned structure."""
    if not isinstance(value, dict) or set(value) != {'schema', 'algorithms', 'profiles'}:
        raise ValueError('registry requires schema, algorithms and profiles')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('unsupported cipher registry schema')
    if not isinstance(value['algorithms'], list) or not isinstance(value['profiles'], list):
        raise ValueError('algorithms and profiles must be lists')
    result = copy.deepcopy(value)
    algorithms = set()
    for entry in result['algorithms']:
        if not isinstance(entry, dict) or set(entry) - _ALGORITHM_FIELDS:
            raise ValueError('algorithm contains unsupported fields')
        if not {'id', 'name', 'implementation'} <= set(entry):
            raise ValueError('algorithm requires id, name and implementation')
        identifier = entry['id']
        if not isinstance(identifier, str) or identifier not in SUPPORTED_ALGORITHMS or identifier in algorithms:
            raise ValueError('algorithm must be an implemented unique identifier')
        _text(entry['name'], 'algorithm name')
        _local_path(entry['implementation'], 'algorithm implementation')
        if 'notes' in entry:
            _text(entry['notes'], 'algorithm notes')
        algorithms.add(identifier)
    checksums = set()
    for index, entry in enumerate(result['profiles']):
        entry = _profile(entry, algorithms)
        if entry['engine_sha256'] in checksums:
            raise ValueError('duplicate engine_sha256 in registry')
        checksums.add(entry['engine_sha256'])
        result['profiles'][index] = entry
    return result


def load_registry(path=None):
    """Read and validate a registry. This function performs no writes."""
    path = DEFAULT_PATH if path is None else Path(path)
    return validate_registry(json.loads(path.read_text('utf-8')))


class CipherProfiles:
    """Immutable runtime snapshot of a local registry, matched by checksum."""
    def __init__(self, path=None, *, root=None):
        self.path = DEFAULT_PATH if path is None else Path(path)
        self.root = ROOT if root is None else Path(root)
        self._data = load_registry(self.path)
        self._roots = {item['engine_sha256']: self.root for item in self._data['profiles']}
        if path is None:
            # Bundled profiles remain authoritative. Imports survive one-file EXE extraction.
            known_ids = {item['id'] for item in self._data['profiles']}
            for extra in sorted((USER_PROFILE_ROOT / 'installed').glob('*/registry.json')):
                external = load_registry(extra)
                for item in external['profiles']:
                    checksum = item['engine_sha256']
                    if checksum in self._roots:
                        continue
                    if item['id'] in known_ids:
                        raise ValueError('Imported profile ID conflicts with another client build')
                    self._data['profiles'].append(item)
                    self._roots[checksum] = extra.parent
                    known_ids.add(item['id'])
        self._by_checksum = {item['engine_sha256']: item for item in self._data['profiles']}

    @property
    def algorithms(self):
        return copy.deepcopy(self._data['algorithms'])

    @property
    def profiles(self):
        return copy.deepcopy(self._data['profiles'])

    def find(self, engine_sha256, *, verified_only=True):
        """Return a detached matching entry, or None; never try another build."""
        entry = self._by_checksum.get(_checksum(engine_sha256))
        if entry is None or (verified_only and entry['validation'] != 'verified'):
            return None
        return copy.deepcopy(entry)

    def resolve_profile(self, engine_sha256, *, verified_only=True):
        """Resolve the registered profile within root without writing anything."""
        entry = self.find(engine_sha256, verified_only=verified_only)
        if entry is None:
            return None
        root = self._roots[entry['engine_sha256']].resolve()
        path = (root / entry['profile'].replace('\\', '/')).resolve()
        if not path.is_relative_to(root):
            raise ValueError('profile resolves outside registry root')
        return path

    def load_profile(self, engine_sha256, *, verified_only=True):
        """Read a matched profile and check its declared Engine checksum."""
        path = self.resolve_profile(engine_sha256, verified_only=verified_only)
        if path is None:
            return None
        value = json.loads(path.read_text('utf-8'))
        if not isinstance(value, dict) or _checksum(value.get('engine_sha256')) != _checksum(engine_sha256):
            raise ValueError('profile Engine checksum disagrees with registry')
        return value


def register_profile(entry, path=None):
    """Operator-only upsert by Engine SHA-256 with validated atomic replacement.

    Runtime readers never call this. The existing registry must exist and be
    valid; corrupt files are not replaced with empty defaults. Other entries
    and algorithm metadata survive unchanged. No session state is accepted.
    """
    path = DEFAULT_PATH if path is None else Path(path)
    registry = load_registry(path)
    prepared = _profile(entry, {item['id'] for item in registry['algorithms']})
    for index, previous in enumerate(registry['profiles']):
        if previous['engine_sha256'] == prepared['engine_sha256']:
            registry['profiles'][index] = prepared
            break
    else:
        registry['profiles'].append(prepared)
    registry = validate_registry(registry)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         dir=path.parent, prefix=path.name + '.',
                                         suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            json.dump(registry, output, ensure_ascii=False, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return copy.deepcopy(prepared)
