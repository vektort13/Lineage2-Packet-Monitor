"""Observed community-board skill offers; commands are retained, never built.

ShowBoard has eight UTF-16LE NUL-terminated navigation strings followed by a
NUL-terminated page string ``101/102/103 + U+0008 + HTML``. HTML can span all
three pages, including an action attribute split across page boundaries.
"""
import collections
import re
import threading
from html.parser import HTMLParser


_SEARCH = '_bbslearnSkills_search_ $skillsearch'
_SEARCH_LEARN = '_bbslearnSkills_learnFromSearch_'
_FILTERS = frozenset(('ALL',))
_DECIMAL = re.compile(r'[0-9]+\Z')
_MAX_HTML = 98304


def _integer(value, minimum=0):
    if not _DECIMAL.fullmatch(value) or len(value) > 10:
        return None
    number = int(value)
    return number if minimum <= number <= 0x7fffffff else None


def parse_learn_command(command):
    """Parse only observed learn routes and retain their exact command text.

    Supports the nine semicolon fields and the search route's six underscore
    fields. The search query is the unsplit remainder, preserving spaces and
    underscores. FILTER/STAT currently accept only the observed ``ALL``.
    """
    if not isinstance(command, str) or not 1 <= len(command) <= 2048:
        return None
    if command.startswith('_bbslearnSkills;learn;'):
        fields = command.split(';')
        if (len(fields) != 9 or fields[:2] != ['_bbslearnSkills', 'learn'] or
                fields[6] != '' or fields[7] not in _FILTERS or fields[8] not in _FILTERS):
            return None
        class_id, skill_id, level, page = (_integer(fields[index], 0 if index == 2 else 1)
                                          for index in (2, 3, 4, 5))
        if None in (class_id, skill_id, level, page):
            return None
        return dict(skill_id=skill_id, skill_level=level, class_id=class_id,
                    command=command, page=page)
    if command.startswith(_SEARCH_LEARN):
        fields = command[len(_SEARCH_LEARN):].split('_', 5)
        if len(fields) != 6 or fields[3] not in _FILTERS or fields[4] not in _FILTERS:
            return None
        class_id, skill_id, level = (_integer(fields[index], 0 if index == 0 else 1)
                                     for index in range(3))
        query = fields[5]
        if (None in (class_id, skill_id, level) or not 1 <= len(query) <= 256 or
                query.strip() != query or not query.isprintable() or ';' in query):
            return None
        return dict(skill_id=skill_id, skill_level=level, class_id=class_id,
                    command=command, query=query)
    return None


class _Actions(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.offers, self.commands = [], []
        self.search_available = False

    def handle_starttag(self, tag, attrs):
        actions = [value for key, value in attrs if key == 'action']
        if len(actions) != 1 or not isinstance(actions[0], str):
            return
        action = actions[0]
        prefix = 'bypass -h ' if action.startswith('bypass -h ') else 'bypass '
        if not action.startswith(prefix):
            return
        command = action[len(prefix):]
        if (not command.startswith('_bbslearnSkills') or len(command) > 2048 or not command.isprintable()):
            return
        self.commands.append(command)
        self.search_available |= command == _SEARCH
        parsed = parse_learn_command(command)
        if parsed is not None:
            self.offers.append({key: parsed[key] for key in ('skill_id', 'skill_level', 'class_id', 'command')})


def _html_actions(html):
    parser = _Actions()
    parser.feed(html)
    return dict(offers=parser.offers, commands=list(dict.fromkeys(parser.commands)),
                search_available=parser.search_available)


def parse_classic_skill_menu(raw, direction):
    """Return observed skill_menu/skill_learn_request fields or None.

    Known packet types with invalid Unicode/framing raise ValueError. Raw
    HTML is parsed for action attributes only; it is never rendered/executed.
    """
    if len(raw) < 3:
        return None
    opcode = raw[2]
    if (direction, opcode) not in (('server', 0x7b), ('client', 0x23)):
        return None
    if int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Community-board packet length mismatch')
    offset = 4 if opcode == 0x7b else 3
    if len(raw) < offset + 2 or (len(raw) - offset) % 2 or raw[-2:] != b'\0\0':
        raise ValueError('Community-board packet has incomplete UTF-16LE content')
    try:
        text = raw[offset:].decode('utf-16le')
    except UnicodeError as error:
        raise ValueError('Community-board packet contains invalid UTF-16LE') from error
    if opcode == 0x23:
        command = text[:-1]
        if '\0' in command:
            raise ValueError('Community-board command contains an embedded NUL')
        parsed = parse_learn_command(command)
        return None if parsed is None else dict(event='skill_learn_request', list_type=0,
                                               method='community-board', **parsed)
    if raw[3] != 1:
        raise ValueError('Unsupported community-board display flag')
    strings = text.split('\0')
    if len(strings) != 10 or strings[-1] != '':
        raise ValueError('ShowBoard does not contain eight navigation strings and one page')
    content = strings[-2]
    if len(content) < 4 or content[:3] not in ('101', '102', '103') or content[3] != '\x08':
        raise ValueError('ShowBoard page identifier or separator is invalid')
    fragment = content[4:]
    if fragment == 'null':
        fragment = ''
    return dict(event='skill_menu', board_id=int(content[:3]), fragment=fragment,
                **_html_actions(fragment))


class SkillMenu:
    """Bounded server-offer cache scoped to a captured connection."""
    def __init__(self):
        self.lock = threading.RLock()
        self.reset(None)

    def reset(self, session_id):
        with self.lock:
            self.session_id = session_id
            self.offers = collections.OrderedDict()
            self.search_available = False
            self.last_board_time = None
            self.revision = self.completed_revision = 0
            self.coverage_gap = False
            self._assembly = ''
            self._page = None

    def gap(self):
        with self.lock:
            self.offers.clear()
            self.search_available = False
            self.last_board_time = None
            self.completed_revision = 0
            self.revision += 1
            self.coverage_gap = True
            self._assembly, self._page = '', None

    def _remember(self, offers):
        for offer in offers:
            if not isinstance(offer, dict):
                continue
            parsed = parse_learn_command(offer.get('command'))
            if parsed is None or any(offer.get(key) != parsed[key] for key in ('skill_id', 'skill_level', 'class_id')):
                continue
            key = (parsed['skill_id'], parsed['skill_level'])
            if key not in self.offers:  # Keep the first server-offered class for duplicate search results.
                self.offers[key] = {field: parsed[field] for field in ('skill_id', 'skill_level', 'class_id', 'command')}
                while len(self.offers) > 10000:
                    self.offers.popitem(last=False)

    def apply(self, packets):
        with self.lock:
            for packet in packets:
                fields = packet.get('fields') or {}
                if packet.get('direction') != 'server' or fields.get('event') != 'skill_menu':
                    continue
                board, fragment = fields.get('board_id'), fields.get('fragment')
                if board == 101 and isinstance(fragment, str):
                    self._assembly, self._page = fragment, 101
                elif board in (102, 103) and isinstance(fragment, str):
                    if self._page != board - 1:
                        self._assembly, self._page = '', None
                        self.revision += 1
                        continue
                    self._assembly += fragment
                    self._page = board
                elif board is None:
                    self._remember(fields.get('offers', []))
                    self.search_available |= bool(fields.get('search_available'))
                    self.last_board_time = packet.get('time')
                    self.revision += 1
                    continue
                else:
                    continue
                if len(self._assembly) > _MAX_HTML:
                    self._assembly, self._page = '', None
                    self.revision += 1
                    continue
                actions = _html_actions(self._assembly)
                self._remember(actions['offers'])
                self.search_available |= actions['search_available']
                self.last_board_time = packet.get('time')
                self.revision += 1
                if board == 103:
                    self.completed_revision += 1
                    self.coverage_gap = False
                    self._assembly, self._page = '', None

    def snapshot(self):
        with self.lock:
            return dict(session_id=self.session_id, offers=[dict(value) for value in self.offers.values()],
                        revision=self.revision, completed_revision=self.completed_revision,
                        search_available=self.search_available, last_board_time=self.last_board_time,
                        coverage_gap=self.coverage_gap)

    def find(self, skill_id, level):
        with self.lock:
            value = self.offers.get((skill_id, level))
            return None if value is None else dict(value)
