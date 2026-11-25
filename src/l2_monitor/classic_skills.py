"""High Five SkillList schema, confirmed by this client's 14-byte records.

Protocol evidence and the matching server serializer are recorded in
docs/classic-inventory-skills.md. Input includes the u16LE wire length.
"""
import struct


def parse_classic_skills(raw):
    """Return an owned ``skill_list`` event; unsupported opcodes return None."""
    if len(raw) < 3 or raw[2] != 0x5f:
        return None
    if len(raw) < 7 or int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Classic SkillList: invalid packet length or incomplete header')
    count = struct.unpack_from('<I', raw, 3)[0]
    if len(raw) != 7 + count * 14:
        raise ValueError('Classic SkillList: count does not match 14-byte records')
    skills = []
    for offset in range(7, len(raw), 14):
        passive, level, skill, disabled, enchantable = struct.unpack_from('<IIIBB', raw, offset)
        if passive not in (0, 1) or disabled not in (0, 1) or enchantable not in (0, 1):
            raise ValueError('Classic SkillList: passive/disabled/enchantable must be boolean values')
        skills.append(dict(skill_id=skill, skill_level=level, passive=passive,
                           disabled=disabled, enchantable=enchantable))
    return dict(event='skill_list', skills=skills, confirmation='server-list',
                record_size=14, schema='classic-high-five')
