"""Partial schemas checked against this client's decrypted packet shapes."""
import struct
from .diagnostics import parse_client_diagnostic


def extra_fields(direction, packet):
    op, size = packet[2], len(packet)
    if direction == 'client' and op == 0x23:
        if size < 5 or (size - 3) % 2 or packet[-2:] != b'\0\0':
            raise ValueError('Bypass: expected terminated UTF-16 command')
        return dict(event='bypass_request', command=packet[3:-2].decode('utf-16le'))
    if direction == 'server' and op == 0x19:
        if size < 9:
            raise ValueError('NpcHtml: truncated header')
        end = next((i for i in range(7, size - 1, 2) if packet[i:i+2] == b'\0\0'), None)
        if end is None:
            raise ValueError('NpcHtml: unterminated text')
        return dict(event='npc_html', object_id=struct.unpack_from('<I', packet, 3)[0],
                    html=packet[7:end].decode('utf-16le'), tail_hex=packet[end+2:].hex())
    if direction == 'server' and op == 0x85:
        count = struct.unpack_from('<H', packet, 3)[0]
        if count > 4096 or size != 5 + count * 10:
            raise ValueError('AbnormalStatusUpdate: incompatible 10-byte records')
        buffs = []
        for offset in range(5, size, 10):
            skill, level, seconds = struct.unpack_from('<IHi', packet, offset)
            buffs.append(dict(skill_id=skill, skill_level=level, remaining_seconds=seconds))
        return dict(event='buff_list', buffs=buffs)
    if direction == 'server' and op == 0x62 and size >= 11:
        message_id, parameter_count = struct.unpack_from('<II', packet, 3)
        result = dict(event='system_message', message_id=message_id, parameter_count=parameter_count)
        if message_id == 2303 and parameter_count == 2 and size == 27:
            kind1, item, kind2, seconds = struct.unpack_from('<4I', packet, 11)
            if kind1 == 3 and kind2 == 1:
                result.update(reuse_item_id=item, retry_after_seconds=seconds)
        return result
    if direction == 'client' and op == 0x19 and size == 11:
        oid, control = struct.unpack_from('<II', packet, 3)
        return dict(event='use_item_request', object_id=oid, control=control)
    if direction == 'client':
        diagnostic = parse_client_diagnostic(packet)
        if diagnostic is not None:
            return diagnostic
    if direction == 'server' and packet[2:5] == b'\xfe\xf9\x00':
        count, offset = struct.unpack_from('<I', packet, 5)[0], 9
        skills = []
        if count > 4096:
            raise ValueError('Too many learnable skills')
        for _ in range(count):
            skill, level, sp, min_level, item_count = struct.unpack_from('<IIIHI', packet, offset)
            offset += 18
            if item_count > (size-offset)//12:
                raise ValueError('Truncated required item list')
            items = []
            for _ in range(item_count):
                item, amount = struct.unpack_from('<IQ', packet, offset)
                items.append(dict(item_id=item, amount=amount))
                offset += 12
            required_count = struct.unpack_from('<I', packet, offset)[0]
            offset += 4
            if required_count > (size-offset)//8:
                raise ValueError('Truncated prerequisite skill list')
            required_skills = []
            for _ in range(required_count):
                required, required_level = struct.unpack_from('<II', packet, offset)
                required_skills.append(dict(skill_id=required, skill_level=required_level))
                offset += 8
            skills.append(dict(skill_id=skill, skill_level=level, required_sp=sp,
                               minimum_level=min_level, required_items=items, required_skills=required_skills))
        if offset != size:
            raise ValueError('Unexpected learnable skill list tail')
        return dict(event='learnable_skill_list', skills=skills, confirmation='offered-by-server')
    if direction == 'client' and op in (0x73, 0x7c):
        if size != 15:
            raise ValueError('AcquireSkill: unsupported request shape')
        skill, level, kind = struct.unpack_from('<III', packet, 3)
        return dict(event='skill_learn_request' if op == 0x7c else 'skill_learn_info_request',
                    skill_id=skill, skill_level=level, list_type=kind, confirmation='request')
    if direction == 'server' and op == 0x5f:
        count = struct.unpack_from('<I', packet, 3)[0]
        if size not in (7 + count * 18, 11 + count * 18):
            raise ValueError('SkillList: incompatible 18-byte skill records')
        skills = []
        for offset in range(7, 7 + count * 18, 18):
            passive, level, skill, group, disabled, enchantable = struct.unpack_from('<IIIIBB', packet, offset)
            skills.append(dict(skill_id=skill, skill_level=level, passive=passive,
                               cooldown_group=group, disabled=disabled, enchantable=enchantable))
        return dict(event='skill_list', skills=skills, confirmation='server-list',
                    newly_learned=struct.unpack_from('<I', packet, size-4)[0] if size == 11+count*18 else None)
    if direction == 'client' and op == 0xb0:
        if size != 45:
            raise ValueError('RequestMultiSellChoose: expected observed 45-byte form')
        list_id, entry_id, amount = struct.unpack_from('<IIQ', packet, 3)
        result = dict(event='multisell_request', list_id=list_id, entry_id=entry_id,
                      amount=amount, confirmation='request')
        if list_id == 53728110 and entry_id in (1, 3):
            result['exchange'] = '1 Gold → 10 Silver' if entry_id == 3 else '10 Silver → 1 Gold'
            result['mapping_source'] = 'exchange-gold-silver-01'
        return result
    if direction == 'server' and op == 0x21:
        count = struct.unpack_from('<H', packet, 3)[0]
        if size != 5 + count * 76:
            raise ValueError('InventoryUpdate: incompatible observed 76-byte item records')
        items = []
        for offset in range(5, size, 76):
            action, object_id, item_id, slot, amount = struct.unpack_from('<HIIIQ', packet, offset)
            items.append(dict(action=action, action_name={1:'added',2:'modified',3:'removed'}.get(action,'unknown'),
                              object_id=object_id, item_id=item_id, slot=slot, amount=amount))
        return dict(event='inventory_update', items=items)
    if direction == 'server' and op == 0x11:
        # This client sends a full ItemList after RequestItemList (0x14).
        # The observed hybrid layout is: list type u16, count u16, 74-byte
        # records, then a trailing u16. Keep the raw slot field because its
        # high bits encode client-specific location data.
        if size < 9:
            raise ValueError('ItemList: incomplete header')
        list_type, count = struct.unpack_from('<HH', packet, 3)
        if count > 4096:
            raise ValueError('ItemList: too many item records')
        record_size, tail_size = 74, 2
        expected = 7 + count * record_size + tail_size
        if size != expected:
            raise ValueError(f'ItemList: expected {expected} bytes, got {size}')
        items = []
        for offset in range(7, 7 + count * record_size, record_size):
            object_id, item_id, location_slot = struct.unpack_from('<III', packet, offset)
            amount = struct.unpack_from('<Q', packet, offset + 12)[0]
            item_type2, custom_type1, is_equipped = struct.unpack_from('<HHH', packet, offset + 20)
            body_part = struct.unpack_from('<I', packet, offset + 26)[0]
            enchant_level, custom_type2 = struct.unpack_from('<HH', packet, offset + 30)
            augmentation_id, mana, remaining_time = struct.unpack_from('<III', packet, offset + 34)
            items.append(dict(action=1, action_name='present', object_id=object_id,
                              item_id=item_id, slot=location_slot, amount=amount,
                              list_type=list_type, location_slot=location_slot,
                              item_type2=item_type2, custom_type1=custom_type1,
                              is_equipped=is_equipped, body_part=body_part,
                              enchant_level=enchant_level, custom_type2=custom_type2,
                              augmentation_id=augmentation_id, mana=mana,
                              remaining_time=remaining_time))
        return dict(event='inventory_update', list_type=list_type, record_size=record_size,
                    trailing_u16=struct.unpack_from('<H', packet, size - 2)[0], items=items)
    if direction == 'server' and op == 0x54:
        if size < 23:
            raise ValueError('Incomplete MagicSkillLaunched')
        reserved, caster, skill, level, count = struct.unpack_from('<IIIII', packet, 3)
        if size != 23 + count * 4:
            raise ValueError('MagicSkillLaunched: target count does not match length')
        return dict(event='skill_launched', caster_id=caster, skill_id=skill, skill_level=level,
                    target_ids=list(struct.unpack_from('<' + 'I' * count, packet, 23)), reserved=reserved)
    if direction == 'server' and op == 0x48:
        # This hybrid adds a byte before the skill ID. Retain unknown fields;
        # do not use the classic C6/H5 offsets for this observed 72-byte form.
        if size != 72:
            raise ValueError('MagicSkillUse: unsupported hybrid packet form')
        caster, target = struct.unpack_from('<II', packet, 7)
        skill, level, cast_ms, auxiliary, reuse_ms = struct.unpack_from('<IIIII', packet, 16)
        return dict(event='skill_use', caster_id=caster, target_id=target, skill_id=skill,
                    skill_level=level, cast_ms=cast_ms, reuse_ms=reuse_ms,
                    xyz=list(struct.unpack_from('<iii', packet, 36)),
                    reserved_u32=struct.unpack_from('<I', packet, 3)[0],
                    hybrid_byte=packet[15], auxiliary_u32=auxiliary)
    return None
