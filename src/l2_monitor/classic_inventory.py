"""High Five inventory schemas, separate from the observed Asterios hybrid.

Input includes u16LE wire length. InventoryUpdate has action + 68-byte item
records; ItemList uses those same 68 bytes followed by the inventory block.
See docs/classic-inventory-skills.md for source and capture evidence.
"""
import struct


ITEM_SIZE = 68


def _item(raw, offset):
    object_id, item_id, slot, amount = struct.unpack_from('<IIIQ', raw, offset)
    item_type2, custom_type1, equipped = struct.unpack_from('<HHH', raw, offset + 20)
    body_part = struct.unpack_from('<I', raw, offset + 26)[0]
    enchant, custom_type2 = struct.unpack_from('<HH', raw, offset + 30)
    augmentation, mana, remaining = struct.unpack_from('<Iii', raw, offset + 34)
    attack_type, attack_power = struct.unpack_from('<hH', raw, offset + 46)
    defenses = list(struct.unpack_from('<6H', raw, offset + 50))
    enchant_options = list(struct.unpack_from('<3H', raw, offset + 62))
    return dict(object_id=object_id, item_id=item_id, slot=slot, location_slot=slot, amount=amount,
                item_type2=item_type2, custom_type1=custom_type1, is_equipped=equipped,
                body_part=body_part, enchant_level=enchant, custom_type2=custom_type2,
                augmentation_id=augmentation, mana=mana, remaining_time=remaining,
                attack_element_type=attack_type, attack_element_power=attack_power,
                defense_elements=defenses, enchant_options=enchant_options)


def parse_classic_inventory(raw):
    """Return standard ``inventory_update`` fields for 0x21 or full 0x11.

    Full ItemList also sets ``full_list=True`` and ``list_type``. A partial
    InventoryUpdate never claims full coverage. Unsupported opcodes return
    None. Known opcodes with incompatible lengths raise ValueError.
    """
    if len(raw) < 3 or raw[2] not in (0x11, 0x21):
        return None
    opcode = raw[2]
    header_size = 7 if opcode == 0x11 else 5
    if len(raw) < header_size or int.from_bytes(raw[:2], 'little') != len(raw):
        raise ValueError('Classic inventory: invalid packet length or incomplete header')
    items = []
    if opcode == 0x21:
        count = struct.unpack_from('<H', raw, 3)[0]
        if len(raw) != 5 + count * (ITEM_SIZE + 2):
            raise ValueError('Classic InventoryUpdate: count does not match 70-byte records')
        for offset in range(5, len(raw), ITEM_SIZE + 2):
            action = struct.unpack_from('<H', raw, offset)[0]
            item = _item(raw, offset + 2)
            item.update(action=action, action_name={1: 'added', 2: 'modified', 3: 'removed'}.get(action, 'unknown'))
            items.append(item)
        return dict(event='inventory_update', items=items, record_size=ITEM_SIZE + 2,
                    full_list=False, schema='classic-high-five')

    list_type, count = struct.unpack_from('<HH', raw, 3)
    end = 7 + count * ITEM_SIZE
    if end + 2 > len(raw):
        raise ValueError('Classic ItemList: truncated items or inventory block')
    blocked_count = struct.unpack_from('<H', raw, end)[0]
    expected = end + 2 + (1 + blocked_count * 4 if blocked_count else 0)
    if len(raw) != expected:
        raise ValueError('Classic ItemList: inventory block count or packet tail does not match')
    for offset in range(7, end, ITEM_SIZE):
        item = _item(raw, offset)
        item.update(action=1, action_name='present', list_type=list_type)
        items.append(item)
    block_mode = raw[end + 2] if blocked_count else None
    blocked = list(struct.unpack_from('<' + str(blocked_count) + 'I', raw, end + 3)) if blocked_count else []
    return dict(event='inventory_update', items=items, list_type=list_type, full_list=True,
                record_size=ITEM_SIZE, inventory_block_mode=block_mode,
                blocked_item_ids=blocked, schema='classic-high-five')
