# Инвентарь и скиллы нового клиента High Five

Парсеры `classic_inventory.py` и `classic_skills.py` применяются только к соответствующему профилю клиента. Старые гибридные схемы Asterios не изменены. На вход подаётся полный расшифрованный пакет с u16LE длиной. Неизвестный opcode возвращает `None`; известный пакет с неподходящими границами отклоняется через `ValueError`.

## SkillList, 0x5F

Два сохранённых пакета `40-SkillList.json` и `2129-SkillList.json` совпадают: 441 байт, 31 запись по 14 байтов после семибайтового заголовка. Поля записи: u32 passive, u32 level, u32 skill ID, u8 disabled, u8 enchantable. Значения passive/disabled/enchantable — отдельные boolean 0/1, а не объединённая битовая маска. В реальном списке 24 пассивных и 7 активных скиллов, все disabled/enchantable равны нулю. Первая запись — ID 118, уровень 1; последняя — ID 5491, уровень 1. Поля cooldown group и newly learned в этой форме отсутствуют и не выдумываются.

Первичный источник — [L2J Server SkillList.java](https://github.com/l2abyss/L2J_Server/blob/master/src/main/java/com/l2jserver/gameserver/network/serverpackets/SkillList.java). Схема совпала с захватом по длине, числу записей и всем флагам. Результат имеет стандартное событие `skill_list` и подтверждение `server-list` для существующего `Skills.apply`.

## InventoryUpdate, 0x21

Три пакета `4627`, `5154`, `5340-InventoryUpdate.json` имеют по 145 байтов: заголовок 5 байтов и две записи по 70 байтов. Запись состоит из u16 действия и 68 байтов item info. Действия 1/2/3 соответствуют добавлению/изменению/удалению; иной код сохраняется как unknown. В первом захвате сервер изменил object ID 268555853, item ID 3493, slot 6, amount 4858 и object ID 268555854, item ID 57, slot 7, amount 9190763.

Первичные источники: [InventoryUpdate.java](https://github.com/l2abyss/L2J_Server/blob/master/src/main/java/com/l2jserver/gameserver/network/serverpackets/InventoryUpdate.java), [AbstractInventoryUpdate.java](https://github.com/l2abyss/L2J_Server/blob/master/src/main/java/com/l2jserver/gameserver/network/serverpackets/AbstractInventoryUpdate.java), [AbstractItemPacket.java](https://github.com/l2abyss/L2J_Server/blob/master/src/main/java/com/l2jserver/gameserver/network/serverpackets/AbstractItemPacket.java). Поля item info: object ID/item ID/location по u32, amount u64, type/custom/equipped по u16, body part u32, enchant/custom по u16, augmentation u32, mana/time по i32, attack element i16/power u16, шесть защит и три enchant option по u16. Подписанные sentinel mana=-1, time=-9999, attack element=-2 сохранены из реального пакета.

## ItemList, 0x11

[ItemList.java](https://github.com/l2abyss/L2J_Server/blob/master/src/main/java/com/l2jserver/gameserver/network/serverpackets/ItemList.java) использует u16 show-window, u16 count, те же 68 байтов item info и inventory block из AbstractItemPacket: u16 blocked count; для ненулевого count далее u8 mode и count*u32 item ID. Пустой block занимает только два байта. Парсер проверяет ровно эту форму и все границы, возвращает `inventory_update` с `full_list=True`, `record_size=68`, `list_type` и данными block. В отличие от обновлений он обозначает полный список.

Реальный пакет `20795-ItemList.json` подтвердил форму: 1505 байтов, 22 предмета по 68 байтов, пустой inventory block. Среди записей item ID 1539 и 728 по 1000 штук, ID 3493 — 7355, adena ID 57 — 14315313. Повторяющиеся template ID сохраняются отдельными предметами по уникальному object ID. Тест проверяет реальные значения и применение полного списка: старые записи заменяются, full_list_received устанавливается, coverage_gap снимается. Четыре начальные и последующие проверочные пакеты сохранены в `tests/fixtures/classic-character` без сессионных ключей.
