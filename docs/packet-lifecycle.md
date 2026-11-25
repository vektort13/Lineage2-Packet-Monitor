# Жизненный цикл объектов в расшифрованной записи Prime

2026-11-21. После расшифровки обоих направлений построена единая временная шкала **2004 прикладных сообщений**: 1879 серверных и 125 клиентских. Начальные ProtocolVersion и VersionCheck в это число не входят. Анализ выполнен офлайн, без управления игровым окном.

Запись: `reports/network-20261121-134122/prime-relogin.pcapng`, SHA256 `8c9a3c7fde74067f4c9d638b3603ebdcad568148d3ac10e53b90f9ceffc80582`, TCP stream 0. Выбран X501, мировой Object ID `270128929`. Проверка расшифровки и личности (`reports/decryption-20261121/offline-prime/exchange-verification.json`).

## Подтверждённые результаты

| События в записи | Результат |
| --- | --- |
| NpcInfo | 100 сообщений, 100 разных Object ID |
| DropItem | 7 сообщений, 7 разных предметов |
| DeleteObject | 74: 67 NPC и 7 предметов; у каждого есть более раннее описание |
| Action от X501 | 22: 15 обращений к NPC, 7 к предметам |
| Состояние цели перед Action | Все 22 цели ранее описаны и ещё не удалены в порядке записи |
| GetItem | 2 сообщения; соответствующий DeleteObject получен раньше |
| Повторные описания после удаления | 0 |
| Обновления движения/позиции после удаления | 0 среди разобранных MoveToLocation, ValidateLocation, StopMove и TeleportToLocation |
| DeleteObject для X501 | 0 |
| Пакеты с эталонным opcode CharInfo `31` | 0 |

Прежние семь несовпадений Action с перечнем NPC полностью объясняются предметами из DropItem. Всего среди целей семь различных NPC и семь различных предметов. Наличие команды Action само по себе не подтверждает успешный выбор цели или взаимодействие.

К концу записи 33 NPC остаются в состоянии «описание получено, последующее удаление не записано». Это состояние пакетов, а не измерение фактической отрисовки.

Для X501 выделены 141 сообщение с его координатами, включая клиентские Action/отчёты позиции/запросы движения и серверные обновления. Отдельно подтверждены девять клиентских запросов движения и 17 серверных MoveToLocation для X501; соответствие один к одному не предполагается.

## Порядок начальных событий

Есть **19 обновлений для десяти NPC до получения их NpcInfo**: 11 ValidateLocation и восемь MoveToLocation. Они получены через 3.138141–5.142978 секунды после начала соединения. Клиентский EnterWorld записан на 6.782537 секунды, первое NpcInfo — на 6.923211 секунды. Все десять Object ID позднее присутствуют в NpcInfo.

Например, серверный пакет №4, outer record 3, содержит ValidateLocation для `268444786`; ему соответствует общий `timeline_seq=6`. Полные 19 ссылок с номерами пакетов, кадров и последующих описаний находятся в `updates_before_description` сводного JSON (`reports/decryption-20261121/prime-timeline/lifecycle-summary.json`).

Это подтверждённая последовательность сетевых сообщений при входе. Механизм её обработки клиентом и связь с серверным KnownList пока не установлены. В записи нет второго наблюдателя, серверных журналов KnownList и наблюдений отрисовки; взаимная невидимость этими данными не подтверждается.

## Разбор полей

Смещения отсчитываются от начала полного расшифрованного пакета, включая двухбайтовую длину. Числа little-endian; координаты знаковые 32-битные. Разбираются перечисленные поля, а не полная схема каждого сообщения.

| Направление/opcode | Поля |
| --- | --- |
| S→C `0C` NpcInfo | Object ID +3, значение шаблона +7, XYZ +15 |
| S→C `08` DeleteObject | Object ID +3, дополнительный DWORD +7; его смысл не присвоен |
| S→C `16` DropItem | ID источника +3, ID предмета +7, шаблон +11, XYZ +15, количество QWORD +31 |
| S→C `17` GetItem | ID владельца +3, ID предмета +7, XYZ +11 |
| S→C `2F` MoveToLocation | Object ID +3, XYZ назначения +7, исходные XYZ +19 |
| C→S `1F` Action | ID цели +3, собственные XYZ +7, байт Shift +19 |
| S→C `32` UserInfo, наблюдаемая сборка | Собственные XYZ +3, мировой Object ID +19, имя UTF-16Z +23 |

Первые шесть строк сопоставлены с первичными определениями NetPro: [NpcInfo](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/high_five/server/NpcInfo.xml), [DeleteObject](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/c2_age_of_splendor/server/DeleteObject.xml), [DropItem](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/gracia_final/server/DropItem.xml), [GetItem](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/prelude/server/GetItem.xml), [MoveToLocation](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/prelude_pts/server/MoveToLocation.xml), [Action](https://github.com/acmi/NetPro/blob/develop/l2emuproject-netpro-app/config/packets/prelude_pts/client/Action.xml). Копии схем, URL и SHA256 сохранены в `reports/decryption-20261121/references/semantic-schemas/`. UserInfo проверен по десяти сообщениям X501 в этой записи. Таблица opcode — эталон NetPro 448; полная совместимость Asterios с эталонными схемами не предполагается.

## Повторение анализа

Из корня проекта, после получения расшифрованных файлов:

```powershell
python src/analyze_prime_timeline.py reports/network-20261121-134122/prime-relogin.pcapng --decoded-dir reports/decryption-20261121/offline-prime --opcode-table reports/decryption-20261121/netpro-448-opcodes.csv --output-dir reports/decryption-20261121/prime-timeline
python -m unittest discover -s tests -v
```

Результаты:

- packet-timeline.csv (`reports/decryption-20261121/prime-timeline/packet-timeline.csv`) и JSONL рядом — все 2004 сообщения, кадры, время, opcode и выбранные поля.
- object-lifecycle.csv (`reports/decryption-20261121/prime-timeline/object-lifecycle.csv`) — состояние 107 описанных объектов.
- actions.csv (`reports/decryption-20261121/prime-timeline/actions.csv`) — состояние описания цели перед каждой командой.
- own-positions.csv (`reports/decryption-20261121/prime-timeline/own-positions.csv`) — координаты X501 по двум направлениям.
- lifecycle-summary.json (`reports/decryption-20261121/prime-timeline/lifecycle-summary.json`) — агрегаты, ссылки на ранние обновления, идентификаторы входных файлов и границы доказательств.

Для 1375 сообщений разобраны выбранные смысловые поля; остальные 629 включены в индекс с opcode и названием из справочника. Их тела уже расшифрованы, но этим инструментом дальше не интерпретируются.

Время — кадр, к которому впервые записан весь упорядоченный TCP-префикс до конца сообщения. Повторная передача не сдвигает его; ранний приход хвоста не обходит отсутствующий префикс. Порядок внутренних сообщений сжатого блока сохранён. Исходный `ts_epoch` сохранён строкой; отображаемый UTC округлён до микросекунд. Порядок захвата двух направлений не доказывает причинный порядок обработки на сервере и клиенте.

Проверки: **22 теста прошли**, включая задержанный TCP-префикс, повторную передачу, переполнение sequence number, конфликтующие байты, неизвестное состояние и повторное описание после удаления. Кадры всех **1879 серверных сообщений** также совпали с ранее независимо составленным индексом сетевых записей: attribution-verification.json (`reports/decryption-20261121/prime-timeline/attribution-verification.json`).
