# Записанные действия X501, 2026-11-21

Пользователь выполнял действия в клиенте; записывались PCAP и согласованные
состояния ключей, счётчиков, заголовка C→S и словаря DEFLATE. Каждый принятый
интервал проверен по конечным состояниям. Времена ниже — UTC из PCAP.

## Четыре цикла Gold ↔ Silver

Запись: `reports/exchange-gold-silver-01/exchange.pcapng`.
SHA-256: `35833c1e887f16c841b358c73f7f24fb15854a86329e1375d55f1476f8f3f921`.

Расшифрованы 616 серверных и 14 клиентских сообщений в 13 интервалах:
501 внешний серверный блок, включая 22 сжатых. Последний интервал после
всех обменов не принят из-за неполного хвоста захвата. Все восемь обменов
полностью находятся в проверенной части.

`RequestMultiSellChoose` C→S `B0`: полная длина 45, list_id=53728110,
entry_id=3 для Gold → Silver, entry_id=1 для Silver → Gold, amount=1.
Схема начала сопоставлена с [NetPro High Five](https://raw.githubusercontent.com/acmi/NetPro/develop/l2emuproject-netpro-app/config/packets/high_five/client/RequestMultiSellChoose.xml).
Ответы `InventoryUpdate` S→C `21` имеют счётчик u16 и наблюдаемые записи
предмета по 76 байт; разобранные поля проверены на записи этого клиента.
[Публичная схема для сравнения](https://raw.githubusercontent.com/acmi/NetPro/develop/l2emuproject-netpro-app/config/packets/high_five/server/InventoryUpdate.xml).

| Запрос UTC | Строка | Gold после | Silver после |
|---|---:|---:|---:|
| 17:31:59.963 | 3 | 14 | 10 |
| 17:32:07.152 | 1 | 15 | 0 |
| 17:32:10.257 | 3 | 14 | 10 |
| 17:32:13.158 | 1 | 15 | 0 |
| 17:32:16.129 | 3 | 14 | 10 |
| 17:32:19.075 | 1 | 15 | 0 |
| 17:32:26.634 | 3 | 14 | 10 |
| 17:32:29.148 | 1 | 15 | 0 |

Gold — Item ID 4356, постоянный OID стека 270322744. Silver — Item ID 4357;
его OID менялся при каждом новом стеке. Названия сопоставлены с сообщённым
пользователем действием, отношение и количества подтверждены ответами сервера.
Каждый обратный обмен удалял стек Silver и возвращал Gold к 15.
Машинный итог: `reports/exchange-gold-silver-01/summary.json`.

## Обучение умениям

Запись: `reports/skill-learning-01/capture.pcapng`.
SHA-256: `e4715abc47eda3f2d031213de4b1246a4a0ad9185320fed8d1bd1b418b2c1c4d`.
Все 11 интервалов проверены: 88 серверных и 14 клиентских сообщений,
77 внешних серверных блоков, 10 сжатых.

| Запрос UTC | Skill ID | Запрошенный уровень | Уровень в ответном SkillList |
|---|---:|---:|---:|
| 17:43:13.564 | 226 | 1 | 1 |
| 17:43:15.861 | 56 | 1 | 1 |
| 17:43:18.463 | 16 | 1 | 1 |
| 17:43:21.019 | 3 | 4 | 4 |

Запрос обучения — `7C`, запрос информации — `73`: skill ID u32 с полного
смещения 3, уровень u32 со смещения 7, тип списка u32 со смещения 11.
[Образец полей NetPro](https://raw.githubusercontent.com/acmi/NetPro/develop/l2emuproject-netpro-app/config/packets/c4_scions_of_destiny/client/RequestAcquireSkill.xml).

`SkillList` `5F` содержит u32 числа записей, затем записи по 18 байт:
passive u32, level u32, skill ID u32, группа u32, disabled/enchantable u8.
Наблюдаемая форма не содержит заключительного Newly learned DWORD из
[сравниваемой схемы Valiance](https://raw.githubusercontent.com/acmi/NetPro/develop/l2emuproject-netpro-app/config/packets/valiance/server/SkillList.xml).

В начале доступных собственных списков ID 3 имел уровень 3, в последнем — 4.
Пользователь сообщал намерение поднять 4 → 5, однако запись подтверждает 3 → 4.
После этого `ExAcquirableSkillListByClass` `FE F9 00` предложил для ID 3 уровень 5.
Это список доступного следующего обучения, а не список уже выученного.

У наблюдаемого `FE F9 00` число записей u32 по смещению 5. Каждая запись:
ID u32, level u32, SP u32, minimum level u16, число предметов u32, пары
item ID u32/amount u64, число обязательных умений u32 и пары ID/level u32.
Эта раскладка отличается от [NetPro Valiance](https://raw.githubusercontent.com/acmi/NetPro/develop/l2emuproject-netpro-app/config/packets/valiance/server/ExAcquirableSkillListByClass.xml)
и принята по полному покрытию всех четырёх записанных сообщений.
Машинный итог: `reports/skill-learning-01/summary.json`.

## Проверка штатного отправителя

По последующему прямому поручению пользователя проверен однократный внешний
вызов клиентского отправителя. Перед этим в Unicorn проверены родной сборщик
формата `b` и ABI переходника: `reports/native-sender-preflight/verification.json`.
Эмулятор не отправлял пакеты и не менял память игры.

Единственный реальный тест — запрос списка умений `03 00 50` в 18:00:37 UTC.
Переходник выполнялся отдельным потоком 125724. Функция вернулась, но целевой
запрос в PCAP отсутствует. Вместо него C→S `FF` содержит диагностический текст
`Packet Fake Send Thrd [0x50] 21896 != 125724`. Причина сообщения и модуль,
который его сформировал, ещё не установлены; несоответствие потоков — гипотеза.
[Подробная диагностика](fake-send-thread-diagnostic.md). Тест изменённого
запроса информации после этого не выполнялся.
Никаких запросов обучения или уровня 9 агент не отправлял.

PCAP: `reports/native-send-test-01/capture.pcapng`, SHA-256
`fb9d7a856dd2386950068c11919e408d1fb70813350372cc59ccc8f579652d62`.
Все 42 интервала расшифрованы: 849 серверных и 111 клиентских сообщений.
Остальные действия в этой записи выполнял пользователь; тест не воспроизводил
и не инициировал найденные команды использования предметов/заточки.
Итог: `reports/native-send-test-01/send-result.json`.

Отправка для данного профиля отключена. Проверка потока не обходилась,
идентификаторы потоков и клиентские проверки не изменялись. Монитор продолжает
пассивную работу.

## Повторение анализа сохранённых записей

```powershell
python src/decode_action_capture.py reports/exchange-gold-silver-01
python src/decode_action_capture.py reports/skill-learning-01
python src/decode_action_capture.py reports/native-send-test-01
```

Результаты: `decoded/packets.jsonl`, отдельные BIN по направлениям и
`decoded/verification.json`. Ключи и словари остаются в игнорируемых локальных
файлах экспериментов и в интерфейс API не выдаются.
