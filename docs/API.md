# JSON API / JSON-интерфейс

[English guide](guides/USER_GUIDE.en.md#14-json-api-and-command-line) · [Русское руководство](guides/USER_GUIDE.ru.md#14-json-api-и-параметры-запуска)

Start / запуск: `L2PacketMonitor.exe --api --port 8765`. Base URL: `http://127.0.0.1:8765`.

GET endpoints return JSON except exports. POST endpoints require `Content-Type: application/json` and `X-Monitor-Token`, obtained from `GET /api/info`. The API listens on loopback.

GET возвращает JSON, кроме экспорта файлов. Для POST нужны `Content-Type: application/json` и `X-Monitor-Token` из `GET /api/info`. API слушает loopback.

## Read / Чтение

| GET route | Result / Результат |
|---|---|
| `/api/health` | Application health / состояние приложения |
| `/api/info` | Version, token, categories and routes / версия, токен, категории и маршруты |
| `/api/status` | Capture, process, connection, counters / захват, процесс, соединение, счётчики |
| `/api/processes`, `/api/interfaces` | Discovery / обнаруженные процессы и адаптеры |
| `/api/sources` | Active source, profiles, bridge / источник, профили и мост |
| `/api/profiles/export` | Profile ZIP / ZIP профилей |
| `/api/ciphers`, `/api/sender` | Cipher modes, sender availability / шифры и доступность отправителя |
| `/api/packets?after=0&limit=250` | Packet page / страница пакетов |
| `/api/packets/{id}` | Packet detail with HEX / полная запись с HEX |
| `/api/types` | Observed message types / наблюдаемые типы |
| `/api/export` | Packet JSONL export / экспорт JSONL |
| `/api/items` | Nearby items / предметы рядом |
| `/api/inventory`, `/api/inventory/drop-queue` | Inventory and drop queue / инвентарь и очередь выброса |
| `/api/skills` | Learned skills / изученные скиллы |
| `/api/character` | Own character state / состояние персонажа |
| `/api/recovery`, `/api/auto-heal` | Recovery channels, legacy HP state / каналы восстановления и прежний HP |
| `/api/auto-pickup`, `/api/buffs` | Pickup and buff state / подбор и бафы |
| `/api/client-catalog?kind=items&search=&offset=0&limit=100` | Built-in catalog; `kind=skills` for skills / база клиента |
| `/api/library?kind=item&search=` | Observed ID catalog; `kind=skill` / справочник наблюдений |
| `/api/library/export?format=json` | Catalog JSON, or `format=csv` / экспорт справочника |
| `/api/packet-queue` | Prepared queue and progress / очередь и прогресс |
| `/api/drafts/{id}`, `/api/drafts/{id}.bin` | Saved packet copy / сохранённая копия |

Packet filters / фильтры: `direction=client|server`, `categories=movement,inventory`, `types=server:21,client:B0`, `search=...`. `after` is a nonnegative cursor; `limit` is 1–1000. Empty category/type lists hide all rows. `history_truncated` marks data that has left the buffer.

`after` — неотрицательный курсор, `limit` — 1–1000. Пустые списки категорий/типов скрывают все строки. `history_truncated` отмечает выход старых данных из буфера.

## Write / Управление

| POST route | JSON fields / Поля |
|---|---|
| `/api/start` | `pid`, `interface`, `cipher`, `source` |
| `/api/stop` | `{}` |
| `/api/source` | `mode`: `auto`, `network`, `client`, `server` |
| `/api/cipher` | `cipher` |
| `/api/convert` | `mode`, `hex`/`text`, `encoding`, `update_length` |
| `/api/drafts` | `hex`, `encoding`, optional `packet_id` |
| `/api/decrypt` | `hex`, `cipher`, `key`, `counter` |
| `/api/send` | `hex` |
| `/api/packet-queue/add` | `hex`, `direction=client` |
| `/api/packet-queue/start` | `repeats`, `interval_ms` |
| `/api/packet-queue/pause` | `paused`: boolean |
| `/api/packet-queue/stop`, `/api/packet-queue/clear` | `{}` |
| `/api/inventory/drop` | `object_id`, `amount`, `mode`, `interval_ms` |
| `/api/inventory/drop-pause` | `paused`: boolean |
| `/api/inventory/drop-stop` | `{}` |
| `/api/auto-pickup` | `enabled`, `radius`, `interval_ms` |
| `/api/skills/refresh` | `{}` |
| `/api/skills/learn` | `skill_id`, `level` |
| `/api/buffs/start` | `count` |
| `/api/recovery` | `resource=cp|hp|mp`, `enabled`, `item_id`, `threshold`, `interval_ms` |
| `/api/auto-heal` | `enabled`, `item_id`, `threshold`, `interval_ms` |
| `/api/bridge/start`, `/api/bridge/stop` | `{}` |
| `/api/bridge/configuration` | `{}` → current bridge configuration / конфигурация моста |
| `/api/bridge/export` | `{}` → SDK ZIP |

Action availability follows the current source and matching build. The desktop window owns queue execution. See [http_api.py](../src/l2_monitor/http_api.py) for response structures and validation.

Доступность действий зависит от источника и сборки. Выполнение очереди связано с нативным окном. Структуры ответов и проверки: [http_api.py](../src/l2_monitor/http_api.py).
