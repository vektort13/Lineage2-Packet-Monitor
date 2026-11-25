"""Native Qt Widgets interface for the passive monitor and local packet copies."""
import copy
import hashlib
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel, QByteArray, QEvent, QLibraryInfo, QModelIndex, QObject, QRunnable, QSettings,
    QSortFilterProxyModel, QSize, Qt, QThreadPool, QTimer, QTranslator, Signal, Slot,
)
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QComboBox, QFileDialog,
    QDialog, QDialogButtonBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QLayout, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox,
    QSplitter, QTabWidget, QTableView, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from . import discovery, live_state
from .editor import ENCODINGS, convert
from .protocol import CATEGORIES
from .client_icons import ClientIcons
from .cipher_profiles import CipherProfiles


DATA_ROOT = getattr(live_state, 'DATA_ROOT', live_state.ROOT)


ENGLISH = {
    'Авто': 'Auto', 'Зелье из инвентаря': 'Inventory potion', 'Порог, %': 'Below, %',
    'Интервал, сек': 'Interval, sec', 'Выберите зелье': 'Select a potion',
    'Нет выбранного зелья в инвентаре': 'Selected potion is absent from inventory',
    'Нет зелий в инвентаре': 'No potions in inventory',
    'Восстановление CP / HP / MP — в панели персонажа над вкладками.': 'CP / HP / MP recovery is in the character panel above the tabs.',
    'Разрешить автовосстановление этой полосы. Запуск — кнопкой справа.': 'Enable recovery for this resource. Start using the button on the right.',
    'После срабатывания восстанавливает до 100%. Серверный откат учитывается отдельно.': 'After triggering, recovers to 100%. Server cooldown is also respected.',
    'Выключено': 'Off', 'Ожидание данных': 'Waiting for data', 'Наблюдение': 'Monitoring',
    'До 100%': 'Recovering to 100%', 'Зелье закончилось': 'Out of potions', 'Персонаж погиб': 'Character is dead',
    'Источники': 'Sources', 'Источник пакетов': 'Packet source',
    'Авто: проверенный источник': 'Auto: verified source',
    'Сетевой захват': 'Network capture', 'Открытые пакеты клиента': 'Client plaintext packets',
    'Серверный мост': 'Server bridge', 'Текущий источник:': 'Current source:',
    'Протокол:': 'Protocol:', 'Алгоритмы:': 'Algorithms:',
    'Сохранённые профили клиентов': 'Saved client profiles',
    'Алгоритм': 'Algorithm', 'Проверка': 'Validation', 'Перехват клиента': 'Client tap',
    'Поддерживается': 'Supported', 'Не подключён': 'Not connected',
    'Авто выбирает проверенный перехват клиента, затем сетевой профиль; для неизвестной сборки показывает TCP без расшифровки.':
        'Auto selects a verified client tap, then a network profile; an unknown build is shown as undecoded TCP.',
    'Сетевой режим использует профиль сборки и текущие ключи соединения.':
        'Network mode uses the client build profile and current connection keys.',
    'Перехват открытых пакетов требует проверенного адаптера для этой сборки клиента.':
        'Plaintext capture requires a verified adapter for this client build.',
    'Серверный модуль передаёт открытые пакеты в локальный мост; протокол задаётся модулем.':
        'The server module sends plaintext packets to the local bridge; the module specifies the protocol.',
    'Остановите захват перед сменой источника': 'Stop capture before changing the source',
    'Запустить мост': 'Start bridge', 'Остановить мост': 'Stop bridge',
    'Экспорт модуля сервера…': 'Export server module…', 'Копировать конфигурацию': 'Copy configuration',
    'Мост остановлен': 'Bridge stopped', 'Мост запущен': 'Bridge running',
    'Принято:': 'Received:', 'Пропущено:': 'Dropped:', 'Сеансов:': 'Sessions:',
    'Конфигурация моста скопирована': 'Bridge configuration copied',
    'Модуль сервера экспортирован': 'Server module exported',
    'Импорт профилей…': 'Import profiles…', 'Экспорт профилей…': 'Export profiles…',
    'Профили импортированы': 'Profiles imported', 'Профили экспортированы': 'Profiles exported',
    'Источник ещё не выбран': 'Source not selected yet',
    'Для этой сборки нет проверенного адаптера открытых пакетов клиента':
        'This build has no verified client plaintext adapter',
    'Расшифровка работает; ключи обоих направлений проверены': 'Decryption is working; both directional keys are verified',
    'Для этой сборки клиента игровые действия пока не подключены': 'Game actions are not connected for this client build yet',
    'Выбранный шифр не соответствует проверенному профилю клиента; выберите Авто': 'The selected cipher does not match the verified client profile; select Auto',
    'Ожидание игрового клиента с установленным TCP-соединением': 'Waiting for a game client with an established TCP connection',
    'У клиента несколько TCP-соединений; игровое соединение неоднозначно': 'The client has multiple TCP connections; the game connection is ambiguous',
    'Соединение обнаружено; захват TCP. Для этой сборки клиента пока нет профиля расшифровки': 'Connected; capturing TCP. This client build does not have a decryption profile yet',
    'Это данные TCP без расшифровки и сборки пакетов; отправка через очередь недоступна': 'This is TCP data without decryption or packet reassembly; queue replay is unavailable',
    'Отправка': 'Sending', 'Пауза': 'Paused', 'Остановлено': 'Stopped', 'Завершено': 'Completed', '▶  Продолжить': '▶  Resume',
    'Пауза после подтверждения предыдущего пакета в захвате': 'Delay after the previous packet is confirmed in capture',
    'База клиента': 'Client database', 'Предметы': 'Items', 'Скиллы и бафы': 'Skills and buffs',
    'Описание': 'Description', 'Назад': 'Previous', 'Далее': 'Next', 'Экспорт всей базы…': 'Export full database…',
    'Записей:': 'Records:', 'Предметов:': 'Items:', 'Скиллов и бафов по уровням:': 'Skill and buff levels:',
    'Автохил': 'Automatic healing', 'Хилка': 'Healing item', 'Лечить при HP ниже, %': 'Start healing below HP, %',
    'Хилки не найдены в инвентаре': 'No healing items found in inventory', 'Выберите хилку': 'Select a healing item',
    'Автохил выключен': 'Automatic healing disabled', 'Автохил: ожидание данных': 'Automatic healing: waiting for data',
    'Автохил: наблюдение за HP': 'Automatic healing: watching HP', 'Автохил: лечение до 100%': 'Automatic healing: healing to 100%',
    'Автохил: хилка закончилась': 'Automatic healing: selected item is unavailable', 'Автохил: персонаж погиб': 'Automatic healing: character is dead',
    'Автохил: пауза': 'Automatic healing: paused', 'Автохил: ошибка': 'Automatic healing: failed',
    'Раз в секунду до 100% HP': 'Once per second until 100% HP', 'Персонаж: ожидание данных': 'Character: waiting for data',
    'Лечение продолжается до 100% HP': 'Healing continues until 100% HP',
    'Интервал применения, сек': 'Use interval, sec', 'Перезарядка хилки, сек:': 'Healing item cooldown, sec:',
    'Ник': 'Character', 'Уровень': 'Level', 'Попыток применения:': 'Use attempts:',
    'Поиск по названию или ID': 'Search by name or ID',
    'Скиллы': 'Skills', 'Повысить уровень скилла': 'Increase skill level',
    'Ввести ID и уровень…': 'Enter ID and level…', 'Скилл по ID': 'Skill by ID',
    'Количество раз': 'Repetitions', 'Старт': 'Start', 'Уровень бафа': 'Buff level',
    'Осталось, сек': 'Remaining, sec', 'Newbie Buff: готов': 'Newbie Buff: ready',
    'Newbie Buff: открытие NPC': 'Newbie Buff: opening NPC', 'Newbie Buff: отправка': 'Newbie Buff: sending',
    'Newbie Buff: ожидание ответа': 'Newbie Buff: waiting for response', 'Newbie Buff: завершено': 'Newbie Buff: completed',
    'Newbie Buff: частично подтверждено': 'Newbie Buff: partially confirmed', 'Newbie Buff: ошибка': 'Newbie Buff: failed',
    'Отправлено:': 'Sent:', 'Запросов в захвате:': 'Captured requests:', 'Подтверждено наборов:': 'Confirmed bundles:',
    'Автоподбор: пауза на время бафов': 'Automatic pickup: paused during buffs',
    'Обновить список скиллов': 'Refresh skill list', 'Новый уровень': 'New level',
    'Текущий уровень': 'Current level', 'ID скилла': 'Skill ID', 'Тип скилла': 'Skill type',
    'Активный': 'Active', 'Пассивный': 'Passive', 'Недоступен': 'Disabled',
    'Ожидание списка скиллов': 'Waiting for skill list', 'Обновление списка скиллов': 'Refreshing skill list',
    'Список скиллов обновлён': 'Skill list updated', 'Обучение завершено': 'Learning completed',
    'Ожидание подтверждения обучения': 'Waiting for learning confirmation',
    'Ожидание обучения': 'Learning queued', 'Обучение не подтверждено': 'Learning not confirmed',
    'Обучение скиллов для этой сборки клиента пока не подключено': 'Skill learning is not connected for this client build yet',
    'Синхронизация захвата потеряна': 'Capture synchronization was lost',
    'Обучение скилла': 'Learning a skill', 'Запрошенный уровень': 'Requested level',
    'Автоподбор: пауза на время обучения': 'Automatic pickup: paused during learning',
    'Полученный уровень': 'Actual level', 'Изученных скиллов:': 'Owned skills:',
    'Пакеты, объекты и словарь игрового протокола': 'Packets, objects and game protocol catalog',
    'НАТИВНЫЙ МОНИТОР': 'NATIVE MONITOR', 'SELF TEST · ЛОКАЛЬНЫЕ ОБРАЗЦЫ': 'SELF TEST · LOCAL SAMPLES',
    'Тема оформления': 'Appearance', 'Язык интерфейса': 'Interface language',
    '☾  Тёмная': '☾  Dark', '☀  Светлая': '☀  Light', 'Файл': 'File',
    'Свернуть': 'Minimize', 'Развернуть': 'Maximize', 'Восстановить': 'Restore', 'Закрыть': 'Close',
    'PID: автоматически': 'PID: automatic', 'PID процесса': 'Process PID',
    'Интерфейс: автоматически': 'Interface: automatic', 'Обновить': 'Refresh',
    'Шифр:': 'Cipher:',
    '▶  Начать захват': '▶  Start capture', '■  Стоп': '■  Stop',
    'ПАКЕТОВ': 'PACKETS', 'КАДРОВ ЗАХВАЧЕНО': 'CAPTURED FRAMES', 'ПРОВЕРЕНО ОКОН': 'VERIFIED WINDOWS',
    'СИНХРОНИЗАЦИЯ': 'SYNCHRONIZATION', 'ШИФР / ЗАХВАТ': 'CIPHER / CAPTURE',
    'Пакеты': 'Packets', 'Предметы рядом': 'Nearby items', 'Справочник ID': 'ID catalog',
    'Инвентарь': 'Inventory', 'Инвентарь и ручной выброс': 'Inventory and manual drop',
    'Очередь пакетов': 'Packet queue', 'Готово': 'Ready', 'пакетов в таблице': 'packets in table',
    'Отправка очереди для этой сборки клиента пока не подключена': 'Queue sending is not connected for this client build yet',
    'Серверный пакет S→C нельзя отправить серверу как клиентский запрос': 'A server S→C packet cannot be sent to the server as a client request',
    'Строка': 'Row',
    'Выбрать пакеты C → S': 'Choose C → S packets',
    'Ожидание открытых пакетов от серверного модуля': 'Waiting for plaintext packets from the server module',
    'Серверный источник открытых пакетов работает': 'Server plaintext capture is active',
    'Подключение открытого захвата клиента': 'Connecting client plaintext capture',
    'Захват открытых пакетов клиента работает': 'Client plaintext capture is active',
    'Открытый захват клиента недоступен:': 'Client plaintext capture unavailable:',
    'Серверный мост остановлен': 'Server bridge stopped',
    'Экспорт захваченных пакетов в JSON…': 'Export captured packets to JSON…', 'Выход': 'Exit',
    'Поиск по opcode, имени пакета и полям…': 'Search opcode, packet name and fields…',
    'Оба направления': 'Both directions', 'Сервер → клиент': 'Server → client', 'Клиент → сервер': 'Client → server',
    'Следить за потоком': 'Follow stream', 'Сброс фильтров': 'Reset filters',
    'КАТЕГОРИИ И ТИПЫ': 'CATEGORIES AND TYPES', 'Все': 'All', 'Ничего': 'None', 'Типы пакетов': 'Packet types',
    'Движение': 'Movement', 'Появление / объект': 'Appearance / object', 'Удаление': 'Removal',
    'Бой / умения': 'Combat / skills', 'Обучение / список умений': 'Learning / skill list', 'Цель': 'Target',
    'Предметы': 'Items', 'Обмен / магазин': 'Trade / shop', 'Выбрасывание': 'Drop', 'Поднятие': 'Pickup',
    'Предмет рядом': 'Ground item', 'Действие с предметом': 'Item action', 'Сеанс': 'Session',
    'Диалог / команда': 'Dialogue / command', 'Состояние': 'State', 'Служебный': 'Service',
    'Сжатый блок': 'Compressed block', 'Неизвестный': 'Unknown', 'Ошибка / отказ': 'Error / rejection',
    '№': '#', 'Время': 'Time', 'Поток': 'Direction', 'Тип пакета': 'Packet type', 'Категория': 'Category', 'Байт': 'Bytes',
    'Выберите пакет': 'Select a packet', 'Поле': 'Field', 'Значение': 'Value',
    'РЕДАКТОР КОПИИ ПАКЕТА': 'PACKET COPY EDITOR', 'Исправить u16': 'Fix u16 length', 'Сброс': 'Reset',
    'HEX-копия выбранного пакета': 'HEX copy of the selected packet',
    'Текст с escape-последовательностями \\xNN': 'Text with \\xNN escape sequences',
    'Текст': 'Text', 'HEX → Текст': 'HEX → Text', 'Текст → HEX': 'Text → HEX',
    'Сохранить BIN…': 'Save BIN…', 'Сохранить JSON…': 'Save JSON…', 'Добавить копию в очередь': 'Add copy to queue',
    'Предметы из наблюдаемых пакетов': 'Items from observed packets', 'Количество': 'Quantity',
    'ID предмета': 'Item ID', 'Объект ID': 'Object ID', 'Слот': 'Slot',
    'Копировать ID': 'Copy ID', 'Подготовить ручной выброс': 'Prepare manual drop',
    'Наблюдаемых позиций:': 'Observed positions:',
    'Автоматически открывать инвентарь': 'Open inventory automatically',
    'Автооткрытие: ожидание синхронизации': 'Auto-open: waiting for synchronization',
    'Автооткрытие: ожидание игрового окна': 'Auto-open: waiting for the game window',
    'Автооткрытие: ожидается список предметов': 'Auto-open: waiting for the item list',
    'Автооткрытие: список предметов получен': 'Auto-open: item list received',
    'Автооткрытие: список предметов не получен': 'Auto-open: item list not received',
    'Автооткрытие выключено': 'Auto-open disabled',
    'Выбросить…': 'Drop…', 'Выбросить одну штуку': 'Drop one item',
    'Выбросить количество…': 'Drop quantity…', 'Выбрасывать по одной…': 'Drop one at a time…',
    'Выброс предметов': 'Drop items', 'Добавить в очередь': 'Add to queue',
    'По одной штуке': 'One at a time', 'Сразу указанное количество': 'Entire quantity at once',
    'Режим': 'Mode', 'Интервал, мс': 'Interval, ms', 'Доступно:': 'Available:',
    'Пауза после ответа, мс': 'Delay after response, ms',
    'Место выброса: рядом с персонажем. Координаты берутся из клиента перед каждым действием.':
        'Drop location: next to your character. Coordinates are read from the client before each action.',
    'Очередь выброса': 'Drop queue', 'Пауза выброса': 'Pause drops',
    'Продолжить выброс': 'Resume drops', 'Остановить выброс': 'Stop drops',
    'Выброшено': 'Dropped', 'Место выброса': 'Drop location', 'Ошибка': 'Error',
    'В очереди': 'Queued', 'Выполняется': 'Running', 'Ожидание ответа сервера': 'Waiting for server response',
    'Завершено': 'Completed', 'Остановлено': 'Stopped', 'Отправляется': 'Sending',
    'Введите количество от 1 до доступного остатка': 'Enter a quantity between 1 and the available amount',
    'Дополнительные опции': 'Additional options', 'Автоподбор окружающих вещей': 'Pick up nearby items automatically',
    'Радиус подбора': 'Pickup radius', 'Пауза после подбора, мс': 'Delay after pickup, ms',
    'Подбирает всё, включая выброшенные программой предметы.': 'Picks up all items, including items dropped by the program.',
    'На время очереди выброса автоподбор приостанавливается.': 'Automatic pickup pauses while the drop queue is active.',
    'Автоподбор выключен': 'Automatic pickup disabled', 'Автоподбор: ожидание синхронизации': 'Automatic pickup: waiting for synchronization',
    'Автоподбор: поиск предметов рядом': 'Automatic pickup: watching for nearby items',
    'Автоподбор: ожидание ответа сервера': 'Automatic pickup: waiting for server response',
    'Автоподбор: пауза на время выброса': 'Automatic pickup: paused while dropping items',
    'Автоподбор: ошибка': 'Automatic pickup: error', 'Подобрано предметов:': 'Picked up objects:',
    'Количество подобранных вещей:': 'Picked up quantity:', 'Неподтверждённых попыток:': 'Unconfirmed attempts:',
    'Выбери строку, скопируй ID и подтверди выброс обычным меню игрового клиента.': 'Select a row, copy the ID, and confirm the drop using the game client menu.',
    'Как выбросить в клиенте': 'How to drop in the client', 'Выберите предмет в таблице': 'Select an item in the table',
    'Ручной выброс': 'Manual drop', 'Открой инвентарь в клиенте.': 'Open the inventory in the client.',
    'Выбери этот предмет.': 'Select this item.', 'Нажми правой кнопкой и выбери «Выбросить».': 'Right-click it and choose “Drop”.',
    'Подтверди действие в клиенте.': 'Confirm the action in the client.',
    'Монитор только показывает наблюдение и ничего не отправляет.': 'The monitor only shows an observation and sends nothing.',
    'ID предмета скопирован:': 'Item ID copied:', 'Подготовка завершена:': 'Preparation complete:',
    'Расстояние XY': 'XY distance', 'Координаты': 'Coordinates', 'Событие': 'Event', 'Владелец': 'Owner',
    'Предметы и умения': 'Items and skills', 'Умения': 'Skills', 'Все серверы': 'All servers',
    'Поиск ID или названия…': 'Search ID or name…', 'Наблюдаемые ID, уровни и серверные профили': 'Observed IDs, levels and server profiles',
    'Тип': 'Type', 'Уровень': 'Level', 'Название': 'Name', 'Сервер': 'Server', 'Профиль': 'Profile',
    'Наблюдений': 'Observations', 'Последний раз': 'Last seen', 'Предмет': 'Item', 'Умение': 'Skill',
    'Рядом': 'Nearby', 'Не уточнён': 'Uncertain', 'Поднят': 'Picked up', 'Удалён': 'Removed',
    'Отправка на сервер недоступна': 'Server transmission is unavailable',
    'Последний тест: CMPF0: 6B8C11AD [0x50]; пакет 0x50 не подтверждён захватом': 'Last test: CMPF0: 6B8C11AD [0x50]; packet 0x50 was not confirmed in capture',
    'В исходящем потоке записано CMPF0: 6B8C11AD [0x50]; пакет 0x50 не подтверждён': 'Outgoing stream recorded CMPF0: 6B8C11AD [0x50]; packet 0x50 was not confirmed',
    'Добавьте копии пакетов через контекстное меню или редактор': 'Add packet copies using the context menu or editor',
    'Исходный №': 'Source #', '↑  Выше': '↑  Move up', '↓  Ниже': '↓  Move down',
    'Удалить': 'Remove', 'Очистить': 'Clear', 'Экспорт JSON…': 'Export JSON…',
    'Циклов': 'Cycles', 'Интервал, мс': 'Interval, ms', '▶  Отправить очередь': '▶  Send queue',
    'Ⅱ  Пауза': 'Ⅱ  Pause',
    'Введите числовой PID или выберите процесс из списка': 'Enter a numeric PID or select a process from the list',
    'Процессов:': 'Processes:', 'интерфейсов:': 'interfaces:', 'Остановка захвата…': 'Stopping capture…',
    'ошибок': 'errors', 'Есть промежуток без наблюдений': 'There is a gap in observations',
    'Предметов рядом:': 'Nearby items:', 'Координаты персонажа:': 'Character coordinates:',
    'элементов': 'entries', 'не совпадает': 'mismatch', 'совпадает': 'matches', 'байт': 'bytes',
    'Сохранить копию пакета': 'Save packet copy', 'Сохранено:': 'Saved:',
    'Экспорт захваченных пакетов': 'Export captured packets', 'Записей:': 'Entries:',
    'Экспорт справочника': 'Export ID catalog', 'Справочник сохранён:': 'Catalog saved:',
    'Повторить N раз': 'Repeat N times', 'Добавить в очередь': 'Add to queue',
    'Копия добавлена в очередь': 'Copy added to the queue', 'Число повторов:': 'Repeat count:',
    'Отправка пакета на сервер не реализована': 'Sending packets to the server is not implemented',
    'Копия пуста': 'The copy is empty',
    'Копия из редактора добавлена в очередь': 'Editor copy added to the queue', 'Экспорт очереди копий': 'Export packet queue',
    'Копий:': 'Copies:', 'Добавляйте пакеты через ПКМ или редактор': 'Add packets using right-click or the editor',
    'Завершение захвата…': 'Finishing capture…', 'Запрос: выбросить': 'Request: drop',
    'Сервер: выброшен': 'Server: dropped', 'Предмет появился': 'Item appeared', 'Сервер: поднят': 'Server: picked up', 'Предмет удалён': 'Item removed',
    'Захват остановлен': 'Capture stopped', 'Поиск игрового процесса': 'Looking for the game process',
    'Синхронизация ключей и словаря': 'Synchronizing keys and dictionary', 'Ключи и словарь проверены': 'Keys and dictionary verified',
    'Захват завершён:': 'Capture ended:', 'Игровое соединение изменилось; повторное подключение монитора': 'Game connection changed; reconnecting the monitor',
    'Повторная синхронизация:': 'Resynchronizing:', 'Ожидание AsteriosGame.exe с подключением к игровому серверу': 'Waiting for AsteriosGame.exe connected to a game server',
    'Найдено несколько клиентов: выберите PID в панели': 'Multiple clients found: select a PID',
    'Выберите интерфейс захвата: автоматический выбор неоднозначен': 'Select a capture interface: automatic selection is ambiguous',
    'Npcap не установлен: не найден System32/Npcap/wpcap.dll': 'Npcap is not installed: System32/Npcap/wpcap.dll was not found',
    'Неподдерживаемый тип интерфейса Npcap:': 'Unsupported Npcap interface type:', 'Npcap превысил snaplen': 'Npcap exceeded snaplen',
    'Поток Npcap ещё завершается; дескриптор сохранён': 'Npcap thread is still finishing; its handle is retained',
    'Остановите воспроизведение перед изменением очереди': 'Stop playback before editing the queue',
    'В очереди не более 1000 пакетов': 'The queue can hold up to 1000 packets', 'Число повторов: 1..10000': 'Repeat count: 1..10000',
    'Интервал: 0..60000 мс': 'Interval: 0..60000 ms', 'Очередь пуста': 'The queue is empty',
    'Незавершённая escape-последовательность': 'Incomplete escape sequence',
    'Неизвестная escape-последовательность; для обратной косой черты используйте \\\\': 'Unknown escape sequence; use \\\\ for a backslash',
    'Ожидается строка HEX': 'Expected a HEX string', 'HEX должен содержать пары цифр 00–FF': 'HEX must contain pairs of digits 00–FF',
    'Буфер ограничен 65535 байтами': 'Buffer is limited to 65535 bytes', 'Кодировка: utf-8, utf-16le, cp1251 или latin-1': 'Encoding: utf-8, utf-16le, cp1251 or latin-1',
    'Ожидается строка текста': 'Expected a text string', 'mode: hex-to-text или text-to-hex': 'mode: hex-to-text or text-to-hex',
    'Для заголовка пакета нужно не менее трёх байт': 'A packet header requires at least three bytes',
    'Преобразование кодировки не сохранило исходные байты': 'Encoding conversion did not preserve the original bytes',
    'Сборка Engine.dll не совпадает с проверенным профилем': 'Engine.dll build does not match the verified profile',
    'Расположение или код шифра изменились; нужен другой профиль': 'Cipher layout or code changed; a different profile is required',
    'Сетевая структура клиента не соответствует профилю': 'Client network structure does not match the profile',
    'Контекст DEFLATE ещё не находится на проверенной границе блока': 'DEFLATE context is not at a verified block boundary yet',
    'Не удалось получить согласованное состояние клиента; повтор синхронизации': 'Could not obtain a consistent client state; retrying synchronization',
    'Счётчик сеанса сброшен или окно наблюдения потеряно': 'Session counter reset or observation window lost',
    'Неожиданная граница или размер DEFLATE': 'Unexpected DEFLATE boundary or size',
    'Конечный словарь DEFLATE не совпал с работающим клиентом': 'Final DEFLATE dictionary does not match the running client',
    'Число распакованных байтов не совпало с работающим клиентом': 'Expanded byte count does not match the running client',
    'Потерян TCP-префикс после последнего проверенного пакета': 'TCP prefix lost after the last verified packet',
    'Ожидание TCP-данных для заголовка': 'Waiting for TCP header data', 'Недопустимая длина записи': 'Invalid record length',
    'Ожидание TCP-хвоста сообщения': 'Waiting for the TCP message tail', 'Неизвестный альтернативный шифр': 'Unknown alternative cipher',
    'Неизвестный шифр': 'Unknown cipher', 'XOR16: обратное шифрование не совпало': 'XOR16: reverse encryption mismatch',
    'состояние длины не соответствует открытому заголовку': 'length state does not match the plaintext header',
    'Автоопределение требует интервала пакетов и контрольных состояний клиента': 'Auto detection requires a packet interval and reference client states',
    'Требуется ключ из 16 байт': 'A 16-byte key is required',
}
_EN_PATTERN = re.compile('|'.join(re.escape(key) for key in sorted(ENGLISH, key=len, reverse=True)))


def translate(text, language='ru'):
    text = str(text)
    if language != 'en':
        return text
    if text in ENGLISH:
        return ENGLISH[text]
    match = re.fullmatch(r'После (\\[xuU]) нужно (\d+) шестнадцатеричных цифр', text)
    if match:
        return f'{match[1]} requires {match[2]} hexadecimal digits'
    text = re.sub(r'число записей (client|server) не совпало со счётчиком', r'\1 record count does not match the counter', text)
    text = re.sub(r'конечный ключ (client|server) не совпал', r'final \1 key mismatch', text)
    return _EN_PATTERN.sub(lambda match: ENGLISH[match.group(0)], text)


STYLE = """
QMainWindow, QWidget { background: #10151e; color: #dce5f3; font-family: 'Segoe UI'; font-size: 10pt; }
QWidget#titleBar { background: #151d2a; border: 1px solid #29354a; border-radius: 9px; }
QWidget#titleBar QLabel { background: transparent; border: none; }
QLabel#title { color: #f0f5ff; font-size: 17pt; font-weight: 650; }
QLabel#appMark { color: white; background: #2164b7; border: 1px solid #3a82d8; border-radius: 10px; font-size: 16pt; font-weight: 700; }
QWidget#titleBar QLabel#appMark { background: #2164b7; border: 1px solid #3a82d8; }
QPushButton#windowButton { background: transparent; border: none; border-radius: 5px; color: #9eafc8; font-family: 'Segoe UI Symbol'; font-size: 14pt; padding: 0px; }
QPushButton#windowButton:hover { background: #304966; color: #f0f5ff; }
QPushButton#closeButton { background: transparent; border: none; border-radius: 5px; color: #9eafc8; font-family: 'Segoe UI Symbol'; font-size: 14pt; padding: 0px; }
QPushButton#closeButton:hover { background: #b3324c; color: white; }
QLabel#creator { color: #96c9ff; background: #1b2c3c; border: 1px solid #365269; border-radius: 5px; padding: 5px 13px; font-size: 11pt; font-weight: 700; }
QLabel#subtle { color: #8f9db4; }
QLabel#section { color: #9eafc8; font-weight: 600; font-size: 9pt; }
QLabel#badge { border: 1px solid #365269; border-radius: 5px; color: #81c4ff; padding: 5px 10px; background: #1b2c3c; }
QFrame#metric { background: #151f2d; border: 1px solid #26354a; border-radius: 7px; }
QFrame#metric QLabel { background: transparent; }
QLabel#metricValue { color: #ecf4ff; font-size: 19pt; font-weight: 600; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit { background: #0c121b; border: 1px solid #2d3c52; border-radius: 5px; padding: 6px; selection-background-color: #285784; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus { border: 1px solid #589cf0; }
QComboBox::drop-down { border: none; width: 23px; }
QComboBox QAbstractItemView { background: #1b2636; selection-background-color: #2b527d; }
QPushButton { background: #223248; border: 1px solid #344b68; border-radius: 5px; padding: 7px 12px; font-weight: 600; }
QPushButton:hover { background: #304966; border-color: #5684b5; }
QPushButton:pressed { background: #16283c; }
QPushButton:disabled { color: #66768a; background: #192130; border-color: #293448; }
QPushButton#primary { background: #2164b7; border-color: #3a82d8; color: white; }
QPushButton#primary:hover { background: #2c78cc; }
QPushButton#danger { background: #482832; border-color: #71404e; color: #ffb0b8; }
QPushButton#primary:disabled, QPushButton#danger:disabled { color: #66768a; background: #192130; border-color: #293448; }
QTabWidget::pane { border: 1px solid #27364a; top: -1px; }
QTabBar::tab { background: #151e2b; border: 1px solid #27364a; padding: 10px 18px; color: #96a7bf; }
QTabBar::tab:selected { color: #e8f2ff; background: #21334a; border-bottom: 2px solid #61a7ff; }
QTabBar::tab:hover { background: #223249; }
QTableView, QTreeWidget { background: #0e1520; alternate-background-color: #121d2a; border: 1px solid #29374b; gridline-color: #202c3c; selection-background-color: #203e5c; selection-color: #f4f8ff; }
QHeaderView::section { background: #1b283a; color: #a8bad3; border: none; border-right: 1px solid #2a3b52; border-bottom: 1px solid #30445e; padding: 9px 7px; font-weight: 600; }
QTableView::item { padding: 5px; border-bottom: 1px solid #172335; }
QTreeWidget::item { padding: 4px 1px; }
QTreeWidget::item:hover { background: #1b2a3e; }
QCheckBox { spacing: 7px; }
QCheckBox::indicator, QTreeWidget::indicator { width: 14px; height: 14px; border: 1px solid #53657e; border-radius: 3px; background: #142132; }
QCheckBox::indicator:checked, QTreeWidget::indicator:checked { background: #4389df; border: 2px solid #91bfff; }
QSplitter::handle { background: #223047; }
QSplitter::handle:hover { background: #3f6087; }
QScrollBar:vertical { background: #101824; width: 11px; }
QScrollBar::handle:vertical { background: #354861; min-height: 25px; border-radius: 5px; }
QScrollBar:horizontal { background: #101824; height: 11px; }
QScrollBar::handle:horizontal { background: #354861; min-width: 25px; border-radius: 5px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; }
QStatusBar { background: #151f2d; color: #9bacc3; }
QStatusBar::item { border: none; }
QMenu { background: #1a2739; border: 1px solid #425572; padding: 4px; }
QMenu::item { padding: 8px 20px; }
QMenu::item:selected { background: #2a4f79; }
QToolTip { color: #e6effc; background: #22354e; border: 1px solid #577392; padding: 5px; }
"""

# The light palette keeps the same layout and focus/selection affordances.
LIGHT_COLORS = {
    '#10151e': '#f2f5fa', '#dce5f3': '#23334b', '#151d2a': '#ffffff',
    '#29354a': '#d3deec', '#f0f5ff': '#16345c', '#9eafc8': '#536985',
    '#304966': '#dfeafb', '#b3324c': '#c32946', '#96c9ff': '#185b9f',
    '#1b2c3c': '#e6f0fd', '#365269': '#b7cfe9', '#8f9db4': '#62758e',
    '#81c4ff': '#225e9f', '#151f2d': '#ffffff', '#26354a': '#d8e2ee',
    '#ecf4ff': '#1d3658', '#0c121b': '#ffffff', '#2d3c52': '#c4d2e4',
    '#285784': '#c7ddfa', '#589cf0': '#377fc8', '#1b2636': '#ffffff',
    '#2b527d': '#c8dff9', '#223248': '#edf3fb', '#344b68': '#bed0e7',
    '#5684b5': '#88afd9', '#16283c': '#d5e5f9', '#66768a': '#92a0b2',
    '#192130': '#e8eef5', '#293448': '#d6e0ec', '#2164b7': '#2164b7',
    '#3a82d8': '#3a82d8', '#2c78cc': '#2c78cc', '#482832': '#ffedf0',
    '#71404e': '#e8bcc6', '#ffb0b8': '#a92f49', '#27364a': '#d0ddeb',
    '#151e2b': '#e7eef8', '#96a7bf': '#5c708d', '#e8f2ff': '#154c8c',
    '#21334a': '#ffffff', '#61a7ff': '#2c79cf', '#223249': '#dce8f8',
    '#0e1520': '#ffffff', '#121d2a': '#f5f8fd', '#29374b': '#cfdaea',
    '#202c3c': '#e6edf5', '#203e5c': '#d5e6fb', '#f4f8ff': '#132d50',
    '#1b283a': '#e9f0f9', '#a8bad3': '#4e6482', '#2a3b52': '#d4dfec',
    '#30445e': '#c5d4e7', '#172335': '#edf2f9', '#1b2a3e': '#e6effb',
    '#53657e': '#9badc4', '#142132': '#ffffff', '#4389df': '#4389df',
    '#91bfff': '#377bcf', '#223047': '#dce5f1', '#3f6087': '#9dbce0',
    '#101824': '#eff4fa', '#354861': '#c2d1e4', '#9bacc3': '#5c7290',
    '#1a2739': '#ffffff', '#425572': '#b6c9e1', '#2a4f79': '#d5e6fb',
    '#e6effc': '#223c5e', '#22354e': '#f8fbff', '#577392': '#b4c9e2',
}
LIGHT_STYLE = re.sub(r'#[0-9a-fA-F]{6}', lambda match: LIGHT_COLORS.get(match.group(0), match.group(0)), STYLE)


def packet_color(value, light=False):
    color = QColor(value)
    return color.darker(165) if light else color


class TitleBar(QWidget):
    """Custom native controls; Qt delegates moving/sizing to the Windows manager."""
    def __init__(self, window):
        super().__init__(window)
        self.owner = window
        self.setObjectName('titleBar')
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setMouseTracking(True)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.owner.windowHandle():
            self.owner.windowHandle().startSystemMove()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.owner.toggle_maximized()
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)


def button(text, action, primary=False, danger=False):
    result = QPushButton(text)
    result.setProperty('_l2SourceText', text)
    result.clicked.connect(action)
    if primary:
        result.setObjectName('primary')
    elif danger:
        result.setObjectName('danger')
    return result


def label(text, name='subtle'):
    result = QLabel(text)
    result.setProperty('_l2SourceText', text)
    result.setObjectName(name)
    return result


def display(value):
    if value is None:
        return '—'
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


class TaskSignals(QObject):
    result = Signal(object)
    error = Signal(str)
    finished = Signal()


class Task(QRunnable):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.signals = TaskSignals()

    @Slot()
    def run(self):
        try:
            self.signals.result.emit(self.function())
        except Exception as error:
            self.signals.error.emit(str(error))
        finally:
            self.signals.finished.emit()


class RowsModel(QAbstractTableModel):
    """Bounded table data; no widgets are allocated per row."""
    def __init__(self, columns, parent=None, packet_colors=False, icon_kind=None, icon_column=None):
        super().__init__(parent)
        self.columns, self.rows = columns, []
        self.packet_colors = packet_colors
        self.light_theme = False
        self.language = 'ru'
        self.highlight_id = None
        self.icons = getattr(parent, 'client_icons', None)
        self.icon_kind, self.icon_column = icon_kind, icon_column

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return translate(self.columns[section][0], self.language)
        return super().headerData(section, orientation, role)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        row = self.rows[index.row()]
        key = self.columns[index.column()][1]
        value = row.get(key)
        if role == Qt.ItemDataRole.DecorationRole and self.icons and self.icon_kind and key == self.icon_column:
            kind = self.icon_kind
            if kind == 'item':
                return self.icons.icon('item', row.get('item_id'))
            if kind == 'skill':
                return self.icons.icon('skill', row.get('skill_id'), row.get('skill_level'))
            if kind == 'catalog':
                return self.icons.icon('skill' if 'level' in row else 'item', row.get('id'), row.get('level'))
            if kind == 'library':
                return self.icons.icon(row.get('kind'), row.get('entity_id'), row.get('level'))
            if kind == 'world':
                return self.icons.icon('item', row.get('template_value'))
        if role == Qt.ItemDataRole.DisplayRole:
            if key == 'time' and value:
                return str(value)[11:23]
            if key == 'direction':
                return {'server': 'S → C', 'client': 'C → S'}.get(value, display(value))
            if key == 'category':
                return translate(CATEGORIES.get(value, (value, ''))[0], self.language)
            if key == 'kind':
                return translate({'item': 'Предмет', 'skill': 'Умение'}.get(value, value), self.language)
            if key == 'state':
                return translate({'present': 'Рядом', 'uncertain': 'Не уточнён', 'picked_up': 'Поднят', 'removed': 'Удалён'}.get(value, value), self.language)
            if key == 'label':
                return translate(value, self.language)
            return display(value)
        if role == Qt.ItemDataRole.ToolTipRole:
            if key in ('category', 'kind', 'state', 'label'):
                return self.data(index, Qt.ItemDataRole.DisplayRole)
            return display(value)
        if role == Qt.ItemDataRole.ForegroundRole and self.packet_colors and key in ('opcode', 'name', 'category', 'direction'):
            return packet_color(row.get('color', '#acbfd8'), self.light_theme)
        if role == Qt.ItemDataRole.BackgroundRole and self.highlight_id is not None and row.get('id') == self.highlight_id:
            return QColor('#d5edda' if self.light_theme else '#334e36')
        if role == Qt.ItemDataRole.TextAlignmentRole and isinstance(value, (int, float)):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None

    def replace(self, rows):
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()

    def append(self, rows, capacity=10000):
        if not rows:
            return
        remove = max(0, len(self.rows) + len(rows) - capacity)
        if remove:
            self.beginRemoveRows(QModelIndex(), 0, min(remove, len(self.rows)) - 1)
            del self.rows[:remove]
            self.endRemoveRows()
        start = len(self.rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        self.rows.extend(rows)
        self.endInsertRows()

    def highlight(self, packet_id):
        if self.highlight_id == packet_id:
            return
        self.highlight_id = packet_id
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, len(self.columns) - 1), [Qt.ItemDataRole.BackgroundRole])


class PacketFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.search, self.direction = '', None
        self.categories, self.types = None, None
        self.setDynamicSortFilter(True)

    def filterAcceptsRow(self, row, parent):
        packet = self.sourceModel().rows[row]
        if self.direction and packet.get('direction') != self.direction:
            return False
        if self.categories is not None and packet.get('category') not in self.categories:
            return False
        if self.types is not None and packet.get('direction', '') + ':' + packet.get('opcode', '') not in self.types:
            return False
        return not self.search or self.search in (str(packet.get('opcode', '')) + ' ' + packet.get('name', '') + ' ' + json.dumps(packet.get('fields', {}), ensure_ascii=False)).lower()

    def refilter(self):
        self.invalidateFilter()


PACKET_COLUMNS = [('№', 'id'), ('Время', 'time'), ('Поток', 'direction'), ('Opcode', 'opcode'),
                  ('Тип пакета', 'name'), ('Категория', 'category'), ('Байт', 'length')]


def table(model, minimum_rows=False):
    view = QTableView()
    view.setModel(model)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.verticalHeader().hide()
    view.verticalHeader().setDefaultSectionSize(32)
    if getattr(model, 'icon_kind', None):
        view.setIconSize(QSize(32, 32))
        view.verticalHeader().setDefaultSectionSize(40)
    view.horizontalHeader().setStretchLastSection(True)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    view.setShowGrid(False)
    view.setWordWrap(False)
    if minimum_rows:
        view.setMinimumHeight(160)
    return view


class MonitorWindow(QMainWindow):
    def __init__(self, monitor, *, pid=None, interface='auto', cipher='auto', source=None, autostart=True, self_test=False):
        super().__init__()
        self.monitor = monitor
        self.client_icons = ClientIcons()
        self.queue = monitor.packet_queue
        self.queue_runner = monitor.packet_queue_runner
        self.pool = QThreadPool.globalInstance()
        self.tasks = set()
        self.self_test = self_test
        self.settings = QSettings('AsteriosTools', 'L2PacketMonitor')
        self.language = 'ru'
        self.qt_translator = QTranslator(self)
        self.qt_translation_loaded = False
        self.qt_translation_path = None
        self._last_status_source = 'Готово'
        self.cursor = 0
        self.original = None
        self._busy_capture = False
        self._closing = False
        self._close_ready = False
        self._discovering = False
        self._library_busy = False
        self._library_again = False
        self._last_library_key = None
        self._type_signature = None
        self._unchecked_types = set()
        self._queue_signature = None
        self._last_world = None
        self._last_inventory = None
        self._source_busy = False
        self._source_signature = None
        self._initial_source = source
        self.theme = 'dark'
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowMinMaxButtonsHint)
        self.setWindowTitle('L2 Packet Monitor · Native')
        self.setMinimumSize(1400, 900)
        self.resize(1600, 980)
        self._build()
        self.apply_theme('dark' if self_test else self.settings.value('theme', 'dark'), persist=False)
        self._restore(pid, interface, cipher)
        self.apply_language('ru' if self_test else self.settings.value('language', 'ru'), persist=False)
        QApplication.instance().installEventFilter(self)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(250)
        if not self_test:
            QTimer.singleShot(100, self.refresh_discovery)
        if autostart and not self_test:
            QTimer.singleShot(400, self.start_capture)
        self.poll()

    def task(self, function, result=None, error=None, finished=None):
        job = Task(function)
        self.tasks.add(job)
        if result:
            job.signals.result.connect(lambda value: result(value) if not self._closing else None)
        job.signals.error.connect(lambda message: (error or self.report_error)(message) if not self._closing else None)

        def completed():
            self.tasks.discard(job)
            if finished and not self._closing:
                finished()
            if self._closing and not self.tasks:
                self._close_ready = True
                self.close()
        job.signals.finished.connect(completed)
        self.pool.start(job)

    def _build(self):
        root = QWidget()
        root.setMouseTracking(True)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(12, 10, 12, 7)
        layout.setSpacing(12)
        self.title_bar = TitleBar(self)
        heading = QHBoxLayout(self.title_bar)
        heading.setContentsMargins(13, 10, 9, 10)
        heading.setSpacing(13)
        app_mark = label('L2', 'appMark')
        app_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        app_mark.setFixedSize(46, 46)
        app_mark.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        heading.addWidget(app_mark)
        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        for text, name in [('L2 Packet Monitor', 'title'), ('Пакеты, объекты и словарь игрового протокола', 'subtle')]:
            text_label = label(text, name)
            text_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            title_box.addWidget(text_label)
        heading.addLayout(title_box)
        heading.addStretch()
        self.mode_badge = label('НАТИВНЫЙ МОНИТОР', 'badge')
        self.mode_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        heading.addWidget(self.mode_badge)
        self.theme_combo = QComboBox()
        self.theme_combo.setAccessibleName('Тема оформления')
        self.theme_combo.setToolTip('Тема оформления')
        self.theme_combo.addItem('☾  Тёмная', 'dark')
        self.theme_combo.addItem('☀  Светлая', 'light')
        self.theme_combo.currentIndexChanged.connect(lambda: self.apply_theme(self.theme_combo.currentData()))
        heading.addWidget(self.theme_combo)
        self.language_combo = QComboBox()
        self.language_combo.setAccessibleName('Язык интерфейса')
        self.language_combo.setToolTip('Язык интерфейса')
        self.language_combo.addItem('Русский', 'ru')
        self.language_combo.addItem('English', 'en')
        self.language_combo.currentIndexChanged.connect(lambda: self.apply_language(self.language_combo.currentData()))
        heading.addWidget(self.language_combo)
        self.file_button = QPushButton('Файл')
        heading.addWidget(self.file_button)
        self.minimize_button = button('−', self.showMinimized)
        self.maximize_button = button('□', self.toggle_maximized)
        self.close_button = button('×', self.close)
        for control, description in [(self.minimize_button, 'Свернуть'), (self.maximize_button, 'Развернуть'), (self.close_button, 'Закрыть')]:
            control.setObjectName('closeButton' if control is self.close_button else 'windowButton')
            control.setFixedSize(38, 38)
            control.setAccessibleName(description)
            control.setToolTip(description)
            heading.addWidget(control)
        layout.addWidget(self.title_bar)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.pid_combo = QComboBox()
        self.pid_combo.setMinimumWidth(190)
        self.pid_combo.addItem('PID: автоматически', None)
        self.pid_combo.setEditable(True)
        self.pid_combo.lineEdit().setPlaceholderText('PID процесса')
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.interface_combo.addItem('Интерфейс: автоматически', 'auto')
        self.cipher_combo = QComboBox()
        for value in ('auto', 'asterios', 'l2xor16', 'l2xor16-u64', 'plain'):
            self.cipher_combo.addItem('Шифр: ' + value, value)
        self.refresh_button = button('Обновить', self.refresh_discovery)
        self.start_button = button('▶  Начать захват', self.start_capture, primary=True)
        self.stop_button = button('■  Стоп', self.stop_capture, danger=True)
        for widget in (self.pid_combo, self.interface_combo, self.cipher_combo, self.refresh_button):
            controls.addWidget(widget)
        controls.addStretch()
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        layout.addLayout(controls)

        metrics = QHBoxLayout()
        self.metric_values = {}
        for key, title in [('packets', 'ПАКЕТОВ'), ('frames', 'КАДРОВ ЗАХВАЧЕНО'), ('windows', 'ПРОВЕРЕНО ОКОН'), ('sync', 'СИНХРОНИЗАЦИЯ'), ('cipher', 'ШИФР / ЗАХВАТ')]:
            frame = QFrame()
            frame.setObjectName('metric')
            card = QVBoxLayout(frame)
            card.setContentsMargins(13, 9, 13, 9)
            card.addWidget(label(title, 'section'))
            value = label('—', 'metricValue')
            self.metric_values[key] = value
            card.addWidget(value)
            metrics.addWidget(frame)
        layout.addLayout(metrics)
        self.state_label = label('Захват остановлен')
        self.state_label.setWordWrap(True)
        layout.addWidget(self.state_label)
        layout.addWidget(self._character_panel(), 0, Qt.AlignmentFlag.AlignLeft)
        self.character_stats = label('')
        self.character_stats.setWordWrap(True)
        self.character_stats.setVisible(False)
        layout.addWidget(self.character_stats)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._packets_page(), 'Пакеты')
        self.tabs.addTab(self._world_page(), 'Предметы рядом')
        self.tabs.addTab(self._library_page(), 'Справочник ID')
        self.tabs.addTab(self._inventory_page(), 'Инвентарь')
        self.tabs.addTab(self._queue_page(), 'Очередь пакетов')
        self.tabs.addTab(self._additional_options_page(), 'Дополнительные опции')
        self.tabs.addTab(self._skills_page(), 'Скиллы')
        self.tabs.addTab(self._client_catalog_page(), 'База клиента')
        self.tabs.addTab(self._sources_page(), 'Источники')
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(root)
        self.statusBar().showMessage('Готово')
        self.shown_label = QLabel('0 пакетов в таблице')
        self.statusBar().addPermanentWidget(self.shown_label)
        self.creator_label = label('Made by Vektor T13', 'creator')
        self.creator_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.creator_label.setAccessibleName('Made by Vektor T13')
        self.statusBar().addPermanentWidget(self.creator_label)
        self.statusBar().setSizeGripEnabled(False)
        menu = QMenu(self.file_button)
        self.file_button.setMenu(menu)
        export_action = QAction('Экспорт захваченных пакетов в JSON…', self)
        export_action.triggered.connect(self.export_packets)
        menu.addAction(export_action)
        menu.addSeparator()
        close_action = QAction('Выход', self)
        close_action.triggered.connect(self.close)
        menu.addAction(close_action)

    def t(self, text):
        return translate(text, self.language)

    def set_text(self, widget, text):
        widget.setProperty('_l2DynamicText', str(text))
        widget.setText(self.t(text))

    def show_status(self, text, timeout=0):
        self._last_status_source = str(text)
        self.statusBar().showMessage(self.t(text), timeout)

    def _translate_combo(self, combo):
        role = Qt.ItemDataRole.UserRole + 20
        previous_text = combo.currentText()
        selected_text = combo.itemText(combo.currentIndex())
        combo.blockSignals(True)
        for index in range(combo.count()):
            source = combo.itemData(index, role)
            if source is None:
                source = combo.itemText(index)
                combo.setItemData(index, source, role)
            combo.setItemText(index, self.t(source))
        if combo.isEditable() and previous_text != selected_text:
            combo.setEditText(previous_text)
        combo.blockSignals(False)

    def apply_language(self, language, *, persist=True):
        self.language = language if language in ('ru', 'en') else 'ru'
        app = QApplication.instance()
        app.removeTranslator(self.qt_translator)
        self.qt_translation_loaded = False
        if self.language == 'ru':
            paths = [Path(QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath))]
            if getattr(sys, '_MEIPASS', None):
                paths.append(Path(sys._MEIPASS) / 'PySide6' / 'translations')
            for path in paths:
                if self.qt_translator.load('qtbase_ru', str(path)):
                    self.qt_translation_loaded = True
                    self.qt_translation_path = str(path)
                    app.installTranslator(self.qt_translator)
                    break
        for widget in self.findChildren(QWidget):
            if isinstance(widget, (QLabel, QPushButton, QCheckBox)):
                source = widget.property('_l2DynamicText')
                if source is None:
                    source = widget.property('_l2SourceText')
                if source is None:
                    source = widget.text()
                    widget.setProperty('_l2SourceText', source)
                widget.setText(self.t(source))
            if isinstance(widget, (QLineEdit, QPlainTextEdit)):
                source = widget.property('_l2Placeholder')
                if source is None:
                    source = widget.placeholderText()
                    widget.setProperty('_l2Placeholder', source)
                widget.setPlaceholderText(self.t(source))
            for property_name, getter, setter in [('_l2Tooltip', widget.toolTip, widget.setToolTip), ('_l2Accessible', widget.accessibleName, widget.setAccessibleName)]:
                source = widget.property(property_name)
                if source is None:
                    source = getter()
                    widget.setProperty(property_name, source)
                if source:
                    setter(self.t(source))
        for combo in (self.theme_combo, self.pid_combo, self.interface_combo, self.cipher_combo, self.direction_combo, self.library_kind, self.library_server, self.source_combo):
            self._translate_combo(combo)
        self.language_combo.blockSignals(True)
        self.language_combo.setCurrentIndex(self.language_combo.findData(self.language))
        self.language_combo.blockSignals(False)
        for index, source in enumerate(('Пакеты', 'Предметы рядом', 'Справочник ID', 'Инвентарь', 'Очередь пакетов', 'Дополнительные опции', 'Скиллы', 'База клиента', 'Источники')):
            self.tabs.setTabText(index, self.t(source))
        self.editor_tabs.setTabText(1, self.t('Текст'))
        self.fields.setHeaderLabels([self.t('Поле'), self.t('Значение')])
        self.filter_tree.blockSignals(True)
        for key, item in self.category_items.items():
            item.setText(0, self.t(CATEGORIES[key][0]))
        self.type_root.setText(0, self.t('Типы пакетов'))
        self.filter_tree.blockSignals(False)
        def translate_field(item):
            source = item.data(1, Qt.ItemDataRole.UserRole + 20)
            if source is not None:
                item.setText(1, self.t(source))
            for index in range(item.childCount()):
                translate_field(item.child(index))
        for index in range(self.fields.topLevelItemCount()):
            translate_field(self.fields.topLevelItem(index))
        for action in self.findChildren(QAction):
            source = action.property('_l2SourceText')
            if source is None:
                source = action.text()
                action.setProperty('_l2SourceText', source)
            action.setText(self.t(source))
        self._translate_combo(self.catalog_kind)
        for model in (self.packet_model, self.world_model, self.events_model, self.library_model, self.inventory_model, self.drop_model, self.queue_model, self.skills_model, self.skill_history_model, self.buffs_model, self.catalog_model, self.source_profiles_model):
            model.language = self.language
            model.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, model.columnCount() - 1)
            if model.rowCount():
                model.dataChanged.emit(model.index(0, 0), model.index(model.rowCount() - 1, model.columnCount() - 1))
        self._last_world = None
        self._last_inventory = None
        self.maximize_button.setText('❐' if self.isMaximized() else '□')
        description = 'Восстановить' if self.isMaximized() else 'Развернуть'
        self.maximize_button.setToolTip(self.t(description))
        self.maximize_button.setAccessibleName(self.t(description))
        self.show_status(self._last_status_source)
        if persist and not self.self_test:
            self.settings.setValue('language', self.language)
            self.settings.sync()
        if hasattr(self, 'timer'):
            self.poll()

    def apply_theme(self, theme, *, persist=True):
        self.theme = theme if theme in ('dark', 'light') else 'dark'
        light = self.theme == 'light'
        self.setStyleSheet(LIGHT_STYLE if light else STYLE)
        for resource, row in self.recovery_widgets.items():
            color = {'cp': '#e6bd45', 'hp': '#e8757b', 'mp': '#78aaf0'}[resource] if light else {'cp': '#a88421', 'hp': '#a43c48', 'mp': '#245c9d'}[resource]
            row['bar'].setStyleSheet(
                'QProgressBar { border: 1px solid ' + ('#b8c9dc' if light else '#34465d') + '; border-radius: 4px; '
                'background: ' + ('#edf3f9' if light else '#101722') + '; color: ' + ('#142237' if light else '#f0f7ff') +
                '; text-align: center; min-height: 28px; } QProgressBar::chunk { background: ' + color + '; border-radius: 3px; }')
            row['toggle'].setStyleSheet('QPushButton:checked { background: #237555; color: white; border: 1px solid #4aaa86; }')
        self.theme_combo.blockSignals(True)
        self.theme_combo.setCurrentIndex(self.theme_combo.findData(self.theme))
        self.theme_combo.blockSignals(False)
        for model in (self.packet_model, self.queue_model):
            model.light_theme = light
            if model.rowCount():
                model.dataChanged.emit(model.index(0, 0), model.index(model.rowCount() - 1, model.columnCount() - 1))
        for key, item in self.category_items.items():
            item.setForeground(0, packet_color(CATEGORIES[key][1], light))
        for item in self.type_items.values():
            item.setForeground(0, packet_color(item.data(0, Qt.ItemDataRole.UserRole + 1) or '#6e7681', light))
        if persist and not self.self_test:
            self.settings.setValue('theme', self.theme)
            self.settings.sync()
        if hasattr(self, 'timer'):
            self.poll()

    def toggle_maximized(self):
        self.showNormal() if self.isMaximized() else self.showMaximized()

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange and hasattr(self, 'maximize_button'):
            self.maximize_button.setText('❐' if self.isMaximized() else '□')
            description = 'Восстановить' if self.isMaximized() else 'Развернуть'
            self.maximize_button.setProperty('_l2Tooltip', description)
            self.maximize_button.setProperty('_l2Accessible', description)
            self.maximize_button.setToolTip(self.t(description))
            self.maximize_button.setAccessibleName(self.t(description))
        super().changeEvent(event)

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress) and isinstance(watched, QWidget) and watched.window() is self and not self.isMaximized():
            point = self.mapFromGlobal(event.globalPosition().toPoint())
            edges = Qt.Edge(0)
            if point.x() < 6:
                edges |= Qt.Edge.LeftEdge
            elif point.x() >= self.width() - 6:
                edges |= Qt.Edge.RightEdge
            if point.y() < 6:
                edges |= Qt.Edge.TopEdge
            elif point.y() >= self.height() - 6:
                edges |= Qt.Edge.BottomEdge
            if event.type() == QEvent.Type.MouseButtonPress and edges and event.button() == Qt.MouseButton.LeftButton and self.windowHandle():
                return self.windowHandle().startSystemResize(edges)
            if event.type() == QEvent.Type.MouseMove:
                diagonal = edges in (Qt.Edge.LeftEdge | Qt.Edge.TopEdge, Qt.Edge.RightEdge | Qt.Edge.BottomEdge)
                reverse = edges in (Qt.Edge.RightEdge | Qt.Edge.TopEdge, Qt.Edge.LeftEdge | Qt.Edge.BottomEdge)
                cursor = Qt.CursorShape.SizeFDiagCursor if diagonal else Qt.CursorShape.SizeBDiagCursor if reverse else Qt.CursorShape.SizeHorCursor if edges & (Qt.Edge.LeftEdge | Qt.Edge.RightEdge) else Qt.CursorShape.SizeVerCursor if edges else Qt.CursorShape.ArrowCursor
                self.setCursor(cursor)
        return super().eventFilter(watched, event)

    def _packets_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('Поиск по opcode, имени пакета и полям…')
        self.search.textChanged.connect(self.apply_filters)
        self.direction_combo = QComboBox()
        for text, value in [('Оба направления', None), ('Сервер → клиент', 'server'), ('Клиент → сервер', 'client')]:
            self.direction_combo.addItem(text, value)
        self.direction_combo.currentIndexChanged.connect(self.apply_filters)
        self.follow = QCheckBox('Следить за потоком')
        self.follow.setChecked(True)
        tools.addWidget(self.search, 1)
        tools.addWidget(self.direction_combo)
        tools.addWidget(self.follow)
        tools.addWidget(button('Сброс фильтров', self.reset_filters))
        layout.addLayout(tools)
        self.packet_splitter = QSplitter(Qt.Orientation.Horizontal)
        filters = QWidget()
        filter_layout = QVBoxLayout(filters)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.addWidget(label('КАТЕГОРИИ И ТИПЫ', 'section'))
        check_buttons = QHBoxLayout()
        check_buttons.addWidget(button('Все', lambda: self.set_checks(True)))
        check_buttons.addWidget(button('Ничего', lambda: self.set_checks(False)))
        filter_layout.addLayout(check_buttons)
        self.filter_tree = QTreeWidget()
        self.filter_tree.setHeaderHidden(True)
        self.filter_tree.setMinimumWidth(210)
        self.category_items = {}
        for key, (title, color) in CATEGORIES.items():
            item = QTreeWidgetItem([title])
            item.setData(0, Qt.ItemDataRole.UserRole, ('category', key))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked)
            item.setForeground(0, QColor(color))
            self.filter_tree.addTopLevelItem(item)
            self.category_items[key] = item
        self.type_root = QTreeWidgetItem(['Типы пакетов'])
        self.type_root.setFlags(self.type_root.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        self.filter_tree.addTopLevelItem(self.type_root)
        self.type_root.setExpanded(True)
        self.type_items = {}
        self.filter_tree.itemChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.filter_tree, 1)
        self.packet_splitter.addWidget(filters)

        self.packet_model = RowsModel(PACKET_COLUMNS, self, packet_colors=True)
        self.proxy = PacketFilter(self)
        self.proxy.setSourceModel(self.packet_model)
        self.packet_table = table(self.proxy)
        for index, width in enumerate((58, 106, 72, 92, 190, 160, 60)):
            self.packet_table.setColumnWidth(index, width)
        self.packet_table.selectionModel().currentRowChanged.connect(self.select_packet)
        self.packet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.packet_context_menu)
        self.packet_splitter.addWidget(self.packet_table)
        self.packet_splitter.addWidget(self._editor_panel())
        self.packet_splitter.setStretchFactor(0, 0)
        self.packet_splitter.setStretchFactor(1, 4)
        self.packet_splitter.setStretchFactor(2, 2)
        self.packet_splitter.setSizes([225, 820, 440])
        layout.addWidget(self.packet_splitter, 1)
        return page

    def _editor_panel(self):
        panel = QWidget()
        panel.setMinimumWidth(340)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(9, 0, 0, 0)
        self.packet_heading = label('Выберите пакет', 'section')
        self.packet_heading.setWordWrap(True)
        layout.addWidget(self.packet_heading)
        self.detail_splitter = QSplitter(Qt.Orientation.Vertical)
        self.detail_splitter.setChildrenCollapsible(False)
        self.fields = QTreeWidget()
        self.fields.setMinimumHeight(120)
        self.fields.setHeaderLabels(['Поле', 'Значение'])
        self.fields.setColumnWidth(0, 140)
        self.detail_splitter.addWidget(self.fields)
        editor = QWidget()
        editor.setMinimumHeight(340)
        edit_layout = QVBoxLayout(editor)
        edit_layout.setContentsMargins(0, 7, 0, 0)
        edit_layout.addWidget(label('РЕДАКТОР КОПИИ ПАКЕТА', 'section'))
        editor_tools = QHBoxLayout()
        self.encoding_combo = QComboBox()
        for encoding in ('utf-8', 'utf-16le', 'cp1251', 'latin-1'):
            self.encoding_combo.addItem(encoding)
        self.encoding_combo.currentTextChanged.connect(self.hex_to_text)
        editor_tools.addWidget(self.encoding_combo)
        editor_tools.addWidget(button('Исправить u16', self.fix_length))
        editor_tools.addWidget(button('Сброс', self.reset_copy))
        edit_layout.addLayout(editor_tools)
        self.editor_tabs = QTabWidget()
        self.hex_edit = QPlainTextEdit()
        self.text_edit = QPlainTextEdit()
        font = QFont('Consolas', 10)
        self.hex_edit.setFont(font)
        self.text_edit.setFont(font)
        self.hex_edit.setPlaceholderText('HEX-копия выбранного пакета')
        self.text_edit.setPlaceholderText('Текст с escape-последовательностями \\xNN')
        self.editor_tabs.addTab(self.hex_edit, 'HEX')
        self.editor_tabs.addTab(self.text_edit, 'Текст')
        edit_layout.addWidget(self.editor_tabs, 1)
        conversions = QHBoxLayout()
        conversions.addWidget(button('HEX → Текст', self.hex_to_text))
        conversions.addWidget(button('Текст → HEX', self.text_to_hex))
        edit_layout.addLayout(conversions)
        self.copy_info = label('0 байт')
        self.copy_info.setMinimumHeight(22)
        edit_layout.addWidget(self.copy_info)
        saves = QHBoxLayout()
        saves.addWidget(button('Сохранить BIN…', lambda: self.save_copy('bin')))
        saves.addWidget(button('Сохранить JSON…', lambda: self.save_copy('json')))
        edit_layout.addLayout(saves)
        edit_layout.addWidget(button('Добавить копию в очередь', self.queue_editor_copy))
        self.detail_splitter.addWidget(editor)
        self.detail_splitter.setSizes([265, 410])
        layout.addWidget(self.detail_splitter, 1)
        return panel

    def _world_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.world_info = label('Предметы из наблюдаемых пакетов')
        layout.addWidget(self.world_info)
        split = QSplitter(Qt.Orientation.Vertical)
        self.world_model = RowsModel([('Object ID', 'object_id'), ('Item ID', 'template_value'), ('Количество', 'amount'),
                                     ('Расстояние XY', 'distance_xy'), ('Координаты', 'xyz'), ('Состояние', 'state'), ('Время', 'last_time')], self, icon_kind='world', icon_column='template_value')
        self.world_table = table(self.world_model)
        split.addWidget(self.world_table)
        self.events_model = RowsModel([('Событие', 'label'), ('Object ID', 'object_id'), ('Item ID', 'template_value'),
                                      ('Количество', 'amount'), ('Владелец', 'owner_id'), ('Время', 'time')], self)
        split.addWidget(table(self.events_model))
        split.setSizes([450, 220])
        layout.addWidget(split, 1)
        return page

    def _library_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        tools = QHBoxLayout()
        self.library_kind = QComboBox()
        for title, value in [('Предметы и умения', None), ('Предметы', 'item'), ('Умения', 'skill')]:
            self.library_kind.addItem(title, value)
        self.library_server = QComboBox()
        self.library_server.setMinimumWidth(220)
        self.library_server.setEditable(True)
        self.library_server.addItem('Все серверы', None)
        self.library_search = QLineEdit()
        self.library_search.setPlaceholderText('Поиск ID или названия…')
        self.library_debounce = QTimer(self)
        self.library_debounce.setSingleShot(True)
        self.library_debounce.setInterval(250)
        self.library_debounce.timeout.connect(self.refresh_library)
        self.library_search.textChanged.connect(lambda: self.library_debounce.start())
        self.library_kind.currentIndexChanged.connect(self.refresh_library)
        self.library_server.currentTextChanged.connect(lambda: self.library_debounce.start())
        tools.addWidget(self.library_kind)
        tools.addWidget(self.library_server)
        tools.addWidget(self.library_search, 1)
        tools.addWidget(button('Обновить', self.refresh_library))
        tools.addWidget(button('CSV…', lambda: self.export_library('csv')))
        tools.addWidget(button('JSON…', lambda: self.export_library('json')))
        layout.addLayout(tools)
        self.library_info = label('Наблюдаемые ID, уровни и серверные профили')
        layout.addWidget(self.library_info)
        self.library_model = RowsModel([('Тип', 'kind'), ('ID', 'entity_id'), ('Уровень', 'level'), ('Название', 'name'),
                                       ('Сервер', 'server'), ('Профиль', 'profile'), ('Наблюдений', 'observations'), ('Последний раз', 'last_seen')], self, icon_kind='library', icon_column='name')
        self.library_table = table(self.library_model)
        for i, width in enumerate((90, 85, 80, 210, 200, 280, 110, 230)):
            self.library_table.setColumnWidth(i, width)
        layout.addWidget(self.library_table, 1)
        return page

    def _inventory_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        intro = QHBoxLayout()
        self.inventory_info = label('Инвентарь восстанавливается из наблюдаемых серверных пакетов')
        self.inventory_info.setWordWrap(True)
        intro.addWidget(self.inventory_info, 1)
        self.inventory_copy_id = button('Копировать ID', self.copy_inventory_id)
        self.inventory_manual_drop = button('Выбросить…', self.show_inventory_drop, primary=True)
        intro.addWidget(self.inventory_copy_id)
        intro.addWidget(self.inventory_manual_drop)
        layout.addLayout(intro)
        self.inventory_search = QLineEdit()
        self.inventory_search.setPlaceholderText('Поиск по названию или ID')
        self.inventory_search.textChanged.connect(lambda: setattr(self, '_last_inventory', None))
        layout.addWidget(self.inventory_search)
        self.inventory_auto_open = QCheckBox('Автоматически открывать инвентарь')
        self.inventory_auto_open.setChecked(True if self.self_test else self.settings.value('inventory/autoOpen', True, type=bool))
        self.monitor.auto_inventory_enabled = self.inventory_auto_open.isChecked()
        self.inventory_auto_open.toggled.connect(self.set_auto_inventory)
        layout.addWidget(self.inventory_auto_open)
        self.inventory_open_status = label('Автооткрытие: ожидание синхронизации', 'subtle')
        layout.addWidget(self.inventory_open_status)
        self.inventory_model = RowsModel([
            ('ID предмета', 'item_id'), ('Название', 'item_name'), ('Объект ID', 'object_id'), ('Слот', 'slot'),
            ('Количество', 'amount'), ('Изменение', 'action_name'), ('Последний раз', 'last_time')
        ], self, icon_kind='item', icon_column='item_name')
        self.inventory_table = table(self.inventory_model)
        self.inventory_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.inventory_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.inventory_table.customContextMenuRequested.connect(self.inventory_context_menu)
        for index, width in enumerate((120, 280, 125, 80, 110, 130, 250)):
            self.inventory_table.setColumnWidth(index, width)
        self.inventory_table.selectionModel().currentChanged.connect(lambda *_: self.update_inventory_actions())
        layout.addWidget(self.inventory_table, 1)
        note = label('Место выброса: рядом с персонажем. Координаты берутся из клиента перед каждым действием.', 'subtle')
        note.setWordWrap(True)
        layout.addWidget(note)
        controls = QHBoxLayout()
        controls.addWidget(label('Очередь выброса', 'badge'))
        controls.addStretch()
        self.drop_pause = button('Пауза выброса', self.toggle_drop_pause)
        self.drop_stop = button('Остановить выброс', self.monitor.inventory_drop.stop, danger=True)
        controls.addWidget(self.drop_pause)
        controls.addWidget(self.drop_stop)
        layout.addLayout(controls)
        self.drop_model = RowsModel([
            ('№', 'id'), ('ID предмета', 'item_id'), ('Количество', 'amount'),
            ('Выброшено', 'dropped'), ('Режим', 'mode_label'), ('Состояние', 'state_label'),
            ('Место выброса', 'destination'), ('Ошибка', 'error'),
        ], self)
        self.drop_table = table(self.drop_model)
        self.drop_table.setMaximumHeight(230)
        self.drop_table.setMinimumHeight(130)
        for index, width in enumerate((54, 105, 105, 105, 240, 220, 230)):
            self.drop_table.setColumnWidth(index, width)
        layout.addWidget(self.drop_table)
        self._drop_signature = None
        self.update_inventory_actions()
        return page

    def _sources_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        controls.addWidget(label('Источник пакетов'))
        self.source_combo = QComboBox()
        for title, mode in [('Авто: проверенный источник', 'auto'), ('Сетевой захват', 'network'),
                            ('Открытые пакеты клиента', 'client'), ('Серверный мост', 'server')]:
            self.source_combo.addItem(title, mode)
        saved = self._initial_source or ('auto' if self.self_test else self.settings.value('capture/source', 'auto'))
        self.source_combo.setCurrentIndex(max(0, self.source_combo.findData(saved)))
        self._configured_source = self.source_combo.currentData()
        self.source_combo.currentIndexChanged.connect(self.change_source)
        controls.addWidget(self.source_combo, 1)
        layout.addLayout(controls)
        self.source_description = label('')
        self.source_description.setWordWrap(True)
        layout.addWidget(self.source_description)
        self.source_active = label('Источник ещё не выбран')
        self.source_active.setWordWrap(True)
        layout.addWidget(self.source_active)
        self.source_message = label('')
        self.source_message.setWordWrap(True)
        layout.addWidget(self.source_message)
        self.source_algorithms = label('')
        self.source_algorithms.setWordWrap(True)
        layout.addWidget(self.source_algorithms)
        profile_actions = QHBoxLayout()
        profile_actions.addWidget(label('Сохранённые профили клиентов', 'section'))
        profile_actions.addStretch()
        self.profiles_import_button = button('Импорт профилей…', lambda: self.profile_package_action(True))
        self.profiles_export_button = button('Экспорт профилей…', lambda: self.profile_package_action(False))
        profile_actions.addWidget(self.profiles_import_button)
        profile_actions.addWidget(self.profiles_export_button)
        layout.addLayout(profile_actions)
        self.source_profiles_model = RowsModel([
            ('Профиль', 'id'), ('Engine SHA-256', 'engine_sha256'), ('Алгоритм', 'algorithm'),
            ('Проверка', 'validation'), ('Перехват клиента', 'client_tap'), ('Протокол:', 'protocol'),
        ], self)
        self.source_profiles_table = table(self.source_profiles_model)
        for index, width in enumerate((300, 520, 150, 120, 150, 150)):
            self.source_profiles_table.setColumnWidth(index, width)
        layout.addWidget(self.source_profiles_table, 1)
        layout.addWidget(label('Серверный мост', 'section'))
        self.bridge_status = label('Мост остановлен')
        self.bridge_status.setWordWrap(True)
        layout.addWidget(self.bridge_status)
        actions = QHBoxLayout()
        self.bridge_start_button = button('Запустить мост', lambda: self.bridge_action(True))
        self.bridge_stop_button = button('Остановить мост', lambda: self.bridge_action(False))
        self.bridge_copy_button = button('Копировать конфигурацию', self.copy_bridge_configuration)
        self.bridge_export_button = button('Экспорт модуля сервера…', self.export_bridge_package)
        for control in (self.bridge_start_button, self.bridge_stop_button, self.bridge_copy_button, self.bridge_export_button):
            actions.addWidget(control)
        actions.addStretch()
        layout.addLayout(actions)
        self.update_source_description()
        return page

    def update_source_description(self):
        descriptions = {
            'auto': 'Авто выбирает проверенный перехват клиента, затем сетевой профиль; для неизвестной сборки показывает TCP без расшифровки.',
            'network': 'Сетевой режим использует профиль сборки и текущие ключи соединения.',
            'client': 'Перехват открытых пакетов требует проверенного адаптера для этой сборки клиента.',
            'server': 'Серверный модуль передаёт открытые пакеты в локальный мост; протокол задаётся модулем.',
        }
        self.set_text(self.source_description, descriptions.get(self.source_combo.currentData(), descriptions['auto']))

    def change_source(self, *_):
        mode = self.source_combo.currentData()
        if self.monitor.status().get('running') or self._busy_capture:
            self.source_combo.blockSignals(True)
            self.source_combo.setCurrentIndex(self.source_combo.findData(self._configured_source))
            self.source_combo.blockSignals(False)
            self.report_error('Остановите захват перед сменой источника')
            return
        try:
            if not self.self_test and hasattr(self.monitor, 'configure_source'):
                self.monitor.configure_source(mode)
        except (ValueError, RuntimeError) as error:
            self.source_combo.blockSignals(True)
            self.source_combo.setCurrentIndex(self.source_combo.findData(self._configured_source))
            self.source_combo.blockSignals(False)
            self.report_error(str(error))
            return
        self._configured_source = mode
        if not self.self_test:
            self.settings.setValue('capture/source', mode)
        self.update_source_description()
        self.poll_sources()

    def poll_sources(self, snapshot=None):
        if snapshot is None:
            snapshot = self.monitor.source_status() if hasattr(self.monitor, 'source_status') else {}
        self.update_source_description()
        active = snapshot.get('active_source') or '—'
        protocol = snapshot.get('protocol') or snapshot.get('active_protocol') or '—'
        bridge = snapshot.get('bridge') or {}
        session = bridge.get('active_session') or {}
        if isinstance(session, dict):
            protocol = session.get('protocol') or protocol
        titles = {'auto': 'Авто: проверенный источник', 'network': 'Сетевой захват',
                  'client': 'Открытые пакеты клиента', 'server': 'Серверный мост'}
        self.set_text(self.source_active, f"Текущий источник: {titles.get(active, active)} · Протокол: {protocol}")
        message = snapshot.get('message') or ''
        if self.source_combo.currentData() == 'client' and not snapshot.get('client_tap_supported') and not message:
            message = 'Для этой сборки нет проверенного адаптера открытых пакетов клиента'
        self.set_text(self.source_message, message)
        algorithms = snapshot.get('algorithms') or []
        self.set_text(self.source_algorithms, 'Алгоритмы: ' + ', '.join(
            str(item.get('id', '')) if isinstance(item, dict) else str(item) for item in algorithms))
        profiles = snapshot.get('profiles') or []
        signature = (self.language, json.dumps(profiles, sort_keys=True, default=str))
        if signature != self._source_signature:
            self._source_signature = signature
            self.source_profiles_model.replace([dict(row, client_tap=self.t(
                'Поддерживается' if row.get('client_tap_supported') else 'Не подключён')) for row in profiles])
        running = bridge.get('running', False)
        endpoint = bridge.get('endpoint') or '—'
        sessions = bridge.get('sessions') or []
        session_count = sessions if isinstance(sessions,int) else len(sessions)
        self.set_text(self.bridge_status,
                      f"{'Мост запущен' if running else 'Мост остановлен'} · {endpoint} · "
                      f"Принято: {bridge.get('received', 0)} · Пропущено: {bridge.get('dropped', 0)} · Сеансов: {session_count}")
        self.bridge_start_button.setEnabled(not running and not self._source_busy and not self.self_test)
        self.bridge_stop_button.setEnabled(running and not self._source_busy and not self.self_test)
        self.bridge_copy_button.setEnabled(hasattr(self.monitor, 'bridge_configuration') and not self.self_test)
        self.bridge_export_button.setEnabled(hasattr(self.monitor, 'export_bridge_package') and not self.self_test)
        self.profiles_import_button.setEnabled(hasattr(self.monitor, 'import_profiles') and not self.self_test
                                              and not self.monitor.status().get('running') and not self._source_busy)
        self.profiles_import_button.setToolTip(self.t('Остановите захват перед сменой источника')
                                              if self.monitor.status().get('running') else '')
        self.profiles_export_button.setEnabled(hasattr(self.monitor, 'export_profiles') and not self.self_test)

    def profile_package_action(self, importing):
        if self.self_test or self._source_busy:
            return
        if importing and self.monitor.status().get('running'):
            self.report_error('Остановите захват перед сменой источника')
            return
        title = self.t('Импорт профилей…' if importing else 'Экспорт профилей…')
        chooser = QFileDialog.getOpenFileName if importing else QFileDialog.getSaveFileName
        path, _ = chooser(self, title, '' if importing else 'l2-client-profiles.zip', 'ZIP (*.zip)')
        if path:
            self._source_busy = True
            self.poll_sources()
            def finished():
                self._source_busy = False
                self._source_signature = None
                self.poll_sources()
            operation = self.monitor.import_profiles if importing else self.monitor.export_profiles
            self.task(lambda: operation(path),
                      lambda _: self.show_status('Профили импортированы' if importing else 'Профили экспортированы', 10000),
                      finished=finished)

    def bridge_action(self, start):
        if self.self_test or self._source_busy:
            return
        self._source_busy = True
        self.poll_sources()
        def finished():
            self._source_busy = False
            self.poll_sources()
        self.task(self.monitor.bridge_start if start else self.monitor.bridge_stop, finished=finished)

    def copy_bridge_configuration(self):
        if self.self_test:
            return
        config = self.monitor.bridge_configuration()
        QApplication.clipboard().setText(json.dumps(config, ensure_ascii=False, indent=2))
        self.show_status('Конфигурация моста скопирована', 10000)

    def export_bridge_package(self):
        if self.self_test:
            return
        path, _ = QFileDialog.getSaveFileName(self, self.t('Экспорт модуля сервера…'), 'l2-server-bridge.zip', 'ZIP (*.zip)')
        if path:
            self.task(lambda: self.monitor.export_bridge_package(path),
                      lambda _: self.show_status('Модуль сервера экспортирован', 10000))

    def _client_catalog_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.catalog_kind = QComboBox()
        self.catalog_kind.addItem('Предметы', 'items')
        self.catalog_kind.addItem('Скиллы и бафы', 'skills')
        controls.addWidget(self.catalog_kind)
        self.catalog_search = QLineEdit()
        self.catalog_search.setPlaceholderText(self.t('Поиск по названию или ID'))
        controls.addWidget(self.catalog_search, 1)
        controls.addWidget(button('Экспорт всей базы…', self.export_client_catalog))
        layout.addLayout(controls)
        self.catalog_info = label('')
        layout.addWidget(self.catalog_info)
        self.catalog_model = RowsModel([('ID', 'id'), ('Название', 'name'), ('Уровень', 'level'), ('Описание', 'description')], self, icon_kind='catalog', icon_column='name')
        self.catalog_table = table(self.catalog_model)
        for index, width in enumerate((100, 320, 100, 850)):
            self.catalog_table.setColumnWidth(index, width)
        self.catalog_table.setWordWrap(False)
        self.catalog_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.catalog_table.customContextMenuRequested.connect(self.catalog_context_menu)
        layout.addWidget(self.catalog_table, 1)
        navigation = QHBoxLayout()
        self.catalog_previous = button('Назад', lambda: self.catalog_page(-1))
        self.catalog_next = button('Далее', lambda: self.catalog_page(1))
        navigation.addWidget(self.catalog_previous)
        navigation.addWidget(self.catalog_next)
        navigation.addStretch()
        layout.addLayout(navigation)
        self._catalog_offset, self._catalog_signature = 0, None
        self.catalog_kind.currentIndexChanged.connect(self.reset_catalog_page)
        self.catalog_search.textChanged.connect(self.reset_catalog_page)
        self.poll_client_catalog()
        return page

    def catalog_context_menu(self, point):
        index = self.catalog_table.indexAt(point)
        if not index.isValid():
            return
        row = self.catalog_model.rows[index.row()]
        menu = QMenu(self)
        copy_id = menu.addAction(self.t('Копировать ID'))
        if menu.exec(self.catalog_table.viewport().mapToGlobal(point)) == copy_id:
            QApplication.clipboard().setText(str(row['id']))

    def reset_catalog_page(self, *_):
        self._catalog_offset = 0
        self.poll_client_catalog()

    def catalog_page(self, delta):
        self._catalog_offset = max(0, self._catalog_offset + delta * 1000)
        self.poll_client_catalog()

    def poll_client_catalog(self):
        catalog = self.monitor.auto_heal.catalog
        signature = (catalog.revision, self.catalog_kind.currentData(), self.catalog_search.text(), self._catalog_offset, self.language)
        if signature == self._catalog_signature:
            return
        self._catalog_signature = signature
        result = catalog.query(signature[1], signature[2], self._catalog_offset)
        self.catalog_model.replace(result['rows'])
        first = self._catalog_offset + 1 if result['rows'] else 0
        last = self._catalog_offset + len(result['rows'])
        self.catalog_info.setText(f"{self.t('Предметов:')} {result['items']} · {self.t('Скиллов и бафов по уровням:')} {result['skills']} · "
                                  f"{self.t('Записей:')} {first}–{last} / {result['total']}")
        self.catalog_previous.setEnabled(self._catalog_offset > 0)
        self.catalog_next.setEnabled(last < result['total'])

    def export_client_catalog(self):
        filename, _ = QFileDialog.getSaveFileName(self, self.t('Экспорт всей базы…'), 'client-catalog.json', 'JSON (*.json)')
        if filename:
            try:
                catalog = self.monitor.auto_heal.catalog
                with catalog.lock:
                    Path(filename).write_text(json.dumps(catalog.data, ensure_ascii=False, indent=2), 'utf-8')
            except OSError as error:
                self.report_error(str(error))

    def _skills_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.skills_info = label('Ожидание списка скиллов')
        controls.addWidget(self.skills_info, 1)
        controls.addWidget(button('Обновить список скиллов', self.refresh_skills))
        self.skill_learn_button = button('Повысить уровень скилла', self.show_skill_learn, primary=True)
        controls.addWidget(self.skill_learn_button)
        self.skill_custom_button = button('Ввести ID и уровень…', self.show_custom_skill)
        controls.addWidget(self.skill_custom_button)
        layout.addLayout(controls)
        self.skills_search = QLineEdit()
        self.skills_search.setPlaceholderText(self.t('Поиск по названию или ID'))
        self.skills_search.textChanged.connect(lambda: self.poll_skills())
        layout.addWidget(self.skills_search)
        self.skills_model = RowsModel([('ID скилла', 'skill_id'), ('Название', 'skill_name'), ('Текущий уровень', 'skill_level'),
                                      ('Тип скилла', 'type_label'), ('Недоступен', 'disabled'), ('Последний раз', 'last_time')], self, icon_kind='skill', icon_column='skill_name')
        self.skills_table = table(self.skills_model)
        self.skills_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.skills_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.skills_table.customContextMenuRequested.connect(self.skill_context_menu)
        for index, width in enumerate((110, 290, 150, 150, 100, 210)):
            self.skills_table.setColumnWidth(index, width)
        layout.addWidget(self.skills_table, 1)
        self.skill_status = label('Ожидание списка скиллов')
        layout.addWidget(self.skill_status)
        self.skill_error = label('')
        self.skill_error.setWordWrap(True)
        layout.addWidget(self.skill_error)
        self.skill_history_model = RowsModel([('ID скилла', 'skill_id'), ('Запрошенный уровень', 'level'),
                                             ('Полученный уровень', 'actual'), ('Состояние', 'state_label'), ('Ошибка', 'error')], self)
        self.skill_history_table = table(self.skill_history_model)
        self.skill_history_table.setMaximumHeight(180)
        for index, width in enumerate((130, 190, 190, 260, 440)):
            self.skill_history_table.setColumnWidth(index, width)
        layout.addWidget(self.skill_history_table)
        self._skills_signature = None
        return page

    def refresh_skills(self):
        try:
            self.monitor.refresh_skills()
        except ValueError as error:
            self.report_error(str(error))

    def selected_skill(self):
        index = self.skills_table.currentIndex()
        return self.skills_model.rows[index.row()] if index.isValid() and index.row() < len(self.skills_model.rows) else None

    def skill_context_menu(self, point):
        index = self.skills_table.indexAt(point)
        if not index.isValid():
            return
        self.skills_table.setCurrentIndex(index)
        menu = QMenu(self)
        action = menu.addAction(self.t('Повысить уровень скилла'))
        action.setEnabled(self.can_learn_skill())
        if menu.exec(self.skills_table.viewport().mapToGlobal(point)) == action:
            self.show_skill_learn()

    def can_learn_skill(self):
        state = self.monitor.status()
        skills = self.monitor.skills.snapshot()
        return bool(not self.self_test and state.get('running') and state.get('state') == 'live'
                    and state.get('skill_actions_supported', state.get('actions_supported') is not False)
                    and skills['full_list_received'] and not skills['coverage_gap']
                    and not self.monitor.skill_actions.snapshot()['active'])

    def skill_learn_dialog(self, skill=None, custom=False):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t('Скилл по ID' if custom else 'Повысить уровень скилла'))
        dialog.setMinimumWidth(390)
        layout = QVBoxLayout(dialog)
        skill = skill or dict(skill_id=1, skill_level=0)
        current = QLabel('')
        layout.addWidget(current)
        form = QFormLayout()
        skill_id = QSpinBox()
        skill_id.setObjectName('customSkillId')
        skill_id.setRange(1, 0x7fffffff)
        skill_id.setValue(skill['skill_id'])
        if custom:
            form.addRow(self.t('ID скилла'), skill_id)
        else:
            skill_id.setParent(dialog)
            skill_id.hide()
        level = QSpinBox()
        level.setObjectName('skillLevel')
        level.setRange(1 if custom else min(skill['skill_level'] + 1, 0x7fffffff), 0x7fffffff)
        level.setValue(skill['skill_level'] + 1)
        def show_current():
            owned = next((row['skill_level'] for row in self.monitor.skills.snapshot()['skills'] if row['skill_id'] == skill_id.value()), 0)
            current.setText(f"{self.t('ID скилла')}: {skill_id.value()} · {self.t('Текущий уровень')}: {owned}")
        skill_id.valueChanged.connect(show_current)
        show_current()
        form.addRow(self.t('Новый уровень'), level)
        layout.addLayout(form)
        error = QLabel('')
        error.setWordWrap(True)
        layout.addWidget(error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText('OK')
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(self.t('Отмена'))
        def submit():
            try:
                self.monitor.skill_actions.learn(skill_id.value(), level.value())
                dialog.accept()
            except (ValueError, RuntimeError) as problem:
                error.setText(self.t(str(problem)))
        buttons.accepted.connect(submit)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        return dialog

    def show_skill_learn(self):
        skill = self.selected_skill()
        if skill:
            self.skill_learn_dialog(skill).exec()

    def show_custom_skill(self):
        self.skill_learn_dialog(self.selected_skill(), custom=True).exec()

    def poll_skills(self):
        skills, actions = self.monitor.skills.snapshot(), self.monitor.skill_actions.snapshot()
        catalog = self.monitor.auto_heal.catalog
        query = self.skills_search.text().strip().casefold()
        signature = (skills, actions, self.language, catalog.revision, query)
        if signature != self._skills_signature:
            self._skills_signature = signature
            selected = self.selected_skill()
            rows = [dict(row, skill_name=catalog.skill_name(row['skill_id'], row['skill_level']),
                         type_label=self.t('Пассивный' if row.get('passive') else 'Активный')) for row in skills['skills']]
            self.skills_model.replace([row for row in rows if not query or query in row['skill_name'].casefold() or query in str(row['skill_id'])])
            if selected:
                for index, row in enumerate(self.skills_model.rows):
                    if row['skill_id'] == selected['skill_id']:
                        self.skills_table.selectRow(index)
                        break
            states = {'waiting': 'Ожидание списка скиллов', 'ready': 'Список скиллов обновлён',
                      'refreshing': 'Обновление списка скиллов', 'queued': 'Ожидание обучения',
                      'confirming': 'Ожидание подтверждения обучения', 'completed': 'Обучение завершено', 'failed': 'Обучение не подтверждено',
                      'unsupported': 'Обучение скиллов для этой сборки клиента пока не подключено'}
            self.set_text(self.skill_status, states.get(actions['state'], actions['state']))
            if actions['job']:
                job = actions['job']
                self.skill_status.setText(f"{self.t(states.get(actions['state'], actions['state']))} · {job['actual']} → {job['level']}")
            self.set_text(self.skill_error, actions['error'] or '')
            rows = [*actions['history'], *([actions['job']] if actions['job'] else [])]
            self.skill_history_model.replace([dict(row, state_label=self.t(states.get(row['state'], row['state']))) for row in rows])
        self.skills_info.setProperty('_l2DynamicText', '')
        self.skills_info.setText(f"{self.t('Изученных скиллов:')} {len(skills['skills'])}")
        self.skill_learn_button.setEnabled(bool(self.selected_skill()) and self.can_learn_skill())
        self.skill_custom_button.setEnabled(self.can_learn_skill())

    def _character_panel(self):
        panel = QWidget()
        panel.setObjectName('characterPanel')
        grid = QGridLayout(panel)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        self.character_label = label('Персонаж: ожидание данных', 'characterIdentity')
        self.character_label.setTextFormat(Qt.TextFormat.PlainText)
        self.character_label.setStyleSheet('font-weight: 700; font-size: 12pt;')
        font = self.character_label.font()
        font.setBold(True)
        self.character_label.setFont(font)
        grid.addWidget(self.character_label, 0, 0, 1, 2)
        for column, title in ((2, 'Зелье из инвентаря'), (3, 'Порог, %'), (4, 'Интервал, сек')):
            grid.addWidget(label(title, 'section'), 0, column)
        self.recovery_widgets = {}
        for index, resource in enumerate(('cp', 'hp', 'mp'), 1):
            prefix = 'heal' if resource == 'hp' else f'recovery/{resource}'
            controller = self.monitor.recovery[resource]
            bar = QProgressBar()
            bar.setObjectName('character_' + resource)
            bar.setRange(0, 1000)
            bar.setValue(0)
            bar.setFormat(resource.upper() + ' — / —')
            bar.setFixedWidth(360)
            enabled = QCheckBox('Авто')
            enabled.setToolTip(self.t('Разрешить автовосстановление этой полосы. Запуск — кнопкой справа.'))
            potion = QComboBox()
            potion.setMinimumWidth(280)
            potion.setMaximumWidth(350)
            potion.setIconSize(QSize(24, 24))
            potion.setPlaceholderText(self.t('Выберите зелье'))
            potion.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            potion.setMinimumContentsLength(25)
            threshold = QSpinBox()
            threshold.setRange(1, 99)
            threshold.setSuffix(' %')
            threshold.setValue(80 if self.self_test else self.settings.value(prefix + '/threshold', 80, type=int))
            interval = QSpinBox()
            interval.setRange(1, 3600)
            interval.setValue(11 if self.self_test else self.settings.value(prefix + '/intervalSeconds', 11, type=int))
            interval.setToolTip(self.t('После срабатывания восстанавливает до 100%. Серверный откат учитывается отдельно.'))
            toggle = QPushButton('Старт')
            toggle.setCheckable(True)
            toggle.setMinimumWidth(85)
            toggle.setObjectName('recovery_' + resource + '_toggle')
            status = label('Выключено')
            status.setMinimumWidth(115)
            saved = None if self.self_test else self.settings.value(prefix + '/itemId', None, type=int)
            selected = saved if type(saved) is int and saved > 0 else None
            row = dict(bar=bar, enabled=enabled, potion=potion, threshold=threshold, interval=interval,
                       toggle=toggle, status=status, selected=selected, signature=None)
            self.recovery_widgets[resource] = row
            for column, widget in enumerate((bar, enabled, potion, threshold, interval, toggle, status)):
                grid.addWidget(widget, index, column)
            controller.configure(False, selected, threshold.value(), interval.value() * 1000)
            enabled.toggled.connect(lambda value, key=resource: self.arm_recovery(key, value))
            toggle.toggled.connect(lambda value, key=resource: self.toggle_recovery(key, value))
            for signal in (potion.currentIndexChanged, threshold.valueChanged, interval.valueChanged):
                signal.connect(lambda _value, key=resource: self.configure_recovery(key))
            setattr(self, 'character_' + resource, bar)
        hp = self.recovery_widgets['hp']
        self.heal_enabled, self.heal_potion = hp['enabled'], hp['potion']
        self.heal_threshold, self.heal_interval = hp['threshold'], hp['interval']
        self.heal_status = hp['status']
        self.heal_error, self.heal_cooldown = label(''), label('')
        return panel

    def arm_recovery(self, resource, armed):
        row = self.recovery_widgets[resource]
        if not armed:
            row['toggle'].blockSignals(True)
            row['toggle'].setChecked(False)
            row['toggle'].blockSignals(False)
        self.configure_recovery(resource)

    def toggle_recovery(self, resource, running):
        row = self.recovery_widgets[resource]
        if running:
            row['enabled'].blockSignals(True)
            row['enabled'].setChecked(True)
            row['enabled'].blockSignals(False)
        self.configure_recovery(resource)

    def configure_heal(self, *_):
        self.configure_recovery('hp')

    def configure_recovery(self, resource):
        row = self.recovery_widgets[resource]
        item_id = row['potion'].currentData()
        if item_id is None:
            item_id = row['selected']
        try:
            self.monitor.recovery[resource].configure(row['enabled'].isChecked() and row['toggle'].isChecked(),
                                                    item_id, row['threshold'].value(), row['interval'].value() * 1000)
            if item_id is not None:
                row['selected'] = item_id
            if not self.self_test:
                prefix = 'heal' if resource == 'hp' else f'recovery/{resource}'
                if item_id is not None:
                    self.settings.setValue(prefix + '/itemId', item_id)
                self.settings.setValue(prefix + '/threshold', row['threshold'].value())
                self.settings.setValue(prefix + '/intervalSeconds', row['interval'].value())
        except ValueError as error:
            controller = self.monitor.recovery[resource]
            current = controller.snapshot()
            controller.configure(False, current['item_id'], current['threshold'], current['interval_ms'])
            row['toggle'].blockSignals(True)
            row['toggle'].setChecked(False)
            row['toggle'].blockSignals(False)
            self.report_error(str(error))
        self.set_text(row['toggle'], 'Стоп' if row['toggle'].isChecked() else 'Старт')

    def poll_health(self):
        health = self.monitor.character_status()
        if health:
            self.character_label.setProperty('_l2DynamicText', '')
            self.character_label.setText(f"{self.t('Ник')}: {health['character']} · {self.t('Уровень')}: {health['level']}")
        else:
            self.set_text(self.character_label, 'Персонаж: ожидание данных')
        states = {'disabled': 'Выключено', 'waiting': 'Ожидание данных', 'watching': 'Наблюдение',
                  'healing': 'До 100%', 'empty': 'Зелье закончилось', 'dead': 'Персонаж погиб',
                  'paused': 'Пауза', 'failed': 'Ошибка'}
        for resource, row in self.recovery_widgets.items():
            controller = self.monitor.recovery[resource]
            state = controller.snapshot()
            current = health.get(resource) if health else None
            maximum = health.get('max_' + resource) if health else None
            if current is not None and maximum and current >= 0:
                percent = 100 * current / maximum
                row['bar'].setValue(max(0, min(1000, round(percent * 10))))
                row['bar'].setFormat(f'{resource.upper()} {current} / {maximum} · {percent:.1f}%')
            else:
                row['bar'].setValue(0)
                row['bar'].setFormat(resource.upper() + ' — / —')
            signature = (state['potions'], state['item_id'], self.language)
            if signature != row['signature']:
                row['signature'] = signature
                selected = state['item_id'] if state['item_id'] is not None else row['selected']
                combo = row['potion']
                combo.blockSignals(True)
                combo.clear()
                for potion in state['potions']:
                    name = f"{potion['name']} ×{potion['amount']} (ID {potion['item_id']})"
                    icon = self.client_icons.icon('item', potion['item_id'])
                    combo.addItem(icon, name, potion['item_id']) if icon else combo.addItem(name, potion['item_id'])
                if selected is None and state['potions']:
                    selected = state['potions'][0]['item_id']
                    row['selected'] = selected
                    controller.configure(state['enabled'], selected, state['threshold'], state['interval_ms'])
                combo.setCurrentIndex(combo.findData(selected))
                combo.setToolTip(combo.currentText() if combo.currentIndex() >= 0 else self.t('Нет выбранного зелья в инвентаре' if selected else 'Нет зелий в инвентаре'))
                combo.blockSignals(False)
            for widget, value in ((row['toggle'], state['enabled']), (row['threshold'], state['threshold']),
                                  (row['interval'], state['interval_ms'] // 1000)):
                widget.blockSignals(True)
                widget.setChecked(value) if isinstance(widget, QPushButton) else widget.setValue(value)
                widget.blockSignals(False)
            if state['enabled'] and not row['enabled'].isChecked():
                row['enabled'].blockSignals(True)
                row['enabled'].setChecked(True)
                row['enabled'].blockSignals(False)
            row['toggle'].setEnabled(state['enabled'] or row['potion'].currentData() is not None)
            self.set_text(row['toggle'], 'Стоп' if state['enabled'] else 'Старт')
            self.set_text(row['status'], states.get(state['state'], state['state']))
            details = f"{self.t('Перезарядка хилки, сек:')} {state['cooldown_seconds']} · {self.t('Попыток применения:')} {state['attempts']}"
            if state['error']:
                details += '\n' + state['error']
            row['status'].setToolTip(details)
            row['bar'].setToolTip(details)
        if health and all(key in health for key in ('str', 'dex', 'con', 'int', 'wit', 'men')):
            core = ' · '.join(f'{key.upper()} {health[key]}' for key in ('str','dex','con','int','wit','men'))
            combat = ' · '.join(f'{title} {health[key]}' for key, title in
                               (('p_atk','P.Atk'),('p_def','P.Def'),('m_atk','M.Atk'),('m_def','M.Def'),
                                ('attack_speed','Atk.Spd'),('casting_speed','Cast.Spd')) if key in health)
            self.character_stats.setText(core + ('\n' + combat if combat else ''))
            self.character_stats.setVisible(True)
        else:
            self.character_stats.setVisible(False)

    def _additional_options_page(self):
        scroll = QScrollArea()
        scroll.setObjectName('additionalOptionsScroll')
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        page = QWidget()
        outer = QVBoxLayout(page)
        # Preserve the controls' size hints when the character panel leaves less
        # vertical space for tabs. Overflow belongs in the viewport scrollbar.
        outer.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        top = QHBoxLayout()
        outer.addLayout(top)
        pickup_section = QWidget()
        layout = QVBoxLayout(pickup_section)
        top.addWidget(pickup_section, 1)
        self.pickup_enabled = QCheckBox('Автоподбор окружающих вещей')
        self.pickup_enabled.setChecked(False if self.self_test else self.settings.value('pickup/enabled', False, type=bool))
        layout.addWidget(self.pickup_enabled)
        form = QFormLayout()
        self.pickup_radius = QSpinBox()
        self.pickup_radius.setRange(50, 1500)
        self.pickup_radius.setSingleStep(50)
        self.pickup_radius.setValue(200 if self.self_test else self.settings.value('pickup/radius', 200, type=int))
        form.addRow(label('Радиус подбора'), self.pickup_radius)
        self.pickup_interval = QSpinBox()
        self.pickup_interval.setRange(250, 30000)
        self.pickup_interval.setSingleStep(250)
        self.pickup_interval.setValue(750 if self.self_test else self.settings.value('pickup/interval', 750, type=int))
        form.addRow(label('Пауза после подбора, мс'), self.pickup_interval)
        layout.addLayout(form)
        for text in ('Подбирает всё, включая выброшенные программой предметы.',
                     'На время очереди выброса автоподбор приостанавливается.'):
            note = label(text, 'subtle')
            note.setWordWrap(True)
            layout.addWidget(note)
        self.pickup_status = label('Автоподбор выключен')
        layout.addWidget(self.pickup_status)
        self.pickup_counts = label('')
        layout.addWidget(self.pickup_counts)
        self.pickup_error = label('')
        self.pickup_error.setWordWrap(True)
        layout.addWidget(self.pickup_error)
        layout.addStretch()
        layout = outer
        layout.addWidget(label('Восстановление CP / HP / MP — в панели персонажа над вкладками.', 'subtle'))
        layout.addSpacing(18)
        buff_controls = QHBoxLayout()
        buff_controls.addWidget(label('Newbie Buff', 'badge'))
        buff_controls.addWidget(label('Количество раз'))
        self.buff_count = QSpinBox()
        self.buff_count.setObjectName('newbieBuffCount')
        self.buff_count.setRange(1, 1000)
        self.buff_count.setValue(1 if self.self_test else self.settings.value('buffs/count', 1, type=int))
        buff_controls.addWidget(self.buff_count)
        self.buff_start = button('Старт', self.start_newbie_buff, primary=True)
        buff_controls.addWidget(self.buff_start)
        buff_controls.addStretch()
        layout.addLayout(buff_controls)
        self.buff_status = label('Newbie Buff: готов')
        layout.addWidget(self.buff_status)
        self.buff_counts = label('')
        layout.addWidget(self.buff_counts)
        self.buff_error = label('')
        self.buff_error.setWordWrap(True)
        layout.addWidget(self.buff_error)
        self.buffs_model = RowsModel([('ID скилла', 'skill_id'), ('Название', 'skill_name'), ('Уровень бафа', 'skill_level'), ('Осталось, сек', 'remaining_seconds')], self, icon_kind='skill', icon_column='skill_name')
        self.buffs_table = table(self.buffs_model)
        self.buffs_table.setMaximumHeight(260)
        self.buffs_table.setMinimumHeight(150)
        for index, width in enumerate((120, 330, 180, 220)):
            self.buffs_table.setColumnWidth(index, width)
        layout.addWidget(self.buffs_table)
        self._buff_signature = None
        layout.addStretch()
        self.pickup_enabled.toggled.connect(self.configure_pickup)
        self.pickup_radius.valueChanged.connect(self.configure_pickup)
        self.pickup_interval.valueChanged.connect(self.configure_pickup)
        self.configure_pickup()
        scroll.setWidget(page)
        return scroll

    def configure_pickup(self, *_):
        self.monitor.auto_pickup.configure(self.pickup_enabled.isChecked(), self.pickup_radius.value(), self.pickup_interval.value())
        if not self.self_test:
            self.settings.setValue('pickup/enabled', self.pickup_enabled.isChecked())
            self.settings.setValue('pickup/radius', self.pickup_radius.value())
            self.settings.setValue('pickup/interval', self.pickup_interval.value())

    def start_newbie_buff(self):
        try:
            self.monitor.newbie_buff.start(self.buff_count.value())
            if not self.self_test:
                self.settings.setValue('buffs/count', self.buff_count.value())
        except (ValueError, RuntimeError) as error:
            self.report_error(str(error))

    def poll_buffs(self):
        buffs, actions = self.monitor.buffs.snapshot(), self.monitor.newbie_buff.snapshot()
        catalog = self.monitor.auto_heal.catalog
        signature = (buffs, actions, self.language, catalog.revision)
        if signature != self._buff_signature:
            self._buff_signature = signature
            self.buffs_model.replace([dict(row, skill_name=catalog.skill_name(row['skill_id'], row['skill_level'])) for row in buffs['buffs']])
            job = actions['job'] or (actions['history'][-1] if actions['history'] else None)
            states = {'opening': 'Newbie Buff: открытие NPC', 'sending': 'Newbie Buff: отправка',
                      'confirming': 'Newbie Buff: ожидание ответа', 'completed': 'Newbie Buff: завершено',
                      'partial': 'Newbie Buff: частично подтверждено', 'failed': 'Newbie Buff: ошибка'}
            self.set_text(self.buff_status, states[job['state']] if job else 'Newbie Buff: готов')
            self.set_text(self.buff_error, job.get('error') or '' if job else '')
            self.buff_counts.setProperty('_l2DynamicText', '')
            self.buff_counts.setText('' if not job else f"{self.t('Отправлено:')} {job['sent']}/{job['count']} · "
                                     f"{self.t('Запросов в захвате:')} {job['requests_seen']} · "
                                     f"{self.t('Подтверждено наборов:')} {job['confirmed']}")
        status = self.monitor.status()
        self.buff_start.setEnabled(bool(not self.self_test and not actions['active'] and status.get('running') and status.get('state') == 'live'))

    def poll_pickup(self):
        state = self.monitor.auto_pickup.snapshot()
        for widget, value in ((self.pickup_enabled, state['enabled']), (self.pickup_radius, state['radius']),
                              (self.pickup_interval, state['interval_ms'])):
            widget.blockSignals(True)
            if isinstance(widget, QCheckBox):
                widget.setChecked(value)
            else:
                widget.setValue(value)
            widget.blockSignals(False)
        labels = {'disabled': 'Автоподбор выключен', 'waiting': 'Автоподбор: ожидание синхронизации',
                  'watching': 'Автоподбор: поиск предметов рядом', 'confirming': 'Автоподбор: ожидание ответа сервера',
                  'dropping': 'Автоподбор: пауза на время выброса', 'learning': 'Автоподбор: пауза на время обучения',
                  'buffing': 'Автоподбор: пауза на время бафов', 'failed': 'Автоподбор: ошибка'}
        self.set_text(self.pickup_status, labels[state['state']])
        self.pickup_counts.setProperty('_l2DynamicText', '')
        self.pickup_counts.setText(f"{self.t('Подобрано предметов:')} {state['picked_items']} · "
                                  f"{self.t('Количество подобранных вещей:')} {state['picked_amount']} · "
                                  f"{self.t('Неподтверждённых попыток:')} {state['failures']}")
        self.pickup_error.setProperty('_l2DynamicText', state['last_error'] or '')
        self.pickup_error.setText(state['last_error'] or '')

    def _queue_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        intro = QHBoxLayout()
        intro.addWidget(label('Очередь пакетов', 'badge'))
        intro.addStretch()
        self.network_button = button('Выбрать пакеты C → S', self.choose_outgoing_packets)
        intro.addWidget(self.network_button)
        layout.addLayout(intro)
        self.queue_info = label('Добавьте копии пакетов через контекстное меню или редактор')
        layout.addWidget(self.queue_info)
        self.queue_model = RowsModel([('№', 'queue_position'), ('Исходный №', 'id'), ('Поток', 'direction'), ('Opcode', 'opcode'),
                                     ('Тип пакета', 'name'), ('Категория', 'category'), ('Байт', 'length')], self, packet_colors=True)
        self.queue_table = table(self.queue_model)
        self.queue_table.setColumnWidth(4, 330)
        self.queue_table.setColumnWidth(5, 230)
        layout.addWidget(self.queue_table, 1)
        editing = QHBoxLayout()
        self.queue_edit_buttons = []
        for text, action in [('↑  Выше', lambda: self.move_queue(-1)), ('↓  Ниже', lambda: self.move_queue(1)),
                             ('Удалить', self.remove_queue), ('Очистить', self.clear_queue), ('Экспорт JSON…', self.export_queue)]:
            control = button(text, action)
            editing.addWidget(control)
            self.queue_edit_buttons.append(control)
        editing.addStretch()
        layout.addLayout(editing)
        run = QHBoxLayout()
        run.addWidget(label('Циклов'))
        self.repeat_spin = QSpinBox()
        self.repeat_spin.setRange(1, 10000)
        self.repeat_spin.setValue(1)
        run.addWidget(self.repeat_spin)
        run.addWidget(label('Интервал, мс'))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(0, 60000)
        self.interval_spin.setValue(250)
        self.interval_spin.setSingleStep(50)
        self.interval_spin.setToolTip(self.t('Пауза после подтверждения предыдущего пакета в захвате'))
        run.addWidget(self.interval_spin)
        run.addStretch()
        self.queue_start = button('▶  Отправить очередь', self.start_packet_queue, primary=True)
        self.queue_pause = button('Ⅱ  Пауза', lambda: self.queue_runner.pause(not self.queue_runner.snapshot()['paused']))
        self.queue_stop = button('■  Стоп', self.queue_runner.stop, danger=True)
        for control in (self.queue_start, self.queue_pause, self.queue_stop):
            control.setEnabled(False)
        run.addWidget(self.queue_start)
        run.addWidget(self.queue_pause)
        run.addWidget(self.queue_stop)
        layout.addLayout(run)
        self.queue_progress = label('')
        self.queue_progress.setWordWrap(True)
        layout.addWidget(self.queue_progress)
        return page

    def _restore(self, pid, interface, cipher):
        if not self.self_test:
            geometry = self.settings.value('geometry')
            if isinstance(geometry, QByteArray):
                self.restoreGeometry(geometry)
            for name, widget in [('packets', self.packet_splitter), ('details', self.detail_splitter)]:
                value = self.settings.value('splitter/' + name)
                if isinstance(value, QByteArray):
                    widget.restoreState(value)
            self.encoding_combo.setCurrentText(self.settings.value('encoding', 'utf-8'))
            self.follow.setChecked(self.settings.value('follow', True, type=bool))
            self.repeat_spin.setValue(self.settings.value('queue/repeats', 1, type=int))
            self.interval_spin.setValue(self.settings.value('queue/interval', 250, type=int))
            unchecked = set(self.settings.value('uncheckedCategories', [], type=list))
            self._unchecked_types = set(self.settings.value('uncheckedTypes', [], type=list))
            self.filter_tree.blockSignals(True)
            for key, item in self.category_items.items():
                if key in unchecked:
                    item.setCheckState(0, Qt.CheckState.Unchecked)
            self.filter_tree.blockSignals(False)
            self.apply_filters()
        # PIDs belong to one process lifetime. Restoring a previous session's
        # numeric PID can pin discovery to a client which no longer exists.
        self._preferred_pid = pid
        self._preferred_interface = interface if interface != 'auto' else self.settings.value('interface', 'auto')
        self._preferred_cipher = cipher if cipher != 'auto' else self.settings.value('cipher', 'auto')
        self.cipher_combo.setCurrentIndex(max(0, self.cipher_combo.findData(self._preferred_cipher)))
        if self._preferred_pid:
            self.pid_combo.addItem('PID ' + str(self._preferred_pid), int(self._preferred_pid))
            self.pid_combo.setCurrentIndex(self.pid_combo.count() - 1)
        else:
            self.pid_combo.setCurrentIndex(0)
        if self._preferred_interface != 'auto':
            self.interface_combo.addItem(str(self._preferred_interface), self._preferred_interface)
            self.interface_combo.setCurrentIndex(self.interface_combo.count() - 1)

    def selected_pid(self):
        text = self.pid_combo.currentText().strip()
        value = self.pid_combo.currentData()
        if value is not None and text == self.pid_combo.itemText(self.pid_combo.currentIndex()):
            return int(value)
        if text in ('PID: автоматически', 'PID: automatic') or not text:
            return None
        text = text.removeprefix('PID').strip().split(' ')[0]
        try:
            return int(text)
        except ValueError as error:
            raise ValueError('Введите числовой PID или выберите процесс из списка') from error

    def refresh_discovery(self):
        if self._discovering:
            return
        self._discovering = True
        self.refresh_button.setEnabled(False)
        try:
            pid = self.selected_pid()
        except ValueError:
            pid = None
        interface = self.interface_combo.currentData()

        def discover():
            result = {'processes': [], 'interfaces': [], 'errors': []}
            for name, function in [('processes', discovery.processes), ('interfaces', discovery.interfaces)]:
                try:
                    result[name] = function()
                except Exception as error:
                    result['errors'].append(str(error))
            return result

        def complete(result):
            self.pid_combo.clear()
            self.pid_combo.addItem('PID: автоматически', None)
            for process in result['processes']:
                self.pid_combo.addItem(f"PID {process['pid']} · {process['name']}", process['pid'])
            if pid and self.pid_combo.findData(pid) < 0:
                self.pid_combo.addItem(f'PID {pid}', pid)
            self.pid_combo.setCurrentIndex(max(0, self.pid_combo.findData(pid)))
            self.interface_combo.clear()
            self.interface_combo.addItem('Интерфейс: автоматически', 'auto')
            for adapter in result['interfaces']:
                text = ('● ' if adapter.get('recommended') else '') + adapter.get('name', adapter.get('device', ''))
                self.interface_combo.addItem(text, adapter['device'])
                self.interface_combo.setItemData(self.interface_combo.count() - 1, adapter['device'], Qt.ItemDataRole.ToolTipRole)
            if interface and self.interface_combo.findData(interface) < 0:
                self.interface_combo.addItem(str(interface), interface)
            self.interface_combo.setCurrentIndex(max(0, self.interface_combo.findData(interface)))
            self._translate_combo(self.pid_combo)
            self._translate_combo(self.interface_combo)
            self.show_status(' · '.join(result['errors']) if result['errors'] else f"Процессов: {len(result['processes'])}; интерфейсов: {len(result['interfaces'])}", 15000)

        def finished():
            self._discovering = False
            self.refresh_button.setEnabled(True)
        self.task(discover, complete, finished=finished)

    def start_capture(self):
        if self._busy_capture or self.self_test:
            return
        try:
            options = dict(pid=self.selected_pid(), interface=self.interface_combo.currentData() or 'auto',
                           cipher=self.cipher_combo.currentData() or 'auto', source=self.source_combo.currentData() or 'auto')
        except ValueError as error:
            self.report_error(str(error))
            return
        self._busy_capture = True
        self.task(lambda: self.monitor.start(**options), finished=self.capture_task_done)

    def capture_task_done(self):
        self._busy_capture = False
        self.poll()

    def stop_capture(self):
        if self._busy_capture:
            return
        self._busy_capture = True
        self.set_text(self.state_label, 'Остановка захвата…')
        self.task(self.monitor.stop, finished=self.capture_task_done)

    def poll(self):
        if self._closing:
            return
        status = self.monitor.status()
        auto_state = (status.get('inventory_auto_open') or {}).get('state')
        auto_text = {
            'waiting': 'Автооткрытие: ожидание игрового окна',
            'requested': 'Автооткрытие: ожидается список предметов',
            'received': 'Автооткрытие: список предметов получен',
            'failed': 'Автооткрытие: список предметов не получен',
        }.get(auto_state, 'Автооткрытие: ожидание синхронизации')
        self.set_text(self.inventory_open_status, auto_text if self.inventory_auto_open.isChecked() else 'Автооткрытие выключено')
        stats = status.get('packets', {})
        running = status.get('running', False)
        self.start_button.setEnabled(not running and not self._busy_capture and not self.self_test)
        self.stop_button.setEnabled(running and not self._busy_capture)
        for widget in (self.pid_combo, self.interface_combo, self.cipher_combo, self.source_combo):
            widget.setEnabled(not running and not self._busy_capture)
        self.metric_values['packets'].setText(f"{stats.get('total', 0):,}".replace(',', ' '))
        self.metric_values['frames'].setText(f"{status.get('captured_frames', 0):,}".replace(',', ' '))
        self.metric_values['windows'].setText(str(status.get('validated_windows', 0)))
        self.set_text(self.metric_values['sync'], str(status.get('sync_errors', 0)) + ' ошибок')
        cipher = status.get('detected_cipher') or status.get('requested_cipher') or self.cipher_combo.currentData()
        self.metric_values['cipher'].setText(str(cipher) + ' / ' + str(status.get('capture_backend', 'npcap')))
        self.metric_values['cipher'].setStyleSheet('font-size: 14pt;')
        state_colors = {'live': '#247343', 'synchronizing': '#966508', 'waiting': '#966508', 'discovering': '#2564aa'} if self.theme == 'light' else {'live': '#71d7a1', 'synchronizing': '#e3b341', 'waiting': '#e3b341', 'discovering': '#81bbff'}
        self.state_label.setStyleSheet('color: ' + state_colors.get(status.get('state'), '#5c7290' if self.theme == 'light' else '#9bacc5') + ';')
        if status.get('state') == 'capturing':
            self.state_label.setStyleSheet('color: ' + ('#247343' if self.theme == 'light' else '#71d7a1') + ';')
        endpoint = status.get('endpoint') or {}
        suffix = f"  ·  {endpoint.get('remote_ip')}:{endpoint.get('remote_port')}" if endpoint else ''
        process = status.get('process') or {}
        suffix += f"  ·  PID {process['pid']}" if process.get('pid') else ''
        self.set_text(self.state_label, status.get('message', '') + suffix)
        if stats.get('total', 0) > self.cursor:
            for _ in range(8):
                result = self.monitor.store.query(after=self.cursor, limit=1000)
                self.packet_model.append(result['packets'])
                self.cursor = result['cursor']
                if not result.get('more'):
                    break
            if self.follow.isChecked():
                self.packet_table.scrollToBottom()
        self.set_text(self.shown_label, f'{self.proxy.rowCount()} / {len(self.packet_model.rows)} пакетов в таблице')
        self.update_types()
        world = self.monitor.world.snapshot()
        if world != self._last_world:
            self._last_world = world
            self.world_model.replace(world.get('items', []))
            self.events_model.replace(world.get('events', []))
            state = ' · Есть промежуток без наблюдений' if world.get('coverage_gap') else ''
            self.set_text(self.world_info, f"Предметов рядом: {len(world.get('items', []))} · Координаты персонажа: {display(world.get('own_position'))}" + state)
        inventory = self.monitor.inventory.snapshot()
        names = self.monitor.auto_heal.snapshot()['item_names']
        inventory['items'] = [dict(row, item_name=names.get(row['item_id']) or self.monitor.auto_heal.catalog.item_name(row['item_id'])) for row in inventory['items']]
        if inventory != self._last_inventory:
            selected = self.selected_inventory()
            self._last_inventory = inventory
            query = self.inventory_search.text().strip().casefold()
            self.inventory_model.replace([row for row in inventory.get('items', [])
                                          if not query or query in str(row['item_id']) or query in row['item_name'].casefold()])
            if selected:
                for index, item in enumerate(self.inventory_model.rows):
                    if item['object_id'] == selected['object_id']:
                        self.inventory_table.selectRow(index)
                        break
            self._render_inventory_info(inventory)
        self.update_inventory_actions()
        self.poll_inventory_drops()
        self.poll_pickup()
        self.poll_skills()
        self.poll_buffs()
        self.poll_health()
        self.poll_queue()
        self.poll_client_catalog()
        self.poll_sources()
        library_key = (stats.get('total', 0), self.tabs.currentIndex())
        if self.tabs.currentIndex() == 2 and library_key != self._last_library_key:
            self._last_library_key = library_key
            self.refresh_library()

    def set_auto_inventory(self, enabled):
        self.monitor.auto_inventory_enabled = enabled
        if not self.self_test:
            self.settings.setValue('inventory/autoOpen', enabled)

    def _render_inventory_info(self, inventory=None):
        inventory = inventory or self._last_inventory or self.monitor.inventory.snapshot()
        text = f"{self.t('Наблюдаемых позиций:')} {len(inventory.get('items', []))}"
        if inventory.get('coverage_gap'):
            text += ' · ' + self.t('Есть промежуток без наблюдений')
        self.inventory_info.setProperty('_l2DynamicText', text)
        self.inventory_info.setText(text)

    def selected_inventory(self):
        index = self.inventory_table.currentIndex()
        if not index.isValid() or index.row() >= len(self.inventory_model.rows):
            return None
        return self.inventory_model.rows[index.row()]

    def update_inventory_actions(self):
        selected = self.selected_inventory() if hasattr(self, 'inventory_table') else None
        enabled = selected is not None
        self.inventory_copy_id.setEnabled(enabled)
        self.inventory_manual_drop.setEnabled(enabled and self.can_drop_inventory())

    def can_drop_inventory(self):
        status = self.monitor.status()
        inventory = self.monitor.inventory.snapshot()
        return (not self.self_test and status.get('state') == 'live' and status.get('running')
                and inventory.get('full_list_received') and not inventory.get('coverage_gap'))

    def copy_inventory_id(self):
        item = self.selected_inventory()
        if not item:
            self.report_error(self.t('Выберите предмет в таблице'))
            return
        QApplication.clipboard().setText(str(item['item_id']))
        self.show_status(f"{self.t('ID предмета скопирован:')} {item['item_id']}", 5000)

    def inventory_context_menu(self, point):
        index = self.inventory_table.indexAt(point)
        if not index.isValid():
            return
        self.inventory_table.setCurrentIndex(index)
        if not self.selected_inventory():
            return
        menu = QMenu(self)
        copy_action = menu.addAction(self.t('Копировать ID'))
        menu.addSeparator()
        one_action = menu.addAction(self.t('Выбросить одну штуку'))
        bulk_action = menu.addAction(self.t('Выбросить количество…'))
        single_action = menu.addAction(self.t('Выбрасывать по одной…'))
        for action in (one_action, bulk_action, single_action):
            action.setEnabled(bool(self.can_drop_inventory()))
        selected = menu.exec(self.inventory_table.viewport().mapToGlobal(point))
        if selected == copy_action:
            self.copy_inventory_id()
        elif selected == one_action:
            self.drop_inventory_one()
        elif selected == bulk_action:
            self.show_inventory_drop('bulk')
        elif selected == single_action:
            self.show_inventory_drop('single')

    def drop_inventory_one(self):
        item = self.selected_inventory()
        if not item:
            return
        try:
            self.monitor.inventory_drop.enqueue(item['object_id'], 1, 'bulk')
        except ValueError as error:
            self.report_error(str(error))

    def show_inventory_drop(self, mode='bulk'):
        item = self.selected_inventory()
        if not item:
            return
        dialog = self.inventory_drop_dialog(dict(item), mode if mode in ('bulk', 'single') else 'bulk')
        dialog.exec()

    def inventory_drop_dialog(self, item, mode='bulk'):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.t('Выброс предметов'))
        dialog.setMinimumWidth(540)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"{self.t('ID предмета')}: {item['item_id']} · {self.t('Доступно:')} {item['amount']}"))
        form = QFormLayout()
        amount = QLineEdit('1')
        amount.setObjectName('dropAmount')
        amount.setMaxLength(19)
        amount.selectAll()
        form.addRow(self.t('Количество'), amount)
        modes = QComboBox()
        modes.setObjectName('dropMode')
        modes.addItem(self.t('Сразу указанное количество'), 'bulk')
        modes.addItem(self.t('По одной штуке'), 'single')
        modes.setCurrentIndex(modes.findData(mode))
        form.addRow(self.t('Режим'), modes)
        interval = QSpinBox()
        interval.setObjectName('dropInterval')
        interval.setRange(100, 30000)
        interval.setSingleStep(100)
        interval.setValue(500 if self.self_test else self.settings.value('inventory/dropInterval', 500, type=int))
        interval.setEnabled(mode == 'single')
        modes.currentIndexChanged.connect(lambda: interval.setEnabled(modes.currentData() == 'single'))
        form.addRow(self.t('Пауза после ответа, мс'), interval)
        layout.addLayout(form)
        location = QLabel(self.t('Место выброса: рядом с персонажем. Координаты берутся из клиента перед каждым действием.'))
        location.setWordWrap(True)
        layout.addWidget(location)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        add = buttons.addButton(self.t('Добавить в очередь'), QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.rejected.connect(dialog.reject)

        def enqueue():
            try:
                text = amount.text().strip()
                if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= item['amount']:
                    raise ValueError(self.t('Введите количество от 1 до доступного остатка'))
                self.monitor.inventory_drop.enqueue(item['object_id'], int(text), modes.currentData(), interval.value())
            except ValueError as error:
                QMessageBox.warning(dialog, self.t('Выброс предметов'), str(error))
                return
            if not self.self_test:
                self.settings.setValue('inventory/dropInterval', interval.value())
            dialog.accept()
        add.clicked.connect(enqueue)
        layout.addWidget(buttons)
        return dialog

    def toggle_drop_pause(self):
        self.monitor.inventory_drop.pause(not self.monitor.inventory_drop.snapshot()['paused'])

    def poll_inventory_drops(self):
        state = self.monitor.inventory_drop.snapshot()
        self.drop_pause.setEnabled(state['active'])
        self.drop_stop.setEnabled(state['active'])
        self.set_text(self.drop_pause, 'Продолжить выброс' if state['paused'] else 'Пауза выброса')
        signature = (self.language, json.dumps(state, sort_keys=True))
        if signature == self._drop_signature:
            return
        self._drop_signature = signature
        labels = {'queued': 'В очереди', 'running': 'Выполняется', 'sending': 'Отправляется',
                  'confirming': 'Ожидание ответа сервера', 'completed': 'Завершено',
                  'stopped': 'Остановлено', 'failed': 'Ошибка'}
        self.drop_model.replace([dict(job, mode_label=self.t('По одной штуке' if job['mode'] == 'single' else 'Сразу указанное количество'),
                                      state_label=self.t(labels[job['state']])) for job in state['jobs']])

    def update_types(self):
        types = self.monitor.store.type_list()
        signature = tuple((row['id'], row['count']) for row in types)
        if signature == self._type_signature:
            return
        self._type_signature = signature
        self.filter_tree.blockSignals(True)
        for row in types:
            item = self.type_items.get(row['id'])
            if item is None:
                item = QTreeWidgetItem(self.type_root)
                item.setData(0, Qt.ItemDataRole.UserRole, ('type', row['id']))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(0, Qt.CheckState.Unchecked if row['id'] in self._unchecked_types else Qt.CheckState.Checked)
                self.type_items[row['id']] = item
            direction = 'S' if row['direction'] == 'server' else 'C'
            item.setText(0, f"{direction} {row['opcode']} · {row['name']} ({row['count']})")
            item.setData(0, Qt.ItemDataRole.UserRole + 1, row['color'])
            item.setForeground(0, packet_color(row['color'], self.theme == 'light'))
        self.filter_tree.blockSignals(False)
        self.apply_filters()

    def apply_filters(self, *_):
        if not hasattr(self, 'proxy'):
            return
        self.proxy.search = self.search.text().strip().lower()
        self.proxy.direction = self.direction_combo.currentData()
        checked = {key for key, item in self.category_items.items() if item.checkState(0) == Qt.CheckState.Checked}
        self.proxy.categories = None if len(checked) == len(self.category_items) else checked
        checked_types = {key for key, item in self.type_items.items() if item.checkState(0) == Qt.CheckState.Checked}
        self.proxy.types = None if len(checked_types) == len(self.type_items) else checked_types
        self.proxy.refilter()
        self.set_text(self.shown_label, f'{self.proxy.rowCount()} / {len(self.packet_model.rows)} пакетов в таблице')

    def set_checks(self, checked):
        self.filter_tree.blockSignals(True)
        for item in list(self.category_items.values()) + list(self.type_items.values()):
            item.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.filter_tree.blockSignals(False)
        self.apply_filters()

    def reset_filters(self):
        self.search.clear()
        self.direction_combo.setCurrentIndex(0)
        self.set_checks(True)

    def selected_packet(self):
        index = self.packet_table.currentIndex()
        if not index.isValid():
            return None
        row = self.packet_model.rows[self.proxy.mapToSource(index).row()]
        return self.monitor.store.detail(row['id']) or (copy.deepcopy(row) if row.get('raw_hex') else None)

    def select_packet(self, current, previous=QModelIndex()):
        packet = self.selected_packet()
        if packet:
            self.load_packet(packet)

    def load_packet(self, packet):
        self.original = copy.deepcopy(packet)
        self.set_text(self.packet_heading, f"#{packet.get('id', '—')} · {packet.get('opcode', '')} · {packet.get('name', '')}")
        self.fields.clear()
        for key, value in packet.items():
            if key not in ('raw_hex', 'fields'):
                item = QTreeWidgetItem([key, self.t(display(value)) if key == 'category_label' else display(value)])
                if key == 'category_label':
                    item.setData(1, Qt.ItemDataRole.UserRole + 20, display(value))
                self.fields.addTopLevelItem(item)
        fields = QTreeWidgetItem(['fields', ''])
        self.fields.insertTopLevelItem(0, fields)
        self._add_fields(fields, packet.get('fields', {}))
        fields.setExpanded(True)
        self.reset_copy()

    def _add_fields(self, parent, value):
        values = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, (tuple, list)) else []
        for key, child in values:
            if isinstance(child, (dict, list, tuple)):
                item = QTreeWidgetItem([str(key), self.t(f'{len(child)} элементов')])
                item.setData(1, Qt.ItemDataRole.UserRole + 20, f'{len(child)} элементов')
                parent.addChild(item)
                self._add_fields(item, child)
            else:
                parent.addChild(QTreeWidgetItem([str(key), display(child)]))

    def conversion(self, mode='hex-to-text', update_length=False):
        return convert(dict(mode=mode, hex=self.hex_edit.toPlainText(), text=self.text_edit.toPlainText(),
                            encoding=self.encoding_combo.currentText(), update_length=update_length))

    def _apply_conversion(self, result):
        self.hex_edit.setPlainText(result['hex'])
        self.text_edit.setPlainText(result['text'])
        state = 'совпадает' if result['length_matches'] else 'не совпадает'
        self.set_text(self.copy_info, f"{result['length']} байт · u16: {result['declared_length']} ({state})")
        self.copy_info.setToolTip('SHA-256: ' + result['sha256'])

    def hex_to_text(self, *_):
        try:
            self._apply_conversion(self.conversion())
        except (ValueError, UnicodeError) as error:
            self.set_text(self.copy_info, str(error))

    def text_to_hex(self):
        try:
            self._apply_conversion(self.conversion('text-to-hex'))
        except (ValueError, UnicodeError) as error:
            self.set_text(self.copy_info, str(error))

    def fix_length(self):
        try:
            mode = 'text-to-hex' if self.editor_tabs.currentIndex() == 1 else 'hex-to-text'
            self._apply_conversion(self.conversion(mode, True))
        except (ValueError, UnicodeError) as error:
            self.set_text(self.copy_info, str(error))

    def reset_copy(self):
        if self.original:
            self.hex_edit.setPlainText(self.original.get('raw_hex', ''))
            self.hex_to_text()

    def edited_copy(self):
        mode = 'text-to-hex' if self.editor_tabs.currentIndex() == 1 else 'hex-to-text'
        converted = self.conversion(mode)
        self._apply_conversion(converted)
        packet = copy.deepcopy(self.original) if self.original else {}
        packet.update(raw_hex=converted['hex'], length=converted['length'], sha256=converted['sha256'])
        return packet, converted

    def save_copy(self, format):
        try:
            packet, converted = self.edited_copy()
            path = self.choose_save('Сохранить копию пакета', f"packet-{packet.get('id', 'copy')}.{format}", format)
            if path:
                content = bytes.fromhex(converted['hex']) if format == 'bin' else json.dumps(dict(packet=packet, conversion=converted, saved_at=datetime.now(timezone.utc).isoformat()), ensure_ascii=False, indent=2).encode('utf-8')
                Path(path).write_bytes(content)
                self.show_status('Сохранено: ' + path, 10000)
        except (ValueError, UnicodeError, OSError) as error:
            self.report_error(str(error))

    def choose_save(self, title, filename, format):
        root = Path(self.settings.value('exportDirectory', str(DATA_ROOT / 'reports')))
        root.mkdir(parents=True, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(self, self.t(title), str(root / filename), format.upper() + ' (*.' + format + ')', options=QFileDialog.Option.DontUseNativeDialog)
        if path:
            self.settings.setValue('exportDirectory', str(Path(path).parent))
        return path

    def export_packets(self):
        try:
            path = self.choose_save('Экспорт захваченных пакетов', 'packets.json', 'json')
            if path:
                self.write_json(path, self.monitor.store.export())
        except OSError as error:
            self.report_error(str(error))

    @staticmethod
    def write_json(path, value):
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    def library_filters(self):
        text = self.library_server.currentText().strip()
        server = None if text in ('Все серверы', 'All servers') or not text else text
        return dict(kind=self.library_kind.currentData(), server=server, search=self.library_search.text().strip())

    def refresh_library(self, *_):
        if self._library_busy:
            self._library_again = True
            return
        self._library_busy = True
        filters = self.library_filters()

        def complete(result):
            self.library_model.replace(result['rows'])
            self.set_text(self.library_info, f"Записей: {len(result['rows'])} · {self.monitor.library.path}")
            current = self.library_server.currentText()
            self.library_server.blockSignals(True)
            for server in result['servers']:
                if self.library_server.findText(server) < 0:
                    self.library_server.addItem(server, server)
            self.library_server.setCurrentText(current)
            self.library_server.blockSignals(False)

        def finished():
            self._library_busy = False
            if self._library_again and not self._closing:
                self._library_again = False
                QTimer.singleShot(0, self.refresh_library)

        self.task(lambda: dict(rows=self.monitor.library.query(**filters), servers=sorted({row['server'] for row in self.monitor.library.query()})), complete, finished=finished)

    def export_library(self, format):
        try:
            path = self.choose_save('Экспорт справочника', 'library.' + format, format)
            if path:
                filters = self.library_filters()
                self.task(lambda: Path(path).write_bytes(self.monitor.library.export(format, **filters)),
                          lambda _: self.show_status('Справочник сохранён: ' + path, 10000))
        except OSError as error:
            self.report_error(str(error))

    def packet_context_menu(self, point):
        index = self.packet_table.indexAt(point)
        if not index.isValid():
            return
        self.packet_table.setCurrentIndex(index)
        packet = self.selected_packet()
        if not packet:
            return
        menu = QMenu(self)
        add = menu.addAction(self.t('Добавить в очередь'))
        selected = menu.exec(self.packet_table.viewport().mapToGlobal(point))
        if selected == add:
            try:
                self.queue.add(packet)
                self.poll_queue()
                self.show_status('Копия добавлена в очередь', 5000)
            except ValueError as error:
                self.report_error(str(error))

    def queue_editor_copy(self):
        try:
            packet, _ = self.edited_copy()
            if not packet.get('raw_hex'):
                raise ValueError('Копия пуста')
            self.queue.add(packet)
            self.poll_queue()
            self.show_status('Копия из редактора добавлена в очередь', 5000)
        except (ValueError, UnicodeError) as error:
            self.report_error(str(error))

    def selected_queue_id(self):
        index = self.queue_table.currentIndex()
        return self.queue_model.rows[index.row()]['queue_id'] if index.isValid() and index.row() < len(self.queue_model.rows) else None

    def move_queue(self, delta):
        entry_id = self.selected_queue_id()
        if entry_id is not None:
            try:
                self.queue.move(entry_id, delta)
            except ValueError as error:
                self.report_error(str(error))
                return
            self.poll_queue()
            for i, row in enumerate(self.queue_model.rows):
                if row['queue_id'] == entry_id:
                    self.queue_table.selectRow(i)
                    break

    def remove_queue(self):
        entry_id = self.selected_queue_id()
        if entry_id is not None:
            try:
                self.queue.remove(entry_id)
            except ValueError as error:
                self.report_error(str(error))
                return
            self.poll_queue()

    def clear_queue(self):
        try:
            self.queue.clear()
        except ValueError as error:
            self.report_error(str(error))
            return
        self.poll_queue()

    def export_queue(self):
        try:
            path = self.choose_save('Экспорт очереди копий', 'packet-queue.json', 'json')
            if path:
                self.write_json(path, dict(mode='draft', repeats=self.repeat_spin.value(), interval_ms=self.interval_spin.value(), entries=self.queue.items()))
        except OSError as error:
            self.report_error(str(error))

    def poll_queue(self):
        rows = self.queue.items()
        signature = tuple((row.get('queue_id'), row.get('raw_hex')) for row in rows)
        if signature != self._queue_signature:
            self._queue_signature = signature
            self.queue_model.replace([dict(row, queue_position=index + 1) for index, row in enumerate(rows)])
        state = self.queue_runner.snapshot()
        sender = self.queue_runner.sender.status()
        blocked = self.queue_runner.validation_error(rows) if rows else None
        reason = blocked or (sender['reason'] if rows and not sender['available'] else None)
        available = sender['available'] and not self.self_test
        self.queue_start.setEnabled(bool(rows and available and not blocked and not state['active']))
        self.queue_start.setToolTip(self.t(reason) if reason else '')
        self.queue_pause.setEnabled(state['active'])
        self.queue_stop.setEnabled(state['active'])
        self.set_text(self.queue_pause, '▶  Продолжить' if state['paused'] else 'Ⅱ  Пауза')
        for control in (*self.queue_edit_buttons[:4], self.repeat_spin, self.interval_spin):
            control.setEnabled(not state['active'])
        states = {'idle': 'Готово', 'running': 'Отправка', 'paused': 'Пауза', 'stopped': 'Остановлено', 'completed': 'Завершено', 'failed': 'Ошибка'}
        self.queue_progress.setText(f"{self.t(states[state['state']])} · {state['completed']} / {state['total']} · "
                                    f"{self.t('Циклов')}: {state['cycle']}" + (f" · {state['error']}" if state['error'] else ''))
        self.set_text(self.queue_info, f"Копий: {len(rows)} · " + (reason or 'Добавляйте пакеты через ПКМ или редактор'))

    def start_packet_queue(self):
        try:
            self.queue_runner.start(self.repeat_spin.value(), self.interval_spin.value())
        except (ValueError, RuntimeError) as error:
            self.report_error(str(error))
        self.poll_queue()

    def choose_outgoing_packets(self):
        self.direction_combo.setCurrentIndex(self.direction_combo.findData('client'))
        self.tabs.setCurrentIndex(0)

    def report_error(self, message):
        self.show_status(message, 20000)
        if self.self_test:
            return
        QMessageBox.warning(self, 'L2 Packet Monitor', self.t(message))

    def closeEvent(self, event):
        if self._close_ready:
            self.client_icons.close()
            event.accept()
            return
        event.ignore()
        if self._closing:
            return
        self._closing = True
        self.timer.stop()
        self.library_debounce.stop()
        if not self.self_test:
            self.settings.setValue('geometry', self.saveGeometry())
            self.settings.setValue('splitter/packets', self.packet_splitter.saveState())
            self.settings.setValue('splitter/details', self.detail_splitter.saveState())
            self.settings.setValue('interface', self.interface_combo.currentData() or 'auto')
            self.settings.setValue('cipher', self.cipher_combo.currentData() or 'auto')
            self.settings.setValue('theme', self.theme)
            self.settings.setValue('language', self.language)
            self.settings.setValue('encoding', self.encoding_combo.currentText())
            self.settings.setValue('follow', self.follow.isChecked())
            self.settings.setValue('queue/repeats', self.repeat_spin.value())
            self.settings.setValue('queue/interval', self.interval_spin.value())
            self.settings.setValue('capture/source', self.source_combo.currentData())
            self.settings.setValue('uncheckedCategories', [key for key, item in self.category_items.items() if item.checkState(0) != Qt.CheckState.Checked])
            self.settings.setValue('uncheckedTypes', [key for key, item in self.type_items.items() if item.checkState(0) != Qt.CheckState.Checked])
            self.settings.remove('pid')
        self.set_text(self.state_label, 'Завершение захвата…')

        def shutdown():
            self.queue_runner.close()
            self.monitor.stop()
            self.monitor.skill_actions.close()
            self.monitor.newbie_buff.close()
            self.monitor.auto_heal.close()
            self.monitor.auto_pickup.close()
            self.monitor.inventory_drop.close()
        self.task(shutdown)


def self_test_samples():
    definitions = [
        ('server', '05', 'SpawnItem', 'item_spawn', {'event': 'spawn_item', 'object_id': 268478901, 'template_value': 4356, 'amount': 500, 'xyz': [83440, 148610, -3400]}, '170005D5B30010'),
        ('client', '1F', 'Action', 'target', {'event': 'action', 'object_id': 268478901, 'xyz': [83422, 148596, -3400]}, '10001FD5B30010'),
        ('server', '17', 'GetItem', 'item_pickup', {'event': 'get_item', 'object_id': 268478901, 'owner_id': 268456770}, '140017D5B30010'),
        ('server', '48', 'MagicSkillUse', 'combat', {'event': 'skill_use', 'skill_id': 1204, 'skill_level': 2}, '100048B404000002000000'),
        ('client', '0F', 'MoveBackwardToLocation', 'movement', {'xyz': [83440, 148610, -3400]}, '13000FF045010082440200B8F2FFFF'),
        ('server', '11', 'ItemList', 'inventory', {'event': 'inventory_update', 'items': [{'action': 1, 'action_name': 'added', 'object_id': 7001, 'item_id': 4356, 'slot': 8, 'amount': 500}]}, '0D0011010004110000F4010000'),
        ('server', 'FE F9 00', 'SkillList', 'skill_learning', {'skills': [{'skill_id': 1204, 'skill_level': 2}]}, '0A00FEF900B404000002'),
    ]
    result = []
    for index, (direction, opcode, name, category, fields, raw_hex) in enumerate(definitions, 1):
        raw = bytes.fromhex(raw_hex)
        raw = len(raw).to_bytes(2, 'little') + raw[2:]
        result.append(dict(id=index, direction=direction, opcode=opcode, name=name, category=category,
                           color=CATEGORIES[category][1], category_label=CATEGORIES[category][0], length=len(raw),
                           time=f'2026-11-21T18:42:{index:02d}.124+00:00', raw_hex=raw.hex(' ').upper(),
                           fields=fields, frame=index, session_id='native-ui-self-test', sha256=hashlib.sha256(raw).hexdigest()))
    return result


def run_ui_self_test(window, output, finish):
    """Exercise native controls with local fixtures, without populating capture storage."""
    target = Path(output) if output else DATA_ROOT / 'reports' / 'native-ui-self-test'
    report_path = target if target.suffix.lower() == '.json' else target / 'self-test.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = dict(native_widgets=True, capture_started=False, passed=False, checks=[], screenshots=[])
    window.set_text(window.mode_badge, 'SELF TEST · ЛОКАЛЬНЫЕ ОБРАЗЦЫ')
    samples = self_test_samples()
    expected_pid = window.selected_pid()

    def check(condition, description):
        if not condition:
            raise AssertionError(description)
        report['checks'].append(description)

    def complete():
        try:
            check(not window.queue_start.isEnabled(), 'Server send button stays disabled without transport')
            check(not window.queue_pause.isEnabled() and not window.queue_stop.isEnabled(), 'Queue playback controls stay disabled')
            check(not window.monitor.status()['running'], 'Capture remains stopped')
            window.poll_queue()
            saved_queue = window.queue.items()
            saved_repeats = window.repeat_spin.value()
            check(len(saved_queue) == 3, 'Queue stores three packet copies')
            check(window.queue_model.rowCount() == 3, 'Queue table shows three packet copies')
            check(saved_repeats == 2, 'Queue repeat setting can be staged')
            check(window.monitor.store.stats()['total'] == 0, 'Queue staging leaves capture store unchanged')
            check(not hasattr(window.queue, 'start'), 'Queue has no local playback mode')
            window.show_status('Готово')
            for language in ('ru', 'en'):
                window.apply_language(language, persist=False)
                check(window.language == language and window.language_combo.currentData() == language, 'Language switches to ' + language)
                if language == 'ru':
                    check(window.qt_translation_loaded, 'Russian Qt standard dialog translation loads')
                    report['qt_translation_path'] = window.qt_translation_path
                check(window.start_button.text() == translate('▶  Начать захват', language), 'Capture controls localized ' + language)
                check(window.network_button.text() == translate('Выбрать пакеты C → S', language), 'Queue outgoing-packet shortcut localized ' + language)
                check(window.packet_model.headerData(4, Qt.Orientation.Horizontal) == translate('Тип пакета', language), 'Table headers localized ' + language)
                check(window.proxy.data(window.proxy.index(0, 5)) == translate('Предмет рядом', language), 'Packet categories localized ' + language)
                check(window.selected_pid() == expected_pid, 'PID selection preserved ' + language)
                check(window.library_filters()['server'] is None, 'All-server filter works ' + language)
                if language == 'en':
                    untranslated = [widget.text() for widget in window.findChildren(QWidget) if isinstance(widget, (QLabel, QPushButton, QCheckBox)) and widget.isVisible() and re.search('[А-Яа-яЁё]', widget.text())]
                    check(not untranslated, 'English visible controls contain no untranslated Russian: ' + repr(untranslated))
                for theme in ('dark', 'light'):
                    window.apply_theme(theme, persist=False)
                    check(window.theme == theme and window.theme_combo.currentData() == theme, 'Theme switches to ' + language + '/' + theme)
                    for index, name in enumerate(('packets', 'world', 'library', 'inventory', 'queue', 'options', 'skills', 'catalog', 'sources')):
                        window.poll_health()
                        window.poll_buffs()
                        if name == 'skills':
                            window.poll_skills()
                        if name == 'catalog':
                            window.poll_client_catalog()
                        if name == 'sources':
                            window.poll_sources()
                        window.tabs.setCurrentIndex(index)
                        QApplication.processEvents()
                        if name == 'options':
                            previous_size = window.size()
                            window.resize(1400, 900)
                            QApplication.processEvents()
                            scroll = window.tabs.widget(index)
                            check(isinstance(scroll, QScrollArea), 'Additional options has a scrollable viewport ' + language + '/' + theme)
                            check(all(widget.height() >= widget.minimumSizeHint().height() for widget in
                                      (window.pickup_radius, window.pickup_interval, window.buff_count, window.buff_start)),
                                  'Options inputs retain their readable height at 1400x900 ' + language + '/' + theme)
                            check(window.pickup_interval.y() >= window.pickup_radius.geometry().bottom(),
                                  'Pickup fields do not overlap at 1400x900 ' + language + '/' + theme)
                            check(scroll.verticalScrollBar().maximum() > 0,
                                  'Short options viewport scrolls instead of crushing controls ' + language + '/' + theme)
                            scroll.ensureWidgetVisible(window.buff_count)
                            QApplication.processEvents()
                            position = window.buff_count.mapTo(scroll.viewport(), window.buff_count.rect().topLeft())
                            check(scroll.viewport().rect().contains(position)
                                  and scroll.viewport().rect().contains(position + window.buff_count.rect().bottomRight()),
                                  'Newbie Buff controls remain reachable by scrolling ' + language + '/' + theme)
                            scroll.verticalScrollBar().setValue(0)
                            window.grab().save(str(report_path.parent / f'native-options-small-{language}-{theme}.png'))
                            window.resize(previous_size)
                            QApplication.processEvents()
                        if language == 'en':
                            untranslated = [widget.text() for widget in window.findChildren(QWidget) if isinstance(widget, (QLabel, QPushButton, QCheckBox)) and widget.isVisible() and re.search('[А-Яа-яЁё]', widget.text())]
                            check(not untranslated, 'English tab fully localized ' + theme + '/' + name + ': ' + repr(untranslated))
                        check(window.creator_label.isVisible() and window.creator_label.text() == 'Made by Vektor T13', 'Creator credit visible on ' + language + '/' + theme + '/' + name)
                        image_path = report_path.parent / f'native-{name}-{language}-{theme}.png'
                        check(window.grab().save(str(image_path)), 'Native screenshot ' + language + '/' + theme + '/' + name)
                        report['screenshots'].append(str(image_path))
            window.apply_language('ru', persist=False)
            check(window.tabs.count() == 9 and window.tabs.tabText(8) == 'Источники',
                  'Sources is the ninth tab and preserves the existing tab indices')
            check([window.source_combo.itemData(i) for i in range(window.source_combo.count())]
                  == ['auto', 'network', 'client', 'server'], 'Sources exposes all four capture modes')
            source_fixture = {
                'mode': 'auto', 'active_source': 'server', 'client_tap_supported': False,
                'algorithms': [{'id': 'l2xor16-u64'}, {'id': 'asterios'}],
                'profiles': [{'id': 'fixture-build', 'engine_sha256': 'a' * 64,
                              'algorithm': 'l2xor16-u64', 'validation': 'verified',
                              'client_tap_supported': False, 'protocol': 'classic-h5'}],
                'bridge': {'running': False, 'endpoint': 'http://127.0.0.1:16600',
                           'received': 7, 'dropped': 0, 'sessions': [{'id': 'fixture'}],
                           'active_session': {'id': 'fixture', 'protocol': 'classic-h5'},
                           'token': 'self-test-secret-must-stay-hidden'},
            }
            window.poll_sources(source_fixture)
            check(window.source_profiles_model.rowCount() == 1 and window.source_profiles_model.columnCount() == 6,
                  'Sources renders the saved profile metadata in six read-only columns')
            check(window.source_profiles_model.rows[0]['engine_sha256'] == 'a' * 64,
                  'Source profile display preserves the full client fingerprint')
            check(window.source_profiles_model.rows[0]['client_tap'] == 'Не подключён',
                  'Missing client plaintext adapter is shown without claiming support')
            check('classic-h5' in window.source_active.text(), 'Sources shows the server producer protocol')
            check('self-test-secret' not in window.bridge_status.text(), 'Bridge status never displays the authentication token')
            check(not window.bridge_start_button.isEnabled() and not window.bridge_export_button.isEnabled(),
                  'Source self-test does not start the server bridge or export files')
            window.source_combo.setCurrentIndex(window.source_combo.findData('client'))
            window.poll_sources({})
            check('нет проверенного адаптера' in window.source_message.text(),
                  'Explicit client mode explains an unavailable plaintext adapter')
            window.source_combo.setCurrentIndex(window.source_combo.findData('auto'))
            window.poll_sources()
            preferences = QSettings(str(report_path.parent / 'preferences.ini'), QSettings.Format.IniFormat)
            original_settings, original_self_test = window.settings, window.self_test
            try:
                window.settings, window.self_test = preferences, False
                window.apply_language('en')
                window.apply_theme('light')
                check(preferences.value('language') == 'en' and preferences.value('theme') == 'light', 'Language and theme preferences persist')
                check(QSettings(str(report_path.parent / 'preferences.ini'), QSettings.Format.IniFormat).value('language') == 'en', 'Language preference reloads')
                preferences.setValue('pid', 99999999)
                window._restore(None, 'auto', 'auto')
                check(window.selected_pid() is None, 'Stale saved PID never pins automatic discovery after restart')
                window._restore(65124, 'auto', 'auto')
                check(window.selected_pid() == 65124, 'An explicitly requested client PID still takes precedence')
            finally:
                window.settings, window.self_test = original_settings, original_self_test
            window.apply_language('ru', persist=False)
            window.apply_theme('dark', persist=False)
            window.tabs.setCurrentIndex(4)
            QApplication.processEvents()
            window.grab().save(str(report_path.parent / 'native-queue.png'))
            window.tabs.setCurrentIndex(0)
            window.packet_table.selectRow(0)
            window.load_packet(samples[0])
            check(not QApplication.instance().windowIcon().isNull(), 'Application icon loads')
            check(not window.windowIcon().isNull(), 'Window and taskbar icon loads')
            registry = CipherProfiles()
            classic_profile = registry.load_profile('557c9f6d4f8bed1d517c38d9746d0b1895a440a32ce234f6e40067e6267efb24')
            check(classic_profile and classic_profile['algorithm'] == 'l2xor16-u64', 'Saved classic cipher profile loads from packaged data')
            check(registry.find('f9632145da8b27fcff5c22257c0a2b909e25e02825ba7e82f61a5dfd68c9b665')['algorithm'] == 'asterios',
                  'Registering the new client preserves the verified Asterios profile')
            check(bool(window.windowFlags() & Qt.WindowType.FramelessWindowHint), 'Custom frame replaces Windows title bar')
            window.toggle_maximized()
            check(window.isMaximized(), 'Custom maximize control')
            window.toggle_maximized()
            check(not window.isMaximized(), 'Custom restore control')
            window.queue.clear()
            report['passed'] = True
        except Exception:
            report['error'] = traceback.format_exc()
        finally:
            MonitorWindow.write_json(report_path, report)
            finish(0 if report['passed'] else 1)

    def begin():
        try:
            window.packet_model.replace(samples)
            window.packet_table.selectRow(0)
            window.load_packet(samples[0])
            window.monitor.inventory.reset('native-ui-self-test')
            window.monitor.inventory.apply([samples[5]])
            window.poll()
            check(window.inventory_model.rowCount() == 1, 'Inventory table renders observed item')
            check(not window.inventory_model.data(window.inventory_model.index(0, 1), Qt.ItemDataRole.DecorationRole).isNull(),
                  'Inventory loads the original item icon from the bundled archive')
            window.inventory_table.selectRow(0)
            window.copy_inventory_id()
            check(QApplication.clipboard().text() == '4356', 'Inventory item ID can be copied for manual action')
            check(window.inventory_table.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu,
                  'Inventory table exposes a manual-action context menu')
            check(window.inventory_auto_open.isChecked() and window.monitor.auto_inventory_enabled,
                  'Inventory auto-opening is enabled by default')
            window.inventory_auto_open.setChecked(False)
            check(not window.monitor.auto_inventory_enabled, 'Inventory auto-opening can be disabled')
            window.inventory_auto_open.setChecked(True)
            dialog = window.inventory_drop_dialog(dict(window.inventory_model.rows[0]), 'single')
            check(dialog.findChild(QComboBox, 'dropMode').currentData() == 'single',
                  'Inventory drop dialog supports one-at-a-time mode')
            check(dialog.findChild(QSpinBox, 'dropInterval').isEnabled(),
                  'Sequential inventory drops expose a delay after confirmation')
            dialog.findChild(QLineEdit, 'dropAmount').setText('2')
            captured_drops = []
            enqueue = window.monitor.inventory_drop.enqueue
            window.monitor.inventory_drop.enqueue = lambda *args: captured_drops.append(args)
            try:
                box = dialog.findChild(QDialogButtonBox)
                next(control for control in box.buttons() if box.buttonRole(control) == QDialogButtonBox.ButtonRole.AcceptRole).click()
            finally:
                window.monitor.inventory_drop.enqueue = enqueue
            check(captured_drops == [(7001, 2, 'single', 500)],
                  'Inventory drop dialog submits object ID, quantity, mode and delay')
            check(dialog.result() == QDialog.DialogCode.Accepted, 'Inventory drop dialog accepts the queued action')
            dialog.deleteLater()
            check(window.tabs.tabText(5) == window.t('Дополнительные опции'), 'Additional options has its own tab')
            check(not window.pickup_enabled.isChecked() and not window.monitor.auto_pickup.enabled,
                  'Automatic pickup is disabled by default')
            window.pickup_enabled.setChecked(True)
            check(window.monitor.auto_pickup.enabled, 'Automatic pickup checkbox enables the worker')
            window.pickup_enabled.setChecked(False)
            check(not window.monitor.auto_pickup.enabled, 'Automatic pickup checkbox disables the worker')
            window.monitor.auto_pickup.close()
            window.monitor.skills.reset('native-ui-self-test')
            window.monitor.skills.apply([dict(direction='server', fields=dict(event='skill_list', skills=[
                dict(skill_id=1204, skill_level=2, passive=0, disabled=0)]))])
            window.poll_skills()
            check(window.tabs.tabText(6) == window.t('Скиллы'), 'Owned skills has its own tab')
            check(window.skills_model.rowCount() == 1 and window.skills_model.rows[0]['skill_level'] == 2,
                  'Skills table renders the owned server level')
            check(window.skills_model.rows[0]['skill_name'] == 'Wind Walk', 'Owned skills resolve exact-level names from full client database')
            check(not window.skills_model.data(window.skills_model.index(0, 1), Qt.ItemDataRole.DecorationRole).isNull(),
                  'Owned skills load the exact-level client icon')
            window.skills_search.setText('wind')
            check(window.skills_model.rowCount() == 1, 'Owned skills can be searched by name')
            window.skills_search.setText('unmatched skill')
            check(window.skills_model.rowCount() == 0, 'Skill search excludes nonmatching names')
            window.skills_search.clear()
            check(window.tabs.tabText(7) == window.t('База клиента'), 'Complete client database has its own tab')
            check(window.catalog_model.rowCount() == 1000, 'Client item database paginates all entries')
            window.catalog_kind.setCurrentIndex(1)
            window.catalog_search.setText('1068')
            check(window.catalog_model.rowCount() > 0 and all(row['id'] == 1068 for row in window.catalog_model.rows),
                  'Client database finds unowned skills and buffs by ID at every level')
            check(all(row['name'] == 'Might' for row in window.catalog_model.rows), 'Buff database names come from client records')
            check(not window.catalog_model.data(window.catalog_model.index(0, 1), Qt.ItemDataRole.DecorationRole).isNull(),
                  'Complete client database displays the original buff icon')
            window.catalog_search.clear()
            window.catalog_kind.setCurrentIndex(0)
            check(window.skills_table.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu,
                  'Skills table exposes the learning context menu')
            original_status, original_self_test = window.monitor.status, window.self_test
            window.self_test = False
            window.monitor.status = lambda: dict(running=True, state='live', actions_supported=False,
                                                 skill_actions_supported=True)
            try:
                check(window.can_learn_skill(), 'Skill controls allow verified skill capability independently of other actions')
                window.monitor.status = lambda: dict(running=True, state='live', actions_supported=False,
                                                     skill_actions_supported=False)
                check(not window.can_learn_skill(), 'Skill controls remain disabled when the skill handler is unavailable')
            finally:
                window.monitor.status, window.self_test = original_status, original_self_test
            original_queue = window.queue.items()
            window.queue.clear()
            window.queue.add(dict(raw_hex='030050', direction='client'))
            window.self_test = False
            window.monitor.status = lambda: dict(running=True, state='live', actions_supported=False,
                detected_cipher='l2xor16-u64', profile='l2-highfive-xor64-557c9f6d')
            try:
                window.poll_queue()
                check(window.queue_start.isEnabled(), 'Queue sends C-to-S with its verified transport despite other actions being unavailable')
                previous_tab, previous_direction = window.tabs.currentIndex(), window.direction_combo.currentIndex()
                window.network_button.click()
                check(window.tabs.currentIndex() == 0 and window.direction_combo.currentData() == 'client',
                      'Queue shortcut opens capture filtered to outgoing client requests')
                window.direction_combo.setCurrentIndex(previous_direction)
                window.tabs.setCurrentIndex(previous_tab)
                window.queue.add(dict(raw_hex='030050', direction='server'))
                window.poll_queue()
                check(not window.queue_start.isEnabled(), 'Queue rejects a server-direction row before sending')
                check('S→C' in window.queue_info.text(), 'Queue visibly explains an invalid incoming packet')
                check('S→C' in window.queue_start.toolTip(), 'Disabled queue button explains its reason')
            finally:
                window.monitor.status, window.self_test = original_status, original_self_test
                window.queue.clear()
                for row in original_queue:
                    window.queue.add(row)
                window.poll_queue()
            dialog = window.skill_learn_dialog(window.skills_model.rows[0])
            dialog.findChild(QSpinBox, 'skillLevel').setValue(5)
            learned = []
            original_learn = window.monitor.skill_actions.learn
            window.monitor.skill_actions.learn = lambda *args: learned.append(args)
            try:
                dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok).click()
            finally:
                window.monitor.skill_actions.learn = original_learn
            check(learned == [(1204, 5)], 'Skill dialog submits the selected ID and entered target level')
            check(dialog.result() == QDialog.DialogCode.Accepted, 'Skill dialog OK accepts the action')
            dialog.deleteLater()
            dialog = window.skill_learn_dialog(custom=True)
            dialog.findChild(QSpinBox, 'customSkillId').setValue(9999)
            dialog.findChild(QSpinBox, 'skillLevel').setValue(7)
            learned.clear()
            window.monitor.skill_actions.learn = lambda *args: learned.append(args)
            try:
                dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok).click()
            finally:
                window.monitor.skill_actions.learn = original_learn
            check(learned == [(9999, 7)], 'Custom skill dialog submits the typed ID and level without a table selection')
            check(dialog.result() == QDialog.DialogCode.Accepted, 'Custom skill dialog OK accepts the action')
            dialog.deleteLater()
            window.monitor.auto_heal.health = dict(character='X501', level=21, hp=79, max_hp=100, hp_percent=79)
            window.monitor.auto_heal.names = {4356: 'Gold Einhasad'}
            window.monitor.auto_heal.potions = [dict(item_id=1061, name='Greater Healing Potion', amount=33),
                                               dict(item_id=8622, name='Elixir of Life (No Grade)', amount=10)]
            window.poll_health()
            check('X501' in window.character_label.text() and '21' in window.character_label.text(),
                  'Global character panel renders the observed name and level')
            check(window.character_hp.value() == 790 and '79 / 100' in window.character_hp.format(),
                  'Global character panel renders current HP, maximum and percentage')
            check(window.heal_potion.count() == 2 and 'Greater Healing Potion' in window.heal_potion.itemText(0),
                  'Auto-heal combo renders real potion names and amounts')
            check(not window.heal_potion.itemIcon(0).isNull(), 'Auto-heal selection displays the original potion icon')
            window.monitor.character.apply([dict(direction='server', fields=dict(
                event='self_info', object_id=123, character='X501', level=21, hp=79, max_hp=100,
                mp=50, max_mp=80, cp=20, max_cp=40, str=35, dex=23, con=46, int=36, wit=22, men=43,
                p_atk=1200, p_def=2400, m_atk=900, m_def=1800, attack_speed=800, casting_speed=600))])
            window.poll_health()
            check(not window.character_stats.isHidden() and all(str(value) in window.character_stats.text()
                  for value in (35, 23, 46, 36, 22, 43, 1200, 2400, 900, 1800)),
                  'Server character state renders core and combat stats in the global panel')
            check('50 / 80' in window.character_mp.format() and '20 / 40' in window.character_cp.format()
                  and window.character_hp.value() == 790 and window.character_mp.value() == 625 and window.character_cp.value() == 500,
                  'Server character state renders MP and CP while preserving live HP')
            check(window.character_label.font().bold(), 'Character identity uses a bold font')
            check(window.character_cp.y() < window.character_hp.y() < window.character_mp.y()
                  and window.character_cp.x() == window.character_hp.x() == window.character_mp.x(),
                  'CP, HP and MP bars form a left-aligned vertical stack')
            check(all(row['bar'].x() < row['enabled'].x() < row['potion'].x() < row['threshold'].x()
                      < row['interval'].x() < row['toggle'].x() for row in window.recovery_widgets.values()),
                  'Every resource has recovery controls immediately on its right')
            check(not window.heal_enabled.isChecked(), 'Automatic healing is off by default')
            check(window.heal_interval.value() == 11 and window.monitor.auto_heal.interval_ms == 11000,
                  'Automatic healing uses the requested eleven-second interval by default')
            window.heal_enabled.setChecked(True)
            check(not window.monitor.auto_heal.enabled, 'Arming recovery alone does not start consuming potions')
            window.recovery_widgets['hp']['toggle'].click()
            check(window.monitor.auto_heal.enabled and window.monitor.auto_heal.item_id == 1061,
                  'Automatic healing checkbox uses the selected potion ID')
            window.heal_threshold.setValue(75)
            check(window.monitor.auto_heal.threshold == 75, 'Automatic healing exposes an editable threshold')
            window.heal_enabled.setChecked(False)
            check(not window.monitor.auto_heal.enabled and not window.recovery_widgets['hp']['toggle'].isChecked(),
                  'Unchecking recovery stops its running toggle')
            window.monitor.recovery['mp'].potions = [dict(item_id=728, name='Mana Potion', amount=10)]
            window.monitor.recovery['cp'].potions = [dict(item_id=5592, name='Greater CP Potion', amount=10)]
            window.poll_health()
            window.recovery_widgets['mp']['threshold'].setValue(60)
            window.recovery_widgets['mp']['interval'].setValue(3)
            window.recovery_widgets['mp']['toggle'].click()
            window.recovery_widgets['cp']['toggle'].click()
            check(window.monitor.recovery['mp'].enabled and window.monitor.recovery['cp'].enabled
                  and not window.monitor.auto_heal.enabled and window.monitor.recovery['mp'].threshold == 60
                  and window.monitor.recovery['mp'].interval_ms == 3000 and window.monitor.recovery['cp'].threshold == 80,
                  'CP and MP toggles, potion choices, thresholds and intervals operate independently of HP')
            for resource in ('mp', 'cp'):
                window.recovery_widgets[resource]['toggle'].click()
            check(not any(channel.enabled for channel in window.monitor.recovery.values()),
                  'Stopping each resource disables all recovery channels')
            window.heal_threshold.setValue(80)
            window.inventory_search.setText('Gold')
            window.poll()
            check(window.inventory_model.rowCount() == 1 and window.inventory_model.rows[0]['item_name'] == 'Gold Einhasad',
                  'Inventory search uses client item names')
            window.inventory_search.setText('missing-item')
            window.poll()
            check(window.inventory_model.rowCount() == 0, 'Inventory name search hides nonmatching rows')
            window.inventory_search.clear()
            window.poll()
            calls = []
            original_start = window.monitor.newbie_buff.start
            window.monitor.newbie_buff.start = lambda count: calls.append(count)
            try:
                window.buff_count.setValue(10)
                window.buff_start.setEnabled(True)
                window.buff_start.click()
            finally:
                window.monitor.newbie_buff.start = original_start
            check(calls == [10], 'Newbie Buff Start submits the typed repetition count once')
            check(window.proxy.rowCount() == len(samples), 'Packet table renders local fixtures')
            window.search.setText('MagicSkillUse')
            check(window.proxy.rowCount() == 1, 'Packet search filters rows')
            window.reset_filters()
            window.category_items['combat'].setCheckState(0, Qt.CheckState.Unchecked)
            check(window.proxy.rowCount() == len(samples) - 1, 'Category checkboxes filter rows')
            window.reset_filters()
            window.hex_edit.setPlainText('00 00 05 FF 00 80 D0 90')
            window.fix_length()
            converted = window.conversion()
            check(converted['length_matches'], 'u16 length repair')
            check(window.conversion('text-to-hex')['hex'] == converted['hex'], 'HEX and text preserve bytes')
            for encoding in ENCODINGS:
                window.encoding_combo.setCurrentText(encoding)
                check(window.conversion('text-to-hex')['hex'] == converted['hex'], 'Lossless encoding ' + encoding)
            window.encoding_combo.setCurrentText('utf-8')
            window.load_packet(samples[0])
            copy_packet, _ = window.edited_copy()
            check(copy_packet['raw_hex'] == samples[0]['raw_hex'], 'Editor holds a packet copy')
            for packet in samples[:3]:
                window.queue.add(packet)
            window.poll_queue()
            check(window.queue_model.rowCount() == 3, 'Queue accepts packet copies')
            window.packet_table.selectRow(0)
            packet_png = report_path.parent / 'native-packets.png'
            window.grab().save(str(packet_png))
            report['screenshots'].append(str(packet_png))
            window.repeat_spin.setValue(2)
            window.interval_spin.setValue(60)
            window.tabs.setCurrentIndex(4)
            QTimer.singleShot(100, complete)
        except Exception:
            report['error'] = traceback.format_exc()
            MonitorWindow.write_json(report_path, report)
            finish(1)
    def runtime_checks():
        profile = live_state.load_profile()
        if not getattr(sys, 'frozen', False):
            runtime_path = live_state.ROOT / profile['runtime_path']
            if str(runtime_path) not in sys.path:
                sys.path.insert(0, str(runtime_path))
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
        from .protocol import Catalog
        from .npcap import interfaces
        emulator = Uc(UC_ARCH_X86, UC_MODE_32)
        emulator.mem_map(0x1000, 0x1000)
        emulator.mem_write(0x1000, b'\x90')
        emulator.emu_start(0x1000, 0x1001)
        catalog = Catalog()
        adapters = interfaces()
        diagnostic = catalog.packet('client', bytes.fromhex(
            '1c00ff0402434d5046303a203642384331314144205b307835305d00'), 0, 1, 'self-test')
        from .diagnostic_audit import audit_files
        from .inventory_drop import check_drop_bridge
        from .client_tap import check_client_tap
        return dict(unicorn_x86=True, catalog_entries=len(catalog.names),
                    profile=profile['id'], interfaces=len(adapters),
                    cmpf0_fields=diagnostic['fields'],
                    audit_schema=audit_files([])['schema'], native_inventory_bridge=check_drop_bridge(),
                    native_plaintext_capture=check_client_tap(),
                    server_sdk_bundled=all((live_state.ROOT/'src/server_bridge_sdk'/name).is_file()
                        for name in ('L2PlaintextBridge.java','bridge_sender.py','README.md')))

    def runtime_complete(result):
        try:
            report['runtime'] = result
            check(result['unicorn_x86'], 'Unicorn x86 dynamic architecture initializes and executes')
            check(result['catalog_entries'] > 0, 'Bundled opcode catalog loads')
            check(bool(result['profile']), 'Bundled monitor profile loads')
            check(result['native_inventory_bridge'], 'Bundled inventory bridge verifies drop, pickup and radius in its own mock client')
            check(result['native_plaintext_capture'], 'Bundled plaintext adapter verifies capture, unchanged cipher calls, drops, detach and restart in its own mock client')
            check(result['server_sdk_bundled'], 'Portable Java and Python server adapters are bundled')
            check(result['interfaces'] >= 0, 'Npcap interface enumeration completes without opening capture')
            check(result['cmpf0_fields'].get('diagnostic_value') == '0x6B8C11AD',
                  'Recorded CMPF0 diagnostic value parses without address attribution')
            check(result['cmpf0_fields'].get('reported_opcode') == '0x50',
                  'Recorded CMPF0 diagnostic opcode parses')
            check(result['audit_schema'] == 'l2-client-diagnostic-audit-v1',
                  'Saved JSONL diagnostic audit module loads')
            QTimer.singleShot(150, begin)
        except Exception as error:
            runtime_error(str(error))

    def runtime_error(message):
        report['error'] = 'Runtime dependency check: ' + message
        MonitorWindow.write_json(report_path, report)
        finish(1)
    QTimer.singleShot(100, lambda: window.task(runtime_checks, runtime_complete, runtime_error))
