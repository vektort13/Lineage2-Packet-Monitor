# Сборка и разработка

[Главная](../README.ru.md) · **Русский** · [English](BUILD.en.md) · [Руководство пользователя](guides/USER_GUIDE.ru.md)

## Инструменты

Нужны Windows x64, Python **3.12**, Visual Studio / Build Tools с компонентами **«Разработка классических приложений на C++»**, инструментами MSVC x86/x64 и Windows SDK. Приложение собирается в x64, адаптеры соответствующих игровых клиентов — в x86.

Закреплённые зависимости: PySide6 Essentials 6.12.0, psutil 7.2.2 и Unicorn 2.1.4. В `requirements-dev.txt` добавлены PyInstaller и средства работы с изображениями/протоколом. JDK Java 8+ включает тест Java SDK; для сборки самого приложения он необязателен.

## Чистое окружение

```powershell
git clone https://github.com/vektort13/L2PacketMonitor.git
cd L2PacketMonitor
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Репозиторий содержит полный каталог предметов/умений, архив иконок, оба профиля сборок, нативные исходники, серверный SDK и примеры протокола. Unicorn берётся из установленного wheel-пакета. Локальные исследовательские снимки для чистой сборки приложения не нужны.

## Запуск из исходников

Сначала скомпилируйте нативные модули:

```powershell
.\packaging\build_drop.cmd
.\packaging\build_tap.cmd
.\.venv\Scripts\python.exe src\desktop.py --no-autostart
```

`packaging/vcvars_x86.cmd` находит Visual Studio через `vswhere.exe` и подключает x86-компилятор. Можно также использовать уже открытое x86 developer-окружение.

Для сетевого захвата установите [Npcap](https://npcap.com/#download). Основное приложение обращается к драйверу напрямую. Старый браузерный интерфейс запускается командой `python src\monitor.py --open`; некоторые исследовательские скрипты используют отдельно установленный TShark.

## Сборка EXE

```powershell
.\.venv\Scripts\python.exe packaging\build.py --dist-dir dist
```

Скрипт компилирует нативные модули, подготавливает конфигурацию, включает русский перевод Qt, упаковывает программу через [PyInstaller](https://pyinstaller.org/en/stable/usage.html) и запускает встроенную проверку. Результат — `dist\L2PacketMonitor.exe`; временные файлы и spec находятся в `build/`.

В EXE входят Python, Qt, Unicorn, нативные модули, иконки, база клиента и серверный SDK. Npcap устанавливается отдельно.

## Проверки

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools\verify_repository.py
.\dist\L2PacketMonitor.exe --self-test --no-api --self-test-output reports\local-self-test
```

Тесты проверяют границы пакетов, шифры, источники, очереди, инвентарь, персонажа, восстановление, серверный мост и нативный захват на тестовом процессе. Встроенная проверка EXE проверяет зависимости, нативные модули, интерфейс, языки и темы без запуска игрового захвата. Она сохраняет `self-test.json` и скриншоты. Windows CI запускает проверки логики, нативного адаптера и ресурсов репозитория.

## Файлы релиза

`L2PacketMonitor.exe` доступен для прямого скачивания. Windows ZIP содержит программу, руководства и изображения документации. Архив исходников включает все отслеживаемые файлы и списки зависимостей. В `SHA256SUMS.txt` записаны контрольные суммы релиза.

## Структура

| Папка | Назначение |
|---|---|
| `src/l2_monitor` | Интерфейс, захват, протокол и модели |
| `src/native_probe` | x86-адаптер и модули действий |
| `src/server_bridge_sdk` | Серверная интеграция Java/Python |
| `config`, `assets` | Профили, таблицы, база клиента и иконки |
| `tests/fixtures` | Воспроизводимые примеры протокола |
| `packaging` | Сборка, поиск компилятора, иконка и версия |
| `web` | Браузерный интерфейс для разработки |
| `docs` | Руководства и исторические технические материалы |
| `reports` | Локальные захваты и подтверждения, исключены из Git |

В исторических материалах пути к локальным подтверждениям сохранены как текст. Опубликованные результаты проверок: [verification/README.md](verification/README.md).
