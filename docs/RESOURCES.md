# Resources / Ресурсы

[Home](../README.md) · [Главная](../README.ru.md)

The EXE bundles the full client catalog and icon archive, both saved build profiles, the cipher registry, opcode table, native helpers, server SDK and application icon. All application resources are included in this repository or built from its sources.

В EXE входят полная база клиента и архив иконок, оба профиля сборок, реестр шифров, таблица opcode, нативные модули, серверный SDK и иконка программы. Все ресурсы приложения включены в репозиторий либо собираются из его исходников.

| Resource / Ресурс | Count / Количество |
|---|---|
| Items / Предметы | 28,690 |
| Skill/buff levels / Уровни скиллов и бафов | 84,004 |
| PNG icons / Иконки PNG | 4,751 |
| Client profiles / Профили клиентов | 2 |
| Cipher implementations / Реализации шифров | 4 |
| UI screenshots / Снимки интерфейса | 36 |
| Thematic illustrations / Тематические иллюстрации | 2 |

## Runtime asset checksums / Контрольные суммы

The complete machine-readable list includes all 36 screenshots: [resource-manifest.json](resource-manifest.json).

Полный машиночитаемый список, включая все 36 скриншотов: [resource-manifest.json](resource-manifest.json).

| File / Файл | Bytes / Байт | SHA-256 |
|---|---:|---|
| [assets/client-icons.zip](../assets/client-icons.zip) | 10185944 | `453156f00bec41db645cc9437941d731d449bb09db44b7a2c7f7eb89322b1c29` |
| [config/cipher-profiles.json](../config/cipher-profiles.json) | 2908 | `f508f92f30434a2225771fc46533ea2b84d90838ae29674d406b217c6a929859` |
| [config/client-catalog.json](../config/client-catalog.json) | 16954486 | `aede747f68b4294eb651987b715dda629c5419533b0d37d070ce580b18abafe0` |
| [config/clients/l2-highfive-557c9f6d.json](../config/clients/l2-highfive-557c9f6d.json) | 2771 | `d31fa7889054f8bd6f7861dd5916d26ed6a93b0a3d3145beddfb7874204150dc` |
| [config/monitor-profile.json](../config/monitor-profile.json) | 14687 | `b28be515c1ace31fa2d842f9073117f46855fc975d872cc3946a7003863b1fc7` |
| [config/opcodes-448.csv](../config/opcodes-448.csv) | 57516 | `177f5c75be0f48c75a98732bd813d28f37767f96c167b21574555bfb5626dcb1` |
| [docs/assets/cover.png](../docs/assets/cover.png) | 2336151 | `8f811a3da3b5d4b43183200abf6fcb81c2354532278022b530399fb291f4fcb9` |
| [docs/assets/field-guide.png](../docs/assets/field-guide.png) | 2819164 | `311064bd926da0f576d06aa525f35b0789d5a52bdb42c56b8514ccac126ac4e7` |
| [packaging/L2PacketMonitor.ico](../packaging/L2PacketMonitor.ico) | 24132 | `13970dada948ab06c078ea59b639e67aca76b6c5353cdf1641432d51fb610ae3` |

## Native modules / Нативные модули

| Output / Результат | Sources / Исходники |
|---|---|
| `drop_controller.exe`, `drop_hook.dll` | [src/native_probe](../src/native_probe/) |
| `tap_controller.exe`, `tap_hook_v2.dll` | [src/native_probe](../src/native_probe/) |

Build commands / команды: [English](BUILD.en.md), [русский](BUILD.ru.md).

The source/resource release archive contains every tracked file. Working captures, process memory snapshots, machine inventory and intermediate build products remain local. The pinned Python dependencies are installed with pip.

Архив исходников и ресурсов содержит каждый отслеживаемый файл. Рабочие захваты, снимки памяти, инвентаризация ПК и промежуточные продукты сборки остаются локально. Закреплённые Python-зависимости устанавливаются через pip.
