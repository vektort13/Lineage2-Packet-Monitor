# Release verification / Проверки релиза

[Home](../../README.md) · [Главная](../../README.ru.md)

The release EXE is the existing ready-to-run application from `dist-update-itemlist/L2PacketMonitor.exe`. Its SHA-256 is `fba37162d9d9e5f23c95f020bb99fbe643417449358a81fc8ce455fa4f762513`, matching the saved successful 236-check UI/native report.

В релиз включён готовый EXE из `dist-update-itemlist/L2PacketMonitor.exe`. Его SHA-256 — `fba37162d9d9e5f23c95f020bb99fbe643417449358a81fc8ce455fa4f762513`, что совпадает с сохранённым успешным отчётом 236 проверок интерфейса и нативных модулей.

| Check / Проверка | Evidence / Результат |
|---|---|
| Complete local logic/native suite / Полные локальные тесты | [unit-tests.json](unit-tests.json) |
| Recorded verification of the exact release EXE / Сохранённая проверка этого EXE | [self-test.json](self-test.json) |
| Recheck in the current Windows session / Повтор в текущем сеансе Windows | [current-session-self-test.json](current-session-self-test.json) |
| Assets, checksums and links / Ресурсы, суммы и ссылки | [repository-check.txt](repository-check.txt) |

The self-test uses fixtures and native mock processes without starting game capture. Live-client experiments are documented separately in the historical notes.

Встроенная проверка использует примеры протокола и нативные тестовые процессы без захвата игры. Опыты с живым клиентом описаны отдельно в исторических материалах.

## Current session / Текущий сеанс

The existing release EXE starts. Its current-session self-test stops during native hook installation; a diagnostic rebuild identifies `SetWindowsHookExW` error 126 at the `install-hook` stage. Tests succeeded for previously registered module images and failed for new copies. A session hook-module resource limit is a working hypothesis. Both the recorded successful report and the current failed recheck are retained above.

Готовый EXE запускается. Повторная проверка в текущем сеансе останавливается при установке нативного hook; диагностическая сборка показывает ошибку `SetWindowsHookExW` 126 на этапе `install-hook`. Проверки проходили для ранее зарегистрированных образов модулей и не проходили для новых копий. Ограничение ресурсов таблицы hook-модулей — рабочая гипотеза. Выше сохранены и успешный исходный отчёт, и текущий неуспешный повтор.
