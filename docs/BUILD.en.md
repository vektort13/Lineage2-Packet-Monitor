# Build and development

[Home](../README.md) · **English** · [Русский](BUILD.ru.md) · [User guide](guides/USER_GUIDE.en.md)

## Toolchain

Use Windows x64, Python **3.12** and Visual Studio / Build Tools with **Desktop development with C++**, the MSVC x86/x64 tools and a Windows SDK. The desktop EXE is x64; the matched game adapters are compiled as x86.

The pinned runtime is PySide6 Essentials 6.12.0, psutil 7.2.2 and Unicorn 2.1.4. `requirements-dev.txt` adds PyInstaller and the image/protocol analysis dependencies. Java 8+ JDK enables the Java SDK test; it is optional for the desktop build.

## Fresh checkout

```powershell
git clone https://github.com/vektort13/L2PacketMonitor.git
cd L2PacketMonitor
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

The repository includes the complete item/skill catalog, icon ZIP, both build profiles, native sources, server SDK and protocol fixtures. Building uses the installed Unicorn wheel. The original research snapshots are not required for a fresh desktop build.

## Run from source

Compile the native helpers once:

```powershell
.\packaging\build_drop.cmd
.\packaging\build_tap.cmd
.\.venv\Scripts\python.exe src\desktop.py --no-autostart
```

`packaging/vcvars_x86.cmd` locates Visual Studio through `vswhere.exe` and initializes the x86 toolchain. It also accepts an existing x86 developer prompt.

For network capture, install [Npcap](https://npcap.com/#download). The default desktop path calls Npcap directly. The older browser interface can be launched with `python src\monitor.py --open`; some research scripts use a separately installed TShark.

## Build the standalone EXE

```powershell
.\.venv\Scripts\python.exe packaging\build.py --dist-dir dist
```

The script compiles the native modules, prepares the bundled configuration, loads Qt's Russian translation, packages the executable with [PyInstaller](https://pyinstaller.org/en/stable/usage.html), then runs its self-test. The output is `dist\L2PacketMonitor.exe`; generated work/spec files are under `build/`.

The EXE includes Python, Qt, Unicorn, native modules, icons, catalog and server SDK. Npcap is installed separately and is also required on the build PC for the complete EXE self-test.

## Verify

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools\verify_repository.py
.\dist\L2PacketMonitor.exe --self-test --no-api --self-test-output reports\local-self-test
```

The logic suite covers framing, ciphers, sources, queues, inventory, character state, recovery, bridge validation and native mock capture. Native helper tests use temporary mock targets. The EXE self-test checks dependencies, native modules and UI, including both languages and themes, without starting game capture. It writes `self-test.json` and screenshots. The Windows CI workflow runs the logic/native tests and repository resource checks.

## Release artifacts

`L2PacketMonitor.exe` is the direct download. The Windows ZIP contains the EXE, guides and documentation assets. The source/resource ZIP includes all tracked repository files and pinned dependency lists. `SHA256SUMS.txt` records release hashes.

## Project layout

| Directory | Purpose |
|---|---|
| `src/l2_monitor` | UI, capture, protocol and application models |
| `src/native_probe` | x86 plaintext adapter and action helpers |
| `src/server_bridge_sdk` | Java/Python bridge integration |
| `config`, `assets` | Runtime profiles, tables, catalog and icons |
| `tests/fixtures` | Repeatable protocol examples |
| `packaging` | Build entry point, compiler setup, icon and version |
| `web` | Development browser interface |
| `docs` | User/developer guides and historical technical notes |
| `reports` | Local captures and development evidence; ignored by Git |

Historical technical notes retain local evidence paths as inline code. The public verification summary is in [verification/README.md](verification/README.md).
