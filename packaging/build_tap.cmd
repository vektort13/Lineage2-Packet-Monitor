@echo off
setlocal
call "%~dp0vcvars_x86.cmd"
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist build\client-tap mkdir build\client-tap
cl /nologo /O2 /MT /LD src\native_probe\tap_hook.cpp /Fo:build\client-tap\tap_hook.obj /link user32.lib /OUT:build\client-tap\tap_hook_v2.dll /IMPLIB:build\client-tap\tap_hook.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /MT src\native_probe\tap_controller.cpp /Fo:build\client-tap\tap_controller.obj /link user32.lib /OUT:build\client-tap\tap_controller.exe
exit /b %errorlevel%
