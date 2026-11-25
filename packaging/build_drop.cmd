@echo off
setlocal
call "%~dp0vcvars_x86.cmd"
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist build\inventory-drop mkdir build\inventory-drop
cl /nologo /O2 /MT /LD src\native_probe\drop_hook.cpp /Fo:build\inventory-drop\drop_hook.obj /link user32.lib /OUT:build\inventory-drop\drop_hook.dll /IMPLIB:build\inventory-drop\drop_hook.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /MT src\native_probe\drop_controller.cpp /Fo:build\inventory-drop\drop_controller.obj /link user32.lib /OUT:build\inventory-drop\drop_controller.exe
exit /b %errorlevel%
