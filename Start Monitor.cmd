@echo off
cd /d "%~dp0"
python src\monitor.py --open %*
if errorlevel 1 pause
