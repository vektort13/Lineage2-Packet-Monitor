@echo off
rem Reuse an x86 developer prompt or locate the installed MSVC toolchain.
if /i "%VSCMD_ARG_TGT_ARCH%"=="x86" exit /b 0
set "L2_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%L2_VSWHERE%" (
  echo Visual Studio C++ tools were not found. Install Desktop development with C++.
  exit /b 1
)
set "L2_VS_ROOT="
for /f "usebackq tokens=*" %%i in (`"%L2_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "L2_VS_ROOT=%%i"
if not defined L2_VS_ROOT (
  echo MSVC x86/x64 tools were not found. Install Desktop development with C++.
  exit /b 1
)
call "%L2_VS_ROOT%\VC\Auxiliary\Build\vcvars32.bat" >nul
exit /b %errorlevel%
