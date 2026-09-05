@echo off
setlocal
set "PS64=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS64=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS64%" exit /b 1
set "PSModulePath=%ProgramFiles%\WindowsPowerShell\Modules;%ProgramFiles(x86)%\WindowsPowerShell\Modules;%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%PS64%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Restore-PowerMenu.ps1" %*
exit /b %errorlevel%
