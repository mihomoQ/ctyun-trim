@echo off
call "%~dp0Start-CTyunTrim.cmd" -Mode Trim %*
exit /b %errorlevel%
