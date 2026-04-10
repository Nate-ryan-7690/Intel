@echo off
cd /d "%~dp0"
title Intel Pipeline
echo Starting Intel Pipeline...
echo Working directory: %CD%
py src/app/app.py
echo.
echo Server stopped. See error above.
pause
