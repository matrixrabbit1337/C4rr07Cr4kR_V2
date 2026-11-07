@echo off
setlocal
cd /d "%~dp0"
set "C4_PY="
where py >nul 2>&1 && set "C4_PY=py"
if not defined C4_PY (
    where python >nul 2>&1 && set "C4_PY=python"
)
if not defined C4_PY (
    echo Python was not found. Install Python 3 and try again.
    pause
    exit /b 1
)
%C4_PY% "%~dp0workbench.py"
if errorlevel 1 pause
