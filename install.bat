@echo off
REM ============================================================
REM  C4rr07CR4cKR - Windows installer
REM  Elevates to Administrator, installs Python dependencies,
REM  then opens the advanced tools so you can run Setup -> Install
REM  everything (downloads hashcat/john portable + tool paths).
REM ============================================================
setlocal

REM ---- self-elevate to Administrator via UAC ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo [*] Running as Administrator in: %cd%

REM ---- find Python (py launcher preferred, then python) ----
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
    echo [!] Python was not found on PATH.
    echo     Install the latest Python from https://www.python.org/downloads/
    echo     and on the first installer screen tick "Add python.exe to PATH"
    echo     and make sure "tcl/tk and IDLE" is selected.
    pause
    exit /b 1
)
echo [*] Using Python: %PY%

REM ---- verify tkinter is present ----
%PY% -c "import tkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Your Python is missing tkinter.
    echo     Reinstall Python from python.org with the "tcl/tk and IDLE" option checked.
    pause
    exit /b 1
)

REM ---- install Python dependencies ----
echo [*] Installing Python packages (customtkinter, pillow, pyyaml, name-that-hash)...
%PY% -m pip install --upgrade pip
%PY% -m pip install --upgrade customtkinter pillow pyyaml name-that-hash

echo.
echo [+] Python side ready.
echo [*] Launching C4rr07CR4cKR. In the app: open the "Setup" page and
echo     click "Install everything" to download hashcat + John and register them.
echo     Use run.bat afterward to open the new Workbench.
echo.
%PY% "%~dp0c4rr07cr4ckr.py" --no-root

pause
