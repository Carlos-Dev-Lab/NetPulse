@echo off
setlocal
title NetPulse Network Analyzer

set "ROOT=%~dp0.."
set "VENV_PY=%ROOT%\.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    where python >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python 3.10 or newer was not found.
        echo Install Python from https://www.python.org/downloads/windows/
        pause
        exit /b 1
    )
    echo Creating .venv...
    python -m venv "%ROOT%\.venv"
    if errorlevel 1 exit /b 1
)

"%VENV_PY%" -c "import flet, flet_desktop, scapy, psutil" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies in .venv...
    "%VENV_PY%" -m pip install -r "%ROOT%\requirements.txt" --disable-pip-version-check
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)

if not exist "C:\Windows\System32\Npcap\wpcap.dll" if not exist "C:\Windows\System32\wpcap.dll" (
    echo [WARN] Npcap was not found in its standard path.
)

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%VENV_PY%' -ArgumentList '-m netpulse' -Verb RunAs -WorkingDirectory '%ROOT%'"
) else (
    pushd "%ROOT%"
    "%VENV_PY%" -m netpulse
    popd
)
