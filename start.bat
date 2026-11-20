@echo off
REM Start EVUL application using the project's virtualenv

:: Change to repository directory (script location)
cd /d "%~dp0"

:: Path to virtualenv python executable
set "VENV_PY=%~dp0\.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
  echo Virtual environment python not found at %VENV_PY%
  echo Please create the virtualenv or update start.bat to point to the correct python.
  pause
  exit /b 1
)

:: Ensure the app doesn't require auth when started via this script (optional)
set "REQUIRE_AUTH=false"

:: Start the Flask app in a new window named EVUL
start "EVUL" "%VENV_PY%" evildev/app.py

exit /b 0
