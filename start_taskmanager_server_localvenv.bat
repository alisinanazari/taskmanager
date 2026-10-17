@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Run next to app.py. The old .venv in this folder is deliberately ignored.
cd /d "%~dp0" || goto failed
if not exist "app.py" (
    echo ERROR: Place this BAT file next to app.py in X:\taskmanager.
    goto failed
)
if not exist "requirements.txt" (
    echo ERROR: requirements.txt is missing.
    goto failed
)

rem A mapped drive can deny renaming or creating a virtual environment.
rem Install Python packages under the current Windows user's local profile.
if not defined LOCALAPPDATA set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"
set "TASKMANAGER_VENV=%LOCALAPPDATA%\AcomTaskManager\venv"
set "TASKMANAGER_PYTHON=%TASKMANAGER_VENV%\Scripts\python.exe"

if not exist "%TASKMANAGER_PYTHON%" (
    echo Creating local Python environment: "%TASKMANAGER_VENV%"
    where py >nul 2>&1
    if not errorlevel 1 py -3 -m venv "%TASKMANAGER_VENV%"
    if not exist "%TASKMANAGER_PYTHON%" (
        where python >nul 2>&1
        if not errorlevel 1 python -m venv "%TASKMANAGER_VENV%"
    )
)
if not exist "%TASKMANAGER_PYTHON%" (
    echo ERROR: A working Python installation was not found for this Windows user.
    echo Run: py -0p
    echo Or run: python --version
    goto failed
)

rem Validate an existing environment in case its base Python was removed.
"%TASKMANAGER_PYTHON%" --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Local Python environment is broken: "%TASKMANAGER_VENV%"
    echo Rename that local venv folder and run this BAT again.
    goto failed
)

echo Installing required packages into the local environment...
"%TASKMANAGER_PYTHON%" -m pip install -r "requirements.txt" "waitress>=3,<4"
if errorlevel 1 goto failed

if not exist "database.db" if not defined SEED_PASSWORD (
    echo ERROR: database.db is missing. Copy the intended database into this folder first.
    echo If creating a fresh database, set a strong SEED_PASSWORD first.
    goto failed
)

echo Initializing or migrating database.db...
"%TASKMANAGER_PYTHON%" -c "import app; app.init_db()"
if errorlevel 1 goto failed
"%TASKMANAGER_PYTHON%" "configure_executives.py"
if errorlevel 1 goto failed

echo.
echo TaskManager is starting on port 5000.
echo Server: http://localhost:5000
echo Network: http://SERVER-IP:5000
echo Waitress worker threads: 20
echo Keep this window open while using TaskManager.
echo.
"%TASKMANAGER_VENV%\Scripts\waitress-serve.exe" --listen=0.0.0.0:5000 --threads=20 app:app
if errorlevel 1 goto failed
endlocal
exit /b 0

:failed
echo.
echo TaskManager could not start. Review the error above.
pause
endlocal
exit /b 1
