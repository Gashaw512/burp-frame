@echo off
setlocal enableDelayedExpansion

:: --- Configuration ---
set "PYTHON_INSTALLED_PACKAGE_NAME=burp-frame"
set "REQUIREMENTS_FILE_PATH=burp_frame\requirements.txt"
set "PYTHON_ENTRY_MODULE=cli"

:: Get the directory where this batch script resides
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%"

chcp 65001 > nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo.
echo ========================================
echo 🚀 Starting %PYTHON_INSTALLED_PACKAGE_NAME% Launcher
echo ========================================
echo.

:: Check Python
echo Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Python not found.
    goto :error_exit
)
echo ✅ Python found.

:: Check pip
echo Checking and upgrading pip...
python -m ensurepip --default-pip >nul 2>&1
python -m pip install --upgrade --no-cache-dir pip setuptools wheel >nul 2>&1
echo ✅ Pip ready.

:: Install dependencies
echo Installing/verifying project dependencies...
if exist "%REQUIREMENTS_FILE_PATH%" (
    python -m pip install --upgrade --no-cache-dir -r "%REQUIREMENTS_FILE_PATH%"
) else (
    echo ⚠ Warning: "%REQUIREMENTS_FILE_PATH%" not found. Skipping dependency installation.
)

:: Install package
echo Installing/verifying %PYTHON_INSTALLED_PACKAGE_NAME% package...
python -m pip install --upgrade --no-cache-dir .

:: Launch
echo.
echo ========================================
echo 🚀 Launching %PYTHON_INSTALLED_PACKAGE_NAME%...
echo ========================================
echo.
python -m %PYTHON_INSTALLED_PACKAGE_NAME%.%PYTHON_ENTRY_MODULE% %*
goto :success_exit

:success_exit
echo.
echo ========================================
echo %PYTHON_INSTALLED_PACKAGE_NAME% exited successfully.
echo ========================================
pause
goto :eof

:error_exit
echo.
echo ========================================
echo ❌ %PYTHON_INSTALLED_PACKAGE_NAME% encountered an error.
echo ========================================
pause
endlocal
