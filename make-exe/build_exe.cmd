@echo off
REM ============================================================
REM  build_exe.cmd - build ts_integrity_check.exe via PyInstaller
REM  ОПТИМИЗИРОВАНО ДЛЯ WINDOWS 7
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo  Building ts_integrity_check.exe (Windows 7 compatible)
echo ============================================================
echo.

REM --- Check Python ---
where python >nul 2>nul
if errorlevel 1 (
    echo [x] Python not found in PATH.
    echo     Install Python 3.8.x and add it to PATH.
    pause
    exit /b 1
)

REM --- Show Python version and check for 3.8.x ---
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [i] %%v
python -c "import sys; sys.exit(0 if sys.version_info[:2]==(3,8) else 1)" >nul 2>nul
if errorlevel 1 (
    echo.
    echo [!] ВНИМАНИЕ: для сборки под Windows 7 рекомендуется Python 3.8.x
    echo.
)

REM --- Check PyInstaller (установка при отсутствии) ---
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo [!] PyInstaller not found. Installing ^(version ^<6^)...
    python -m pip install "pyinstaller<6"
    if errorlevel 1 (
        echo [x] Cannot install PyInstaller.
        pause
        exit /b 2
    )
)

REM --- Show PyInstaller version (без ложных предупреждений) ---
for /f "tokens=*" %%v in ('python -c "import PyInstaller; print(PyInstaller.__version__)" 2^>^&1') do set PYI_VER=%%v
echo [i] PyInstaller !PYI_VER!

REM --- Check bin\ contents (только ffmpeg обязателен) ---
echo [i] External binaries in bin\:
if exist "bin\ffmpeg.exe"  (echo     ffmpeg.exe  - OK) else (echo     ffmpeg.exe  - MISSING ^(обязателен^))
if exist "bin\ffprobe.exe" (echo     ffprobe.exe - OK) else (echo     ffprobe.exe - опционально, не найден)
echo.

REM --- Clean previous build ---
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

REM --- Run PyInstaller ---
echo [i] Running PyInstaller (Windows 7 mode)...
echo.
pyinstaller ts_integrity_check.spec --clean --noconfirm
if errorlevel 1 (
    echo.
    echo [x] Build FAILED. See errors above.
    pause
    exit /b 3
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo ============================================================
if exist "dist\ts_integrity_check.exe" (
    for %%A in ("dist\ts_integrity_check.exe") do (
        echo   File: %%~fA
        echo   Size: %%~zA bytes
    )
) else (
    echo   [!] dist\ts_integrity_check.exe not found.
)

echo.
echo   ВАЖНО для Windows 7:
echo   1. На целевой машине желательно установить KB2999226
echo      (Universal C Runtime). Без него .exe может не запуститься.
echo   2. Протестируйте .exe на чистой машине с Windows 7 без Python.
echo.

if exist dist explorer dist

pause
endlocal