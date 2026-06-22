@echo off
REM Sentinel SOC — Windows .exe builder
REM Prerequisites: Python 3.12+ from python.org (NOT MSYS2)
REM Run this script from: E:\Equilibrium Design System\

echo.
echo ========================================
echo  Sentinel SOC .exe Builder
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Install Python 3.12 from https://python.org
    echo        (IMPORTANT: NOT MSYS2 — use the official python.org installer)
    pause
    exit /b 1
)

echo [1/5] Checking dependencies...
python -c "import flask, cryptography, psutil" 2>nul
if errorlevel 1 (
    echo [2/5] Installing core dependencies...
    pip install flask cryptography psutil --quiet
)

REM Optional deps (with graceful failures if not available)
echo [3/5] Installing optional dependencies (tray icon support)...
pip install --upgrade pystray pillow pyinstaller 2>nul
REM Note: the app runs fine even if pystray fails — the tray icon is optional.

REM Verify PyInstaller
echo [4/5] Building .exe with PyInstaller...
if not exist "sentinel.spec" (
    echo Error: sentinel.spec not found. Run this script from the project root.
    pause
    exit /b 1
)

pyinstaller sentinel.spec
if errorlevel 1 (
    echo Error: PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo [5/5] Build complete!
echo.
echo ========================================
echo  Success!
echo ========================================
echo.
echo Your executable is here:
echo   dist\Sentinel_SOC.exe
echo.
echo Next steps:
echo   1. Run the .exe: double-click dist\Sentinel_SOC.exe
echo   2. Your browser opens to http://127.0.0.1:8000
echo   3. Log in with admin credentials
echo.
echo Optional: Create a Windows shortcut for easier access
echo   - Right-click dist\Sentinel_SOC.exe
echo   - Create shortcut
echo   - Cut and paste to Desktop or Start Menu
echo.
echo For auto-start at boot:
echo   - Place a shortcut in: C:\Users\[YourName]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
echo.
pause
