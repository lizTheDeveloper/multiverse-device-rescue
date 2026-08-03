@echo off
REM Build the Windows Device Rescue installer on a Windows PC.
REM Prereqs: Python 3.11+ on PATH, Node.js 18+ on PATH, this repo checked out.
REM Run from anywhere: it cd's to the repo root relative to this script.
setlocal
cd /d %~dp0\..

echo === Building engine (PyInstaller) ===
python -m pip install pyinstaller || goto :err
python scripts\build.py || goto :err
if not exist desktop\engine mkdir desktop\engine
copy /Y dist\rescue.exe desktop\engine\rescue.exe || goto :err

echo === Building Electron installer ===
cd desktop
call npm install || goto :err
copy /Y ..\shared\permissions-content.json shared\permissions-content.json || goto :err
call npm run dist || goto :err

echo.
echo Build complete. Installer is in desktop\dist\
echo Next: gh release upload v0.1.0 desktop\dist\DeviceRescue-0.1.0-win-x64.exe
goto :eof

:err
echo.
echo Build FAILED. See the error above.
exit /b 1
