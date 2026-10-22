@echo off
echo ========================================================
echo   Stitch Sentinel EDR Agent Standalone Build Script
echo ========================================================
echo [*] Cleaning previous builds...
rmdir /s /q build dist
echo [*] Compiling Python agent using PyInstaller...
pyinstaller --onefile --console --name=stitch_agent --add-data "..\config\config.json;config" ..\agent\main.py
if %ERRORLEVEL% equ 0 (
    echo [+] Standalone agent successfully built in dist/stitch_agent.exe
) else (
    echo [-] PyInstaller build failed!
)
pause
