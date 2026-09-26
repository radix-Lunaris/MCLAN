@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo    build client -^> dist\MCLanP2P.exe
echo ============================================
echo.
python build.py
if errorlevel 1 goto bad
echo.
echo done: dist\MCLanP2P.exe
goto end
:bad
echo.
echo BUILD FAILED - see the message above.
:end
echo.
pause
