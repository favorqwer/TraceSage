@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0neo4j_desktop_start.ps1"
echo.
pause
