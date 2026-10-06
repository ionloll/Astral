@echo off
title Astral - Incident Response ^& Defensive Systems by ion (@ionj)
color 0B
mode con cols=95 lines=30

:: Verify Administrator privileges
openfiles >nul 2>nul
if %errorlevel% NEQ 0 (
    echo [!] Administrator privileges required.
    echo [*] Requesting elevation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

if exist "bin\Release\Astral.exe" (
    "bin\Release\Astral.exe"
) else if exist "Astral.exe" (
    "Astral.exe"
) else (
    echo [!] Astral.exe was not found.
    echo [*] Build the project using MSBuild or Visual Studio first.
    pause
)
