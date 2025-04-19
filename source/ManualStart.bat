@echo off
:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Define the paths for PsExec and the PowerShell script
set "PsExecPath=%~dp0tools\PsExec64.exe"
set "BrowserKioskScript=%~dp0Set-BrowserKioskSettings.ps1"

:: Launch PowerShell as SYSTEM using PsExec64 and pass the switches to the script
"%PsExecPath%" -i -s powershell -NoProfile -ExecutionPolicy Bypass -File "%BrowserKioskScript%" -ApplySTIGs -InstallAVDClient -ShowDisplaySettings