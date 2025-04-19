@echo off

REM Define the paths for PsExec and the PowerShell script
set PsExecPath=%~dp0tools\PsExec64.exe
set BrowserKioskScript=%~dp0\Set-BrowserKioskSettings.ps1

REM Launch PowerShell as SYSTEM using PsExec64 and pass the switches to the script
"%PsExecPath%" -i -s powershell -NoProfile -ExecutionPolicy Bypass -File "%BrowserKioskScript%" -ApplySTIGs -InstallAVDClient -ShowDisplaySettings