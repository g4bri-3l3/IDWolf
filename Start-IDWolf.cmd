@echo off
rem IDWolf launcher for double-click use. Runs Start-IDWolf.ps1 with the
rem execution policy bypassed for this process only (nothing is changed on
rem the system). A policy enforced by GPO (MachinePolicy / UserPolicy) still
rem wins: in that case ask IT, or sign the scripts.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-IDWolf.ps1" %*
pause
