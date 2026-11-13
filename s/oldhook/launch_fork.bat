@echo off
rem ===== 2026-10-02 fork (patch-old) launcher =====
rem Runs the forked managed hook from C:\s\oldhook with its own config dir,
rem so it can never fight over the deployed baseline's files.
taskkill /F /IM Deepchart.exe >nul 2>&1
taskkill /F /IM VolumetricaBridge.exe >nul 2>&1
timeout /t 2 /nobreak >nul
set DOTNET_STARTUP_HOOKS=C:\s\oldhook\DeepHook.dll
set DP_HOOKOUT=C:\s\oldhook\hookout
set DOTNET_TieredCompilation=0
set DOTNET_TC_QuickJitForLoops=0
set DOTNET_TieredPGO=0
start "" /D "C:\Program Files\Volumetrica Trading\Deepchart" "C:\Program Files\Volumetrica Trading\Deepchart\Deepchart.exe"
echo ================================================
echo  Deepchart (fork hook) launched
echo ================================================
