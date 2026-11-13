@echo off
taskkill /F /IM Deepchart.exe >nul 2>&1
taskkill /F /IM VolumetricaBridge.exe >nul 2>&1
timeout /t 2 /nobreak >nul
set DOTNET_STARTUP_HOOKS=C:\Users\Admin\Desktop\DPDP\runtime\DeepHook.dll
set DOTNET_TieredCompilation=0
set DOTNET_TC_QuickJitForLoops=0
set DOTNET_TieredPGO=0
start "" /D "C:\Program Files\Volumetrica Trading\Deepchart" "C:\Program Files\Volumetrica Trading\Deepchart\Deepchart.exe"
echo ================================================
echo  Deepchart patched - launched (PID list via tasklist)
echo ================================================
