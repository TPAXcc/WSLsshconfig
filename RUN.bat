@echo off
:: ���Windows Terminal��װ·����Ĭ��λ�ú�Scoop��װλ�ã�
set "wtPath1=%LOCALAPPDATA%\Microsoft\WindowsApps\wt.exe"
set "wtPath2=%USERPROFILE%\scoop\apps\windows-terminal\current\wt.exe"

:: �ж��Ƿ�װWindows Terminal
if exist "%wtPath1%" (
    echo ��⵽Windows Terminal��ʹ��wtִ��...
    PowerShell -Command "Start-Process -FilePath '%wtPath1%' -ArgumentList 'PowerShell -NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs"
) else if exist "%wtPath2%" (
    echo ��⵽Scoop��װ��Windows Terminal...
    PowerShell -Command "Start-Process -FilePath '%wtPath2%' -ArgumentList 'PowerShell -NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs"
) else (
    echo δ��װWindows Terminal��ʹ��Ĭ��PowerShellִ��...
    PowerShell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs}"
)