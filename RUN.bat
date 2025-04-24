@echo off
:: 检测Windows Terminal安装路径（默认位置和Scoop安装位置）
set "wtPath1=%LOCALAPPDATA%\Microsoft\WindowsApps\wt.exe"
set "wtPath2=%USERPROFILE%\scoop\apps\windows-terminal\current\wt.exe"

:: 判断是否安装Windows Terminal
if exist "%wtPath1%" (
    echo 检测到Windows Terminal，使用wt执行...
    PowerShell -Command "Start-Process -FilePath '%wtPath1%' -ArgumentList 'PowerShell -NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs"
) else if exist "%wtPath2%" (
    echo 检测到Scoop安装的Windows Terminal...
    PowerShell -Command "Start-Process -FilePath '%wtPath2%' -ArgumentList 'PowerShell -NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs"
) else (
    echo 未安装Windows Terminal，使用默认PowerShell执行...
    PowerShell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0wsl_ssh_setup.ps1\"\"' -Verb RunAs}"
)