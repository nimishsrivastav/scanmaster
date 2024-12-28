@echo off
echo Installing Radare2...

:: Check if Chocolatey is installed, and if not, install it
choco -v >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Chocolatey not found, installing Chocolatey...
    set "PATH=%PATH%;C:\ProgramData\chocolatey\bin"
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
)

:: Install Radare2 using Chocolatey
echo Installing Radare2...
choco install radare2 -y

:: Install Python dependencies
echo Installing Python dependencies...
pip install -r requirements.txt

echo Setup complete!
