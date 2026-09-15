@echo off
setlocal
cd /d "%~dp0"

cargo build --release -p win-proxychains --features std-bin --bin win-proxychains
if errorlevel 1 exit /b %errorlevel%

cargo build --release -p win-proxychains --lib
exit /b %errorlevel%
