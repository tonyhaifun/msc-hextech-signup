@echo off
chcp 65001 >nul
cd /d "%~dp0"
set HOST=0.0.0.0
set PORT=4173
echo 正在启动 MSC 实验室海克斯大乱斗报名网站...
echo.
node server.js
pause
