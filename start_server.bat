@echo off
cd /d "%~dp0"
echo 正在启动 Markdown 本地服务...
echo 如果看到“本地服务已启动”，请在浏览器打开显示的地址。
if exist "%~dp0..\python314\python.exe" (
  "%~dp0..\python314\python.exe" -u server.py
  pause
  exit /b
)
where python >nul 2>nul
if %errorlevel%==0 (
  python -u server.py
) else (
  py -3 -u server.py
)
pause
