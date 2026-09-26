@echo off
chcp 65001 >nul
cd /d "%~dp0"
python main.py
if errorlevel 1 (
  echo.
  echo 启动失败。若提示缺 python，请先安装 Python 3.8+  https://www.python.org/downloads/
  echo 安装时务必勾选 "Add Python to PATH"。
  pause
)
