@echo off
REM ============================================================
REM send_to_vm.bat — 一键把形式化验证包传到 Ubuntu VM
REM
REM 用法:
REM   双击此文件，或在 cmd 里跑:
REM   send_to_vm.bat
REM
REM 密码通过脚本内置参数传递，不会在屏幕上明文显示。
REM ============================================================

setlocal

set "SCRIPT_DIR=%~dp0"
set "PY_SCRIPT=%SCRIPT_DIR%send_to_vm.py"

REM 优先用受管 Python，没有就用系统 Python
set "PY_EXE=C:\Users\Yi\.workbuddy\binaries\python\envs\default\Scripts\python.exe"

if not exist "%PY_EXE%" (
    set "PY_EXE=python"
)

echo [%DATE% %TIME%] 开始传输文件到 Ubuntu VM...
echo.

"%PY_EXE%" "%PY_SCRIPT%"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% equ 0 (
    echo [OK] 传输完成！
) else (
    echo [FAIL] 传输失败，错误码 %EXIT_CODE%
)

REM 暂停一下让用户看到结果
echo.
echo 按任意键退出...
pause >nul
exit /b %EXIT_CODE%