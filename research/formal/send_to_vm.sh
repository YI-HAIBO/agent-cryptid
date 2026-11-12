#!/bin/bash
# ==========================================================================
# send_to_vm.sh — 一键把形式化验证包传到 Ubuntu VM
# ==========================================================================
# 用法（Git Bash / WSL）：
#   chmod +x send_to_vm.sh
#   ./send_to_vm.sh
# 或直接：
#   bash send_to_vm.sh
# ==========================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 优先用受管 Python
PY_EXE="C:/Users/Yi/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
if [ ! -f "$PY_EXE" ]; then
    PY_EXE="python3"
fi

echo "============================================="
echo "  传输文件到 Ubuntu VM (192.168.58.129)"
echo "============================================="
echo ""

"$PY_EXE" "$SCRIPT_DIR/send_to_vm.py"
exit $?