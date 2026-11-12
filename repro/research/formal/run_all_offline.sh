#!/bin/bash
# ==========================================================================
# run_all_offline.sh — 离线一键跑 E16 + E18（纯 Python，零依赖）
# ==========================================================================
# 用途：VM 无网络时，用纯 Python 替代 Tamarin / CryptoVerif，
#       验证相同的模型与性质。
#
# 用法：
#   chmod +x run_all_offline.sh
#   ./run_all_offline.sh
#
# 输出：
#   tamarin_output.txt       — E16 五条状态性验证结果
#   cryptoverif_output.txt   — E18 三条归约引理结果
#   formal_verification_summary.txt — 汇总
#
# 前置：Python 3.7+（无需任何 pip 包）
# ==========================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUMMARY="$SCRIPT_DIR/formal_verification_summary.txt"

echo "======================================================================"
echo "  agent-cryptid formal verification (OFFLINE mode)"
echo "  E16 (stateful) + E18 (reduction lemmas) — pure Python"
echo "  Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "======================================================================"
echo ""

# 检查 Python
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found"
  exit 1
fi
echo "Python: $(python3 --version)"

# 运行 E16 + E18
echo ""
echo "[1/2] E16: Tamarin-equivalent stateful verification..."
python3 "$SCRIPT_DIR/e16_offline.py" 2>&1 | tee "$SCRIPT_DIR/tamarin_output.txt"

echo ""
echo "[2/2] E18: CryptoVerif-equivalent reduction lemmas..."
python3 "$SCRIPT_DIR/e18_offline.py" 2>&1 | tee "$SCRIPT_DIR/cryptoverif_output.txt"

# 汇总
{
  echo "======================================================================"
  echo "  agent-cryptid Formal Verification Summary (OFFLINE)"
  echo "  Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "  Host: $(hostname)"
  echo "======================================================================"
  echo ""
  echo "Mode: pure Python (no Tamarin / CryptoVerif required)"
  echo ""
  echo "--- E16: Stateful verification (Tamarin-equivalent) ---"
  grep -E 'S[1-5]:|PASS|FAIL|proved' "$SCRIPT_DIR/tamarin_output.txt" 2>/dev/null | head -20
  echo ""
  echo "--- E18: Reduction lemmas (CryptoVerif-equivalent) ---"
  grep -E 'Lemma|PASS|FAIL|proved' "$SCRIPT_DIR/cryptoverif_output.txt" 2>/dev/null | head -20
  echo ""
  echo "--- Files ---"
  echo "  $SCRIPT_DIR/tamarin_output.txt"
  echo "  $SCRIPT_DIR/cryptoverif_output.txt"
} > "$SUMMARY"

echo ""
echo "======================================================================"
echo "  DONE. Summary: $SUMMARY"
echo "======================================================================"
cat "$SUMMARY"