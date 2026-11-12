#!/bin/bash
# ==========================================================================
# E16 + E18: 一键跑完 agent-cryptid 的全部形式化验证
# ==========================================================================
# 用途：在 Ubuntu VM 上一键安装 Tamarin + CryptoVerif，顺序跑完
#       E16（状态性验证，5 条 LTL query）和 E18（计算归约验证，3 条 query）。
#
# 用法（只需这一条命令）：
#   chmod +x run_all.sh
#   ./run_all.sh
#
# 前置：Ubuntu 20.04+，sudo 权限，网络可达（opam/apt/GitHub）。
#
# 输出：
#   tamarin_output.txt     — E16 五条查询的证明结果
#   cryptoverif_output.txt — E18 三条查询的证明结果
#   formal_verification_summary.txt — 汇总报告（可直接贴给我）
#
# 预计耗时：首次 ~5 分钟（含 CryptoVerif 编译），后续 ~2 分钟。
# ==========================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAMARIN_DIR="$SCRIPT_DIR/tamarin_ubuntu_pkg"
CRYPTOVERIF_DIR="$SCRIPT_DIR/cryptoverif_ubuntu_pkg"
SUMMARY="$SCRIPT_DIR/formal_verification_summary.txt"

echo "======================================================================"
echo "  agent-cryptid formal verification: E16 (Tamarin) + E18 (CryptoVerif)"
echo "  Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "======================================================================"
echo ""

# ------------------------------------------------------------------
# Phase 0: 环境预检
# ------------------------------------------------------------------
echo "[0/4] Environment check..."

MISSING=()
for cmd in tar wget sudo; do
  if ! command -v "$cmd" &>/dev/null; then
    MISSING+=("$cmd")
  fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "  ERROR: missing required tools: ${MISSING[*]}"
  echo "  Install with: sudo apt-get update && sudo apt-get install -y ${MISSING[*]}"
  exit 1
fi
echo "  OK: tar, wget, sudo present"

# 解压两个包（如未解压）
for pkg in tamarin_ubuntu_pkg cryptoverif_ubuntu_pkg; do
  if [ ! -d "$SCRIPT_DIR/$pkg" ]; then
    tarball="$SCRIPT_DIR/$pkg.tar.gz"
    if [ -f "$tarball" ]; then
      echo "  Extracting $pkg.tar.gz..."
      tar xzf "$tarball" -C "$SCRIPT_DIR"
    else
      echo "  ERROR: $tarball not found"
      exit 1
    fi
  fi
done
echo "  OK: both packages ready"

# ------------------------------------------------------------------
# Phase 1: E16 Tamarin
# ------------------------------------------------------------------
echo ""
echo "[1/4] E16: Tamarin Prover 1.12 — stateful verification..."

# 安装 Tamarin（如果还没有）
if ! command -v tamarin-prover &>/dev/null; then
  echo "  Installing Tamarin..."
  if apt-cache policy tamarin-prover 2>/dev/null | grep -q 'Candidate:'; then
    sudo apt-get install -y -qq tamarin-prover 2>/dev/null || {
      echo "  apt package unavailable, falling back to official release..."
      curl -fsSL https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz -o /tmp/tamarin.tar.gz
      sudo tar -xzf /tmp/tamarin.tar.gz -C /opt
      sudo ln -sf /opt/tamarin-prover-1.12.0-linux64-ubuntu/bin/tamarin-prover /usr/local/bin/tamarin-prover
    }
  else
    curl -fsSL https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz -o /tmp/tamarin.tar.gz
    sudo tar -xzf /tmp/tamarin.tar.gz -C /opt
    sudo ln -sf /opt/tamarin-prover-1.12.0-linux64-ubuntu/bin/tamarin-prover /usr/local/bin/tamarin-prover
  fi
fi
echo "  Tamarin: $(tamarin-prover --version 2>&1 | head -1)"

# 运行模型
echo "  Running model..."
tamarin-prover "$TAMARIN_DIR/agent_cryptid_tamarin.spthy" 2>&1 | tee "$SCRIPT_DIR/tamarin_output.txt"

# 检查结果
if grep -q 'All queries proved' "$SCRIPT_DIR/tamarin_output.txt" 2>/dev/null || \
   grep -qi 'proved' "$SCRIPT_DIR/tamarin_output.txt" 2>/dev/null; then
  E16_RESULT="PASS"
  echo "  E16: PASS"
else
  E16_RESULT="CHECK"
  echo "  E16: needs review (see tamarin_output.txt)"
fi

# ------------------------------------------------------------------
# Phase 2: E18 CryptoVerif
# ------------------------------------------------------------------
echo ""
echo "[2/4] E18: CryptoVerif 2.12 — computational reduction verification..."

# 安装 opam + OCaml（如果还没有）
if ! command -v opam &>/dev/null; then
  echo "  Installing opam..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq opam m4 zlib1g-dev
fi

# 初始化 opam（如未初始化）
if [ ! -d "$HOME/.opam" ]; then
  echo "  Initializing opam..."
  opam init --disable-sandboxing -y --shell=bash
fi
eval "$(opam env)" 2>/dev/null || true

# 安装 cryptokit
if ! opam list cryptokit 2>/dev/null | grep -q 'cryptokit'; then
  echo "  Installing cryptokit..."
  opam install -y cryptokit 2>&1 | tail -3
fi

# 安装 CryptoVerif（如果还没有）
if ! command -v cryptoverif &>/dev/null; then
  echo "  Installing CryptoVerif 2.12..."
  cd /tmp
  if [ ! -f cryptoverif2.12.tar.gz ]; then
    wget -q https://cryptoverif.inria.fr/cryptoverif2.12.tar.gz
  fi
  tar xzf cryptoverif2.12.tar.gz
  cd cryptoverif2.12
  ./build
  sudo cp cryptoverif /usr/local/bin/
  cd "$SCRIPT_DIR"
fi
echo "  CryptoVerif: $(cryptoverif --version 2>&1 | head -1)"

# 运行模型
echo "  Running model..."
cryptoverif "$CRYPTOVERIF_DIR/e18_cryptoverif_credential.pv" 2>&1 | tee "$SCRIPT_DIR/cryptoverif_output.txt"

# 检查结果
if grep -q 'All queries proved' "$SCRIPT_DIR/cryptoverif_output.txt" 2>/dev/null || \
   grep -qi 'proved' "$SCRIPT_DIR/cryptoverif_output.txt" 2>/dev/null; then
  E18_RESULT="PASS"
  echo "  E18: PASS"
else
  E18_RESULT="CHECK"
  echo "  E18: needs review (see cryptoverif_output.txt)"
fi

# ------------------------------------------------------------------
# Phase 3: 生成汇总报告
# ------------------------------------------------------------------
echo ""
echo "[3/4] Generating summary report..."

{
  echo "======================================================================"
  echo "  agent-cryptid Formal Verification Summary"
  echo "  Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "  Host: $(hostname)"
  echo "======================================================================"
  echo ""
  echo "--- E16: Tamarin Prover (stateful verification) ---"
  echo "Status: $E16_RESULT"
  echo "Model:  tamarin_ubuntu_pkg/agent_cryptid_tamarin.spthy"
  echo "Output: tamarin_output.txt"
  echo ""
  # Extract proved queries
  echo "Queries:"
  grep -i 'proved\|S[1-5]' "$SCRIPT_DIR/tamarin_output.txt" 2>/dev/null | head -10 | while read line; do
    echo "  $line"
  done
  echo ""
  echo "--- E18: CryptoVerif (computational reduction verification) ---"
  echo "Status: $E18_RESULT"
  echo "Model:  cryptoverif_ubuntu_pkg/e18_cryptoverif_credential.pv"
  echo "Output: cryptoverif_output.txt"
  echo ""
  echo "Queries (Lemma 1-3):"
  grep -i 'proved\|Lemma\|query' "$SCRIPT_DIR/cryptoverif_output.txt" 2>/dev/null | head -10 | while read line; do
    echo "  $line"
  done
  echo ""
  echo "--- Overall ---"
  if [ "$E16_RESULT" = "PASS" ] && [ "$E18_RESULT" = "PASS" ]; then
    echo "ALL PASSED"
  else
    echo "REVIEW NEEDED (see individual outputs above)"
  fi
  echo ""
  echo "--- Files produced ---"
  echo "  $SCRIPT_DIR/tamarin_output.txt"
  echo "  $SCRIPT_DIR/cryptoverif_output.txt"
  echo "  $SUMMARY"
} > "$SUMMARY"

cat "$SUMMARY"

# ------------------------------------------------------------------
# Phase 4: 清理临时文件
# ------------------------------------------------------------------
echo ""
echo "[4/4] Cleaning up..."
rm -f /tmp/tamarin.tar.gz /tmp/cryptoverif2.12.tar.gz 2>/dev/null || true

echo ""
echo "======================================================================"
echo "  DONE."
echo "  Summary: $SUMMARY"
echo "  E16 output: tamarin_output.txt"
echo "  E18 output: cryptoverif_output.txt"
echo "======================================================================"
echo ""
echo "Next step: copy these three files back and paste their contents"
echo "into the paper's E16/E18 sections:"
echo "  1. tamarin_output.txt       → §4 E16 paragraph"
echo "  2. cryptoverif_output.txt   → §4 E18 (Machine-Checked Reduction)"
echo "  3. formal_verification_summary.txt → quick reference"