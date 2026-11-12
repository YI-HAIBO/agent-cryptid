#!/bin/bash
# ==========================================================================
# E18: CryptoVerif machine-checking of the E9 provable-security reduction
# ==========================================================================
# 用途：在 Ubuntu 上一键安装 CryptoVerif 并运行 E18 模型，
#       验证 E9 归约的三个结构性引理。
#
# 前置：Ubuntu 20.04+，sudo 权限，网络可达
#       （opam 需要从 GitHub/OCaml.org 拉取包）。
#
# 用法：
#   chmod +x run_cryptoverif.sh
#   ./run_cryptoverif.sh
#
# 输出：cryptoverif_output.txt（保存完整证明结果）
# ==========================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODEL="$SCRIPT_DIR/e18_cryptoverif_credential.pv"
OUTPUT="$SCRIPT_DIR/cryptoverif_output.txt"

echo "=== E18: CryptoVerif installation and verification ==="
echo "Model: $MODEL"
echo "Output: $OUTPUT"
echo ""

# ---- Step 1: install opam + OCaml ----
if ! command -v opam &>/dev/null; then
    echo "[1/4] Installing opam..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq opam m4 zlib1g-dev
else
    echo "[1/4] opam already installed: $(opam --version)"
fi

# ---- Step 2: init opam (non-interactive) ----
if [ ! -d "$HOME/.opam" ]; then
    echo "[2/4] Initializing opam..."
    opam init --disable-sandboxing -y --shell=bash
    eval "$(opam env)"
else
    echo "[2/4] opam already initialized"
    eval "$(opam env)"
fi

# ---- Step 3: install cryptokit ----
echo "[3/4] Installing cryptokit..."
opam install -y cryptokit 2>&1 | tail -5

# ---- Step 4: install CryptoVerif ----
if ! command -v cryptoverif &>/dev/null; then
    echo "[4/4] Installing CryptoVerif (2.12)..."
    cd /tmp
    if [ ! -f cryptoverif2.12.tar.gz ]; then
        wget -q https://cryptoverif.inria.fr/cryptoverif2.12.tar.gz
    fi
    tar xzf cryptoverif2.12.tar.gz
    cd cryptoverif2.12
    ./build
    sudo cp cryptoverif /usr/local/bin/
    cd "$SCRIPT_DIR"
else
    echo "[4/4] CryptoVerif already installed: $(cryptoverif --version 2>&1 | head -1)"
fi

# ---- Run the model ----
echo ""
echo "=== Running E18 model ==="
cryptoverif "$MODEL" 2>&1 | tee "$OUTPUT"

echo ""
echo "=== Done. Output saved to $OUTPUT ==="
echo ""
echo "Expected: 3 queries proved (Lemma 1 enc-injectivity, Lemma 2 conjunction,"
echo "Lemma 3 chain reduction). If any query fails, see troubleshooting in"
echo "E18_cryptoverif_verification.md."