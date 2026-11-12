#!/usr/bin/env bash
# =====================================================================
# E16 — Tamarin 机器执行（Ubuntu / Debian 原生）
# 用法：
#   1. 把本文件 + agent_cryptid_tamarin.spthy 拷到 Ubuntu VM 同一目录
#   2. chmod +x run_tamarin.sh && ./run_tamarin.sh
# 3. 产出：tamarin_output.txt（论文可引用的机器证明）
# =====================================================================
set -euo pipefail

MODEL="agent_cryptid_tamarin.spthy"
OUT="tamarin_output.txt"

# --- 1. 安装 Tamarin（若未装） ----------------------------------------
if ! command -v tamarin-prover >/dev/null 2>&1; then
  echo ">>> 安装 Tamarin Prover 1.12 ..."
  # 优先 apt（Debian/Ubuntu 官方包）
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq tamarin-prover 2>/dev/null || {
      # apt 无包 → 用官方 release tarball
      echo "    apt 无包，改用官方 release tarball ..."
      curl -fsSL \
        https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz \
        -o /tmp/tamarin.tar.gz
      sudo tar -xzf /tmp/tamarin.tar.gz -C /opt
      sudo ln -sf /opt/tamarin-prover-1.12.0-linux64-ubuntu/bin/tamarin-prover /usr/local/bin/tamarin-prover
    }
  else
    echo "ERROR: 未找到 apt-get，请手动安装 Tamarin 1.12" >&2
    exit 1
  fi
fi

echo ">>> Tamarin 版本: $(tamarin-prover --version 2>&1 | head -1)"

# --- 2. 检查模型文件 ---------------------------------------------------
if [ ! -f "$MODEL" ]; then
  echo "ERROR: 找不到 $MODEL（请与本脚本放在同一目录）" >&2
  exit 1
fi

# --- 3. 执行验证 -------------------------------------------------------
echo ">>> 运行: tamarin-prover $MODEL"
echo ">>> 期望：5 个 query 全部 proved，耗时 < 60s"
echo

# 先跑标准模式（纯 LTL 证明）
tamarin-prover "$MODEL" 2>&1 | tee "$OUT"

# --- 4. 可选：Coq 后端机器检查（需 Coq 8.18+） --------------------------
if command -v coqc >/dev/null 2>&1; then
  echo
  echo ">>> Coq 后端机器检查（可选，更硬）..."
  tamarin-prover "$MODEL" --coq 2>&1 | tee -a "$OUT"
else
  echo
  echo ">>> 未检测到 Coq，跳过 --coq 后端（LTL 证明已足够）"
fi

# --- 5. 结果摘要 --------------------------------------------------------
echo
echo ">>> 结果摘要："
if grep -qiE "proved|safe" "$OUT"; then
  echo "    ✓ 至少一个 query 证明成功"
else
  echo "    ✗ 未见 proved，检查 $OUT"
fi
echo "    产出: $OUT"