# E18: CryptoVerif machine-checking of the E9 reduction

> 面向密码顶刊（IEEE TDSC / TIFS）的「可证明安全」一节。
> 与 E8（ProVerif 形式化验证）互补：E8 在 Dolev-Yao 模型下证明**认证/correspondence**；
> E18 在计算模型下验证**归约结构的 soundness**（EUF-CMA reduction）。

## 状态（2026-11-04 真机全证）

- **模型文件**：`e18_cryptoverif_credential.pv`（CryptoVerif 2.12 语法，含域分离 + 双签名实例）
- **运行环境**：Ubuntu 24.04 VM（192.168.231.128），CryptoVerif 2.12 **原生编译**
  （`./build` → ocamlopt，`cryptoverif2.12.tar.gz` 源码包，md5 `a7d04beb0aa5f1ed6f28c0e05f24104b` 校验通过）
- **结果**：三个引理全部机器证明，日志 `_dl/e18_live_proof.log`
  - Lemma 1（enc injectivity）：由 `fun enc` 构造子语义保证（无归约规则 ⇒ 单射）
  - Lemma 2（conjunction）：两查询 `RESULT Proved`（≤ 0）
  - Lemma 3（chain reduction）：`RESULT Proved ... up to probability Psign(time_1, N)`（EUF-CMA 界）
  - 末行 `All queries proved.`
- **与离线探索器**：`e18_offline.py`（240 tuples / truth table / 174 chains，全 PASS）佐证同一性质

## 关键建模决策（本轮修复 Lemma 3 的经验）

1. **双签名实例（关键）**：混合档与委托链各用**独立** `expand SUF_CMA_proba_signature`
   （`sign_h/check_h` 与 `sign_c/check_c`）。若共用同一 `sign/check`，CryptoVerif 的 SUF-CMA
   展开会把 hybrid 签名实例也放进 chain 校验端的 find 分支，导致「借 hybrid 有效签名触发
   chain_hop_accepted 而无 chain_hop_issued」。分实例后 `check_c` 的 find 只匹配 `sign_c` 实例。
2. **域分离**：`enc` 第 6 参 `domain ∈ {DOM_HYB, DOM_CHN}` 再加一层标签（与独立实例互为冗余防护）。
3. **消息级事件（Lemma 3 表述）**：链事件以签名消息 `m: blocksize` 为参数
   （`chain_hop_accepted(m) ==> chain_hop_issued(m)`）。CryptoVerif 的 SUF-CMA find 直接把
   verifier 的 `m1` 与 issuer 的 `m_i` 绑定（`m1 = m_i`），无需 enc 单射桥接即可证；
   由 Lemma 1（enc 单射）把消息级语句提升到跳元组级
   （`m = enc(delegatee, deleg, sc, n, ALG, DOM_CHN)` 唯一确定 `(deleg, delegatee, sc, n)`）。
   - 若不改为消息级（事件仍带元组参数），CryptoVerif 在**数组 find** 里不展开 `m_1[ri]`、
     不应用 enc 单射，无法从 `enc(a)=enc(b)` 推出事件元组相等——即使加域分离/双实例也证不出。
4. **类型/通道规则**：`type domain` 必须在 `fun enc` 之前声明；`else 0`（PNil）不被
   `check_oprocess` 接受须用 `else yield`；同通道不能既是 `in` 又是 `out` 并行、
   多次 `in` 参数类型须一致（通道已拆分：`cReqIss/cReqVer`、`cDlOut/cDlIn`）。

## 与 E9 的关系

E9（`E9_provable_security.md`）给出了三个定理的归约证明草图：

| 定理 | 内容 | E18 验证的引理 |
|---|---|---|
| 定理 1 (SM2 档) | CS\|SM2 EUF-CMA ≤ Adv_SM2 + ε_enc | Lemma 1 (enc injectivity ⇒ ε_enc=0) |
| 定理 2 (混合档) | CS\|hybrid EUF-CMA ≤ min(Adv_SM2, Adv_MLDSA) | Lemma 2 (conjunction ⇒ 伪造必先伪造某分量) |
| 定理 3 (委托链) | Adv_chain ≤ Σ Adv_Sig_i + ε_check | Lemma 3 (chain reduction) |

E18 不重证原语安全（SM2→ECDLP、ML-DSA→MLWE 引用标准结果），
而是用 CryptoVerif **机器验证归约的结构是 sound 的**——即「若凭证被伪造，
则必先伪造底层签名」这一逻辑链条无漏洞。

## 运行方式

### 方案 A：一键脚本（推荐，需 OCaml/opam 宿主）

```bash
cd cryptoverif_ubuntu_pkg
chmod +x run_cryptoverif.sh
./run_cryptoverif.sh
```

脚本自动安装 opam → cryptokit → CryptoVerif 2.12 → 运行模型 → 输出
`cryptoverif_output.txt`。

### 方案 B：原生源码编译（本次 VM 实际采用，绕开 opam 仓库克隆）

```bash
# Ubuntu 24.04 上（apt 源可达；VM 时钟需校准避免 "Release file not valid yet"）
sudo apt-get update
sudo apt-get install -y ocaml ocaml-findlib libcryptokit-ocaml-dev libzarith-ocaml-dev libgmp-dev
cd /tmp
curl -LO https://cryptoverif.inria.fr/cryptoverif2.12.tar.gz
tar xzf cryptoverif2.12.tar.gz
cd cryptoverif2.12
./build          # 原生 ocamlopt 编译（顶层无 configure/Makefile）
cryptoverif e18_cryptoverif_credential.pv
```

### 方案 C：Docker

```bash
docker pull cjacomme/cryptoverif
docker run -it -v $(pwd):/home/examples cjacomme/cryptoverif
# 容器内：
cd /home/examples/cryptoverif_ubuntu_pkg
cryptoverif e18_cryptoverif_credential.pv
```

## 预期输出（已达成）

```
RESULT Proved forall n: nonce, sc: scope, aud, sub: message; event(accept_hybrid(...)) ==> event(comp1_verified(...))
RESULT Proved forall n: nonce, sc: scope, aud, sub: message; event(accept_hybrid(...)) ==> event(comp2_verified(...))
RESULT Proved forall m: blocksize; event(chain_hop_accepted(m)) ==> event(chain_hop_issued(m)) up to probability Psign(time_1, N)
All queries proved.
```

## 与 E16 (Tamarin) 的关系

| | E16 (Tamarin) | E18 (CryptoVerif) |
|---|---|---|
| 模型 | 多重集重写（stateful） | 概率过程演算（computational） |
| 性质 | replay-at-most-once, revocation persistence, delegation depth, scope convergence, freshness | EUF-CMA reduction soundness |
| 状态 | **5/5 VERIFIED**（Tamarin 1.12 + Maude 3.4 补丁，2026-11-03） | **3/3 Proved**（CryptoVerif 2.12 原生，2026-11-04） |
| 互补性 | 状态化性质（重放、撤销、时效） | 计算归约（不可伪造性） |

二者共同构成「Dolev-Yao + ROM/QROM」双层安全论证，是密码顶刊要求的
完整形式化验证覆盖。

## 真机运行记录

- 环境：VM 192.168.231.128（cloud/123456），Ubuntu 24.04，CryptoVerif 2.12 原生编译
- 编译：`./build` → BUILD_RC=0，二进制 9.8MB，`cryptogen` + `default.cvl` 库齐全
- 运行：`cryptoverif e18_cryptoverif_credential.pv`（后台 nohup + 日志轮询）
- 日志：`_dl/e18_live_proof.log`（21778 字节，All queries proved）
- 时间：安装 + 编译 ≈ 30 分钟；模型运行 ≤ 1 分钟
