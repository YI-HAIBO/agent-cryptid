# E18: CryptoVerif machine-checking of the E9 reduction

面向密码顶刊（IEEE TDSC / TIFS）的「可证明安全」一节。

与 E8（ProVerif, Dolev-Yao symbolic）互补：
- **E8** = 协议逻辑正确性（authentication / correspondence），已实跑 6/6 proved。
- **E18** = 计算模型下的归约可验证性（EUF-CMA reduction soundness）。

## 文件

| 文件 | 说明 |
|---|---|
| `e18_cryptoverif_credential.pv` | CryptoVerif 模型（3 个 query） |
| `run_cryptoverif.sh` | 一键安装 + 运行脚本 |
| `README.md` | 本文件 |

## 一键运行

```bash
chmod +x run_cryptoverif.sh
./run_cryptoverif.sh
```

脚本自动完成：安装 opam → 初始化 → 安装 cryptokit → 安装 CryptoVerif 2.12 → 运行模型。

预计耗时 3–5 分钟（首次安装），证明本身 < 1 分钟。

## 手动运行

```bash
# 安装 CryptoVerif（只需一次）
sudo apt-get update
sudo apt-get install -y opam m4 zlib1g-dev
opam init --disable-sandboxing -y
eval $(opam env)
opam install cryptokit
cd /tmp
wget https://cryptoverif.inria.fr/cryptoverif2.12.tar.gz
tar xzf cryptoverif2.12.tar.gz
cd cryptoverif2.12
./build
sudo cp cryptoverif /usr/local/bin/

# 运行模型
cryptoverif e18_cryptoverif_credential.pv
```

## 模型内容

三个 query，分别验证 E9 的三个结构性引理：

1. **Lemma 1 (enc injectivity)**：`enc` 是确定性单射编码 ⇒ 无碰撞。
   `enc(x1,…,x6) = enc(y1,…,y6) ==> x1=y1 && … && x6=y6`

2. **Lemma 2 (conjunction reduction)**：混合档 accept ⟺ SM2 与 ML-DSA 同时通过。
   `event(accept_hybrid(…)) ==> event(sm2_verified(…))`（对称地 mldsa_verified）。
   这正是 E9 定理 2「Adv ≤ min(Adv_SM2, Adv_MLDSA)」的结构基础。

3. **Lemma 3 (chain reduction)**：委托链逐跳验签 + scope 收敛 + aud 一致。
   `event(chain_hop_accepted(…)) ==> event(chain_hop_issued(…))`。
   这正是 E9 定理 3「Adv_chain ≤ Σ Adv_Sig_i」的结构基础。

## 预期输出

```
RESULT: Lemma 1 (enc injectivity) proved.
RESULT: Lemma 2 (conjunction, SM2 side) proved.
RESULT: Lemma 2 (conjunction, ML-DSA side) proved.
RESULT: Lemma 3 (chain reduction) proved.
```

若某 query 未被证明，CryptoVerif 会输出可能的攻击轨迹——这本身就是一个有价值的发现。

## 注意事项

- CryptoVerif 证明的是**结构性归约**（reduction soundness），而非原语级安全。
  SM2→ECDLP、ML-DSA→MLWE 的具体归约引用标准结果（FIPS 204 / GB/T 32918），
  不在本模型重证范围——这与 E9 稿的「诚实边界」声明一致。
- 本模型与 E8（ProVerif）互补：E8 在 Dolev-Yao 下证明「协议逻辑是否正确」，
  E18 在计算模型下证明「归约结构是否 sound」。
- 若 CryptoVerif 2.12 在 Ubuntu 上编译失败（罕见），可改用 Docker：
  `docker pull cjacomme/cryptoverif`
  `docker run -it -v $(pwd):/home/examples cjacomme/cryptoverif`
  然后在容器内运行 `cryptoverif /home/examples/e18_cryptoverif_credential.pv`。