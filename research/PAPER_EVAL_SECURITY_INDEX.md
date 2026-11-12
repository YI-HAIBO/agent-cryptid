# 论文素材索引：Evaluation & Security 章节（agent-cryptid）

> 用途：把 E1–E9 的实验/分析成果，按 SCI 一区论文的 Evaluation 与 Security 章节结构归拢，
> 标明「现在就能引用的数字/结论」「待回填占位」「必须规避的坑」。
> 数据口径：**标注 quiet 机的数字可引用**；本机重负载下跑出的时序数字（验签中位 75–118ms）**仅供方法学演示，禁止入稿**。

---

## A. 章节 ↔ 实验映射总表

| 论文章节 | 用哪些实验 | 素材文件 |
|---|---|---|
| §5 安全分析 / Formal Security | E8 形式化 + E9 归约 | `formal/agent_cryptid.pv`、`formal/README.md`、`formal/E9_provable_security.md` |
| §6.1 实验设置（硬件声明+方法学） | 框架 `system_info()` + 方法论 | `research/eval_framework.py` 头部说明 |
| §6.2 可扩展性 | E1 | `eval_E1_*.csv`（full 产出） |
| §6.3 基线对比 | E2 | `eval_E2_baseline.csv` |
| §6.4 安全测评 | E3 威胁驱动 + E4 混合失败关闭 + **E10 集成攻击** | `eval_E3_threats.csv`、`eval_E4_failclosed.csv`、`eval_E10_integration.csv` |
| §6.5 密码原语符合性 | E5 KAT | `eval_E5_kat.csv` |
| §7 讨论/局限 | 各实验的诚实边界 | 本表 C 节 |

---

## B. 现在就能引用的数字/结论

### B1 安全测评（与机器负载无关，可直接入稿）

**E3 威胁驱动（14/14 攻击被拒 ✅ full 已实跑）**——`eval_E3_threats.csv`：
重放 / 受众混淆 / 签名伪造 / 载荷篡改（scope·sub·exp）/ 缺签名 / 委托越权 / 委托受众不匹配 / 撤销绕过 / 过期 / 未生效 / **算法降级·剥 pq_sig / 算法降级·改 alg_tier**。每条映射到一个设计机制（nonce 一次性、aud 绑定、签名覆盖、scope 收敛、累加器撤销、exp/nbf、PQ 分量失败关闭、档位纳入签名覆盖）。

**E4 混合失败关闭**——`eval_E4_failclosed.csv`：
both_valid→接受；SM2 分量篡改 / ML-DSA 分量篡改 / 两者皆篡改 → 全部拒绝。

**E5 KAT（54/54 ✅ full 已实跑）**：SM2/SM3 4/4、SHA3/SHAKE 5/5、SM9 28/28、ML-DSA-65 9/9、SLH-DSA 8/8。

**E7 密码敏捷迁移 ✅ full 已实跑**：存量 SM2 向后兼容=True、剥 PQ 被拦=True、改档被拦=True（含 SLH-DSA 新档）。

**E10 集成攻击实验 ✅ 已实跑（a2amcp venv，8/8 攻击全拒 + 正向对照通过）**——`eval_E10_integration.csv`：
把四类攻击打到**真实 A2A/MCP 集成边界**（MCP `TokenVerifier` + A2A 纯 ASGI 中间件 + 委托链验签器）：
token 透传（aud 绑定拒）/ 多跳越权（scope 收敛拒，签发侧+验链侧）/ 混淆代理人（act 篡改→签名失效拒）/ 算法降级（剥 pq_sig→失败关闭拒）。
**负载无关**（纯正确性/安全断言，与 E3/E4/E5/E7 同类），结论稳定可引用；是把「补上 A2A/MCP 官方承认缺口」
从规范论断变成**可运行证据**的关键实验。需 a2amcp venv；`eval_framework` 在默认 venv 自动跳过 E10。

> 以上 E3/E4/E5/E7 均由 `research/verify_claims.py` 在 **full 正确性模式**下实跑通过（~80s）。
> 关键方法论：这四项是**纯正确性/安全断言，与机器负载无关**，可脱离 `--full` 的重时序单独跑，
> 因此本机重负载不影响其结论——这是绕开「安静机阻塞」取得实测背书的关键。

### B2 形式化安全（稿已成，引用时标注「draft→实跑回填」）

- **E8 ProVerif** ✅ **已实跑（ProVerif 2.05，0.29s）**：6/6 query 全部 proved。P0 私钥保密（3/3）、P1 凭证不可伪造+受众绑定+scope 完整（非单射 correspondence）、P2 委托不可伪造（单射 correspondence）、P3 nonce 真实性（非单射 correspondence）。完整输出见 `formal/proverif_output.txt`。
- **E9 归约**：定理1 `Adv_CS|SM2 ≤ Adv_SM2`；定理2 混合档 `Adv ≤ min(Adv_SM2, Adv_MLDSA)`（失败关闭的可证明化身）；定理3 委托链 `Adv ≤ Σ 各跳 Adv`。QROM：ML-DSA 侧成立、SM2 按 ROM。

### B3 性能基线（quiet 机实测，可引用；复跑需安静机确认）

| 指标 | 实测 | 要求 | 结论 |
|---|---|---|---|
| 撤销→拒绝 | P99 460ms | <1000ms | 达标（余量 2 倍） |
| 签发 P99 | 5.4ms | ≤50ms | 达标（余量 9 倍） |
| 校验 中位/P99 | 4.66 / 5.05ms | ≤5ms（中位口径） | 中位达标，P99 贴线 |
| 十跳委托链 | 51.7ms | ≤100ms | 达标 |
| 注册 | 34.7ms/个 | — | — |
| 签发吞吐（单实例） | 166 TPS（E11e 稳态实测） | 5000 TPS | **未达标** |
| 签发吞吐（单机峰值） | **1008 TPS @ 16 进程**（效率 38%） | 5000 TPS | **单机不可达**，须 ≥5 台横向扩容 |

**抗量子档位（纯 Python 实测）**：ML-DSA keygen 0.17s / 签名中位 0.34s（单轮接受率≈24%，均 3–4 轮）/ 验签 0.032s；SLH-DSA keygen 18.9s / 签名验签≈0.07s。

**凭证体积**：SM2 档 ≈449–457 B（wire JSON）；PQ 档体积待 `--full` 补测。

---

## C. 待回填占位（投稿前必须补）

| 占位 | 来源 | 动作 |
|---|---|---|
| E1/E2 全量数字（1k/1万/10万注册、三档签发/验证、撤销时序、PQ 体积） | `eval_framework.py --full` | ⚠️ 本机负载污染（SM2 verify 75ms vs quiet 4.66ms），待安静机跑 |
| ~~E8 实跑结果~~ | ~~`formal/agent_cryptid.pv`~~ | ✅ 已完成（ProVerif 2.05, 0.29s, 6/6 proved） |
| ~~E5 完整 KAT（SM9/ML-DSA/SLH-DSA 项）~~ | ~~`eval_framework.py --full`~~ | ✅ 已完成：`verify_claims.py` 实跑 54/54（SM9 28/28、ML-DSA-65 9/9、SLH-DSA 8/8），无需安静机 |
| ~~E3 完整的 14 条攻击（含两条算法降级）~~ | ~~`eval_framework.py --full`~~ | ✅ 已完成：`verify_claims.py` 实跑 14/14，无需安静机 |
| ~~各优势界的数值代入（选定曲线/参数下的具体 bit 数）~~ | E9 §5.1 | ✅ 已完成：SM2 128-bit / ML-DSA 128-bit / 混合档 2^(-128) / 委托链 n·2^(-128) |

---

## D. 必须规避的坑（写作时）

1. **负载污染**：本机验签中位 75–118ms 的数字**绝不能进稿**；所有时序数字须来自安静机 `--full` 或已标注的 quiet 基线。论文须声明硬件 + warmup + 分位口径（中位/P95/P99）。
2. ~~**full-t 变体归约缺口**~~ **已修复（v2.17）**：ML-DSA 已换回标准 t1+hint 紧凑格式（`proto/mldsa.py`），享有完整 FIPS 204 可证明归约，E9 定理 2 的 ML-DSA 侧可直接套用。原 full-t 偏离声明已从 mldsa.py / E9 / 本文档同步移除。
3. **基线数字标注**：E2 的 X.509/SPIFFE/DID/OAuth 行是「文献代表值-待核实」，投稿前须以所引文献核实，不能当实测写。
4. **NFR 未闭环**（口径已由 E11 实测更新）：NFR-04 的**十万标识持有侧已闭环**（服务路径对标识数 O(1)：N×10 → 校验中位 ×1.041），但**5000 TPS 吞吐侧未达标**——单实例稳态 166 TPS、单机峰值 1008 TPS @ 16 进程（效率 38%），须 ≥5 台本机规格横向扩容或国密芯片/C 扩展。NFR-09（国产 OS/DB）仍未验证。论文勿声称 NFR-04 达标。
   - **别用线性外推**：天真按核数外推单机上限得 2653 TPS，**比实测峰值高估 163%**。任何"需 N 个实例"的说法必须基于**实测峰值效率**（每实例实际贡献 63 TPS @ 峰值），不能按单实例 166 TPS 理想外推（那会得出 31 实例的乐观错值）。
   - **GIL 归因已实测确立**：线程加速比 **1.00×**（1→8 线程：187.2→180.2 TPS，无收益甚至下降），进程加速比 **6.08×**（1→16 进程：165.8→1008.4 TPS）。并发只能靠**进程级**并行，线程方案无解。
5. **性能口径**：NFR-01 按 P99、NFR-02 按中位——与验收文档一致，别混用。
6. **v3.0 特性**：硬件根/侧信道/跨域撤销/真上链属 v3.0，论文中作为 future work，勿当已实现。

---

## E. 复现命令速查

```bash
# 【推荐】只跑负载无关的正确性实验（E3/E4/E5/E7），~80s，任何机器结论一致
python research/verify_claims.py
# 冒烟（验证 E3/E4/E5 正确性，quick 规模）
python research/eval_framework.py --quick
# 论文级基准（安静机，~10-12min）——现在只剩 E1/E2/E6 绝对时序需要它
python research/eval_framework.py --full --outdir ./_paper
# 形式化（需先装 ProVerif）
proverif research/formal/agent_cryptid.pv
# 【引用并行度数字请用这条】E11 并行瓶颈干净测量（~50s，含线程/进程对照）
#   理由：e11_scalability.py --full 串行跑时 E11a 的大负载会污染 E11b/E11e 基线，
#   表现为并行效率 >100%（物理不可能）。本脚本无前置负载，且自带污染自检。
python research/integration/e11_clean_parallelism.py --csv
# E11 全套（--e11 挂入 eval_framework；也可独立跑 --full，约 17 分钟）
python research/integration/e11_scalability.py --full
# E10 集成攻击实验（需 a2amcp venv；eval_framework 在默认 venv 自动跳过 E10）
python research/integration/e10_integration_attacks.py
# 论文编译（必须 --disable-installer，否则联网探测被拦 → SIGTERM 零输出）
pdflatex --disable-installer -interaction=nonstopmode agent_cryptid.tex
```

---

## F. 一区就绪度自评（2026-11-05 更新至 v1.7，ABC 推进进度已记录）

- **已实测/机器背书（可直接入稿）**：E3 14/14 攻击全拒、E5 54/54 KAT、E4 混合失败关闭、E7 迁移失败关闭（`verify_claims.py` full 实跑）；E8 ProVerif 2.05 实跑 6/6（0.29s）；E9 理论归约 + 具体数值代入（SM2/ML-DSA 128-bit、混合 2^(-128)、链 n·2^(-128)）；**E16 Tamarin 5/5 VERIFIED（1.12 + Maude 3.4 补丁，2026-11-03）**；**E18 CryptoVerif 3/3 Proved（2.12 原生，2026-11-04，Lemma 3 至 Psign EUF-CMA 界）**——E16/E18 双工具全机器验证，论文 §4/附录已改为 machine-verified。E10 集成攻击 8/8 + TCK 正交矩阵 129/129 Δ=0 + 多语言 14/14；E11 GIL 归因（线程 1.00× vs 进程 6.08×）/ 线性外推高估 163% / 十万标识 O(1) / 中位≠并发；E12 消融、E13 并发、E14 统计、E15 后端等价、E17 真实场景均已入稿。
- **论文 v1.7（IEEEtran 版，A1/A3/A4/C 已推进）**：已切换 `\documentclass[10pt,twocolumn]{IEEEtran}`（删除 article shim，补 `\IEEEauthormark`），3-pass 编译 16 页、0 错误、0 undefined citation/ref、仅 1 个 4.7pt 轻微 Overfull（行 398-400，等宽串，可接受），附录引用全解析。备份 `agent_cryptid.tex.article_class.bak` 留存。三大差异化支点（SM9 国密标识 / 可证明安全密码敏捷迁移 / 防混淆代理人委派）+ A2A/MCP 集成证据链齐备。实验 E1–E18 全部入稿。
- **投前必补（ABC 分级）——A 档（硬阻塞，3/4 已闭环，A2 待用户输入）**：
  - ✅ **A1 实验设置表 RAM**：已填 `RAM & 32 GiB`（本机 GlobalMemoryStatusEx 实测 34.1GB / 32 GiB）。
  - ✅ **A3 IEEEtran 模板切换**：已完成（见上），16 页编译干净。
  - ⏳ **A2 NSFC 基金号**：仍为 `Grant No.~[TBD]`（line 1808），**待用户提供真实资助号**后回填。
  - ✅ **A4 E1/E2/E6 安静机 `--full` 复跑**：**已完成**（VM 192.168.28.128，Ubuntu 26.04，负载≈0.00）。全量数字已回填论文：E1 注册 37.52(1k)/38.96(10k)ms·id、SM2 签发 P99 5.47ms、委托 10 跳 52.88ms、撤销 460ms P99；E2 SM2 4.30ms/混合 51.67ms/SLH-DSA 24.52ms（均为安静机，替换原 loaded-host 157.7/130.7ms）；E6 agent-cryptid 验签 4.83ms、匹配 4 跳链 17.1ms（vs UCAN 311.2ms，**18.2× 快于 UCAN**，原报 3.3×）。E5 在 VM 复跑 54/54（补推 `sm9_pairing.py` 后 SM9 28/28）。设置表新增「安静机 VM」列。
- **C 档（加分机会）——Redis nonce 实连已闭环**：VM 装 Redis 8.0.5 + redis-py 8.1.0，`RedisNonceStore` 实连可用；并发原子声称 64 线程/16 进程 **恰 1 赢家、0 错误**（v2.18 SET NX EX 修复实证）。`nonce_store.self_check` 9/9 PASS。A2A TCK 认证入口补丁、商用密码产品认证仍为外部项。
- **已如实披露、审稿人可能扣分（B 档，均已诚实回答，无需改稿）**：NFR-04 吞吐 5000 TPS 未达标（单实例 166 / 单机峰值 1008 @ 16 进程，效率 38%，须 ≥5 台横向扩容或国密芯片/C 扩展）；NFR-09 国产 OS/DB 未验证；SLH-DSA 用降参数集（非 FIPS 205 全参数）；E2 基线数值为「文献代表值」（出处已核实，数值建议逐个数回核）；NFR-02 校验 P99 5.05ms 贴线无余量；v3.0 硬件根/侧信道/跨域撤销/真上链 = future work。
- **加分机会（C 档，非必需）**：A2A TCK 认证入口补丁提交（规范级缺口已论文披露，"we intend to contribute"，若提交并合并是加分项）；商用密码产品认证（外部流程，需资质）。
- **已知减分项（v2.17 已修）**：full-t 归约缺口已闭环（ML-DSA 已换回标准 t1+hint 紧凑格式）。
