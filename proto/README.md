# agent-cryptid / proto —— 智能体密码身份中台（v2.8）

## 概述

中间件形态，嵌入企业智能体运行时，提供「标识—凭证—委托—存证」四层能力。
纯 Python 自研，零第三方依赖，国密合规（SM2 / SM3 / SM9）。

## 目录结构

```
proto/
├── __init__.py              # 包入口
├── __main__.py              # python -m proto.entrypoint 入口
├── entrypoint.py            # CLI 入口（--check / --smoke / --http / demo）
├── DEPLOY.md                # 生产部署指南（Uvicorn + Docker）
├── config.example.json      # 生产配置示例（v2.8）
├── sm2.py                   # SM2 / SM3 纯 Python 实现（GB/T 32918.2）
├── sm2_fast.py              # FastSigner（gmssl 加速，7ms 签名 / 3ms 验签）
├── sm2_jac.py               # SM2 验签性能优化（Jacobian + Shamir，3ms）
├── sm9.py                   # SM9 标识密码（GB/T 38635，全 KAT + 双向互操作 gmalg）
├── sm9_pairing.py           # R-ate 双线性对（Fp2/Fp4/Fp12 塔式扩张）
├── identity.py              # IdentityAuthority：标识密钥签发与验签
├── credential.py            # Credential：凭证签发/序列化/本地校验（SM2+SM9 双档）
├── delegation.py            # 委托链：多跳委托构造 + 审计哈希链
├── revocation.py            # Merkle 累加器撤销（CAPACITY=1024，满自动冻结）
├── audit_anchor.py          # 审计锚点：链根签名锚定（上链存证雏形）
├── persistence.py           # SQLite 后端（6 表：identities/revocations/audit_log/
│                            policy/revocation_state/audit_anchors）
├── agent_platform.py        # Platform：10 API 全流程
├── http_api.py              # HTTP 路由分发（stdlib + ASGI 共用 route()）
├── asgi_app.py              # ASGI 应用（uvicorn 生产部署）
├── auth.py                  # 控制面鉴权（SM3 摘要 + hmac.compare_digest）
├── nonce_store.py           # NonceStore 可插拔（Memory/Sqlite/Redis）
├── runtime.py               # 运行时（agent-cryptid 的入口逻辑）
├── demo.py                  # 端到端 demo
├── check_sm2.py             # SM2 自检（17 项）
├── check_v01.py             # v0.1 自检（26 项）
├── check_v1.py              # v1.0 持久化/多租户（19 项）
├── check_v2.py              # v2.0 累加器集成（9 项）
├── check_v3.py              # v2.1 NonceStore（6 项）
├── check_v4.py              # v2.2 审计锚点（7 项）
├── check_v5.py              # v2.3 锚点持久化（5 项）
├── check_v6.py              # v2.4 累加器状态持久化（5 项）
├── check_v7.py              # v2.7 SM9 集成（22 项）
├── check_v8.py              # v2.8 HTTP/ASGI/委托链 SM9 端到端（37 项）
├── bench_sm2.py             # SM2 性能基准
└── *_report.txt             # 各模块自检报告
```

## 算法档位

| 档位 | 标准 | 签名 | 验签 | 特性 |
|---|---|---|---|---|
| `sm2` | GB/T 32918.2 | 2.5ms | 3.2ms | 短效凭证，PRD 达标 |
| `sm9` | GB/T 38635 | 152ms | 221ms | 无证书标识，适配海量分钟级生灭 |
| `sm2-ml-dsa` | SM2 + ML-DSA | — | — | 中期凭证，抗量子 |
| `hash-signature` | 自研 | — | — | 长存证离线冷签 |

## 快速开始

```bash
cd agent-cryptid/proto

# 端到端 demo
python entrypoint.py

# 完整验证（326 项全 PASS）
python entrypoint.py --check

# 10 API 烟测
python entrypoint.py --smoke

# HTTP API 烟测
python entrypoint.py --http
```

## 生产部署

```bash
pip install uvicorn
export AC_DB=/var/lib/agent-cryptid/prod.db
uvicorn asgi_app:app --host 0.0.0.0 --port 8000 --workers 4
```

详见 [DEPLOY.md](DEPLOY.md)。

## 验证矩阵（v2.8）

| 模块 | 项数 | 结果 |
|---|---|---|
| check_sm2 | 17 | PASS |
| check_v01 | 26 | PASS |
| check_v1 | 19 | PASS |
| sm2_fast | 12 | PASS |
| revocation | 36 | PASS |
| check_v2 | 9 | PASS |
| nonce_store | 9 | PASS |
| check_v3 | 6 | PASS |
| asgi_app | 18 | PASS |
| audit_anchor | 14 | PASS |
| check_v4 | 7 | PASS |
| check_v5 | 5 | PASS |
| check_v6 | 5 | PASS |
| auth | 22 | PASS |
| sm9 | 28 | PASS |
| check_v7 | 22 | PASS |
| check_v8 | 37 | PASS |
| platform smoke | 10 | PASS |
| http_api smoke | 24 | PASS |
| **GRAND TOTAL** | **326** | **PASS=326 FAIL=0** |

## 关键设计决策

1. **控制面/数据面分离**：校验本地化（公钥 + 撤销快照本地缓存），无网络往返。
2. **主体标识与发起方标识分离**（sub / act），防混淆代理人攻击。
3. **受众字段**防跨服务挪用；**一次性随机数**防重放；**算法档位纳入签名覆盖**防降级攻击。
4. **凭证全文不在服务端留存**，只存撤销与统计元数据。
5. **SM9 无证书特性**：签发方只需持 ks，验签方只需 P_pub 与 ID，无需下发用户公钥。
6. **SM2/SM9 双档并行**：wire 格式自动识别（sig_s vs sig_s_x/sig_s_y），向后兼容零破坏。