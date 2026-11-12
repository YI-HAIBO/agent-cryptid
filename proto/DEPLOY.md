# agent-cryptid 生产部署指南（v2.16）

面向企业运行时集成场景。中间件形态，嵌入企业智能体运行时。

## 一、快速启动（本地开发）

```bash
# 目录
cd agent-cryptid/proto

# 跑端到端 demo
python entrypoint.py

# 跑完整回归（10 API 烟测 + 全部 965 项验证，约 3 分钟）
python entrypoint.py --check

# 只跑 HTTP 层
python entrypoint.py --http

# 也可作为包调用（README 记录的入口）
python -m proto --check
```

## 二、生产部署（Uvicorn + ASGI）

### 1. 安装依赖

```bash
pip install uvicorn
# 可选：Redis 存 nonce（跨进程共享）
pip install redis
```

### 2. 启动 ASGI 服务

```bash
# 基本启动（内存存储）
uvicorn asgi_app:app --host 0.0.0.0 --port 8000

# 生产推荐：4 workers + SQLite 文件存储
export AC_DB=/var/lib/agent-cryptid/prod.db
export AC_DEFAULT_TENANT=prod
uvicorn asgi_app:app --host 0.0.0.0 --port 8000 --workers 4
```

### 3. 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `AC_DB` | `:memory:` | SQLite 数据库路径；生产用文件路径 |
| `AC_DEFAULT_TENANT` | `default` | 未指定 X-Tenant-Id 时的默认租户 |
| `AC_AUTH` | 空 | 鉴权配置：JSON 文件路径或直接 JSON |

### 4. 多租户（每租户一个 Platform 实例）

请求头 `X-Tenant-Id: <tenant-id>` 路由到独立 Platform。物理隔离：
- identities / revocations / audit_log / revocation_state / policy 表都按 tenant_id 分区
- 每个租户独立 IdentityAuthority（独立 ks / P_pub）

### 5. 鉴权（v2.5 起）

禁用鉴权（默认，向后兼容 demo）：
```bash
uvicorn asgi_app:app --port 8000
```

启用鉴权（配置文件）：
```json
{
  "auth": {
    "enabled": true,
    "keys": [
      {"key": "k-acme", "tenants": ["tenant-acme"], "note": "Acme Corp"},
      {"key": "k-globex", "tenants": ["tenant-globex"], "note": "Globex"},
      {"key": "k-admin", "tenants": ["*"], "note": "管理员"}
    ]
  }
}
```

```bash
export AC_AUTH=/etc/agent-cryptid/auth.json
uvicorn asgi_app:app --host 0.0.0.0 --port 8000 --workers 4
```

请求必须携带 `X-API-Key` 或 `Authorization: Bearer <key>`，且 key 授权的 tenants 必须包含请求的 `X-Tenant-Id`，否则返回 401/403。

配置里**只存 SM3 摘要**，不存明文 key。

### 6. 算法档位

默认策略允许 SM2 与 SM9 并存。可通过 `/v1/policy` 调整：

```bash
curl -X POST http://localhost:8000/v1/policy \
  -H "X-Tenant-Id: t1" \
  -H "Content-Type: application/json" \
  -d '{"allowed_algs": ["sm2", "sm9"], "max_ttl_seconds": 3600}'
```

- `sm2`：GB/T 32918.2，短生命周期凭证（NFR-01/02 达标，见第七节）
- `sm9`：GB/T 38635，无证书特性（签发方只持 ks，验签方只知 P_pub 与 ID）
- `sm2-ml-dsa`：混合档（v2.16）。SM2 与 ML-DSA-65 双签名，**失败关闭**
  ——两个分量都必须验过才接受。用于国密合规与抗量子并存场景
- `hash-signature`：SLH-DSA 档（v2.16），年尺度审计等长期存证场景

**降级攻击防护**：`alg_tier` 字段进入签名覆盖，篡改档位 → 校验失败；
跨档位串用（如把 SM2 签名伪装成抗量子档位）同样被拒。

> ⚠️ 抗量子档位为非国密算法。`hash-signature` 档**不含国密分量**，
> 启用前须就 NFR-06「禁用国际算法作为唯一依赖」单独评估。
> 合规报表（`compliance_report.py`）会自动采集并披露抗量子档位的使用。

### 7. HTTP API（42 条路由）

下表按功能分组列出。除下表外还有 `/health`、`/metrics`、`/stats`
（存活 / 指标 / 租户统计）三个运维端点。

**标识（FR1）**

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/v1/identities` | 注册智能体标识（含 tags） |
| GET | `/v1/identities` | 按 org/owner/tag/status/agent_type 检索（FR1-04） |
| POST | `/v1/identities/tags` | 更新标识标签 |
| POST | `/v1/identities/disable` | 停用标识 |
| POST | `/v1/identities/enable` | 重新启用标识（复用原密钥对） |
| POST | `/v1/identities/import` | 批量导入标识（FR1-07） |
| GET | `/v1/identities/export` | 批量导出标识（FR1-07） |
| POST | `/v1/keys/rotate` | 主密钥轮换（FR1-05） |
| GET | `/v1/keys/version` | 查询当前主密钥版本 |

**凭证（FR2）**

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/v1/credentials` | 签发凭证（支持 alg_tier） |
| POST | `/v1/credentials/verify` | 本地校验（无网络往返） |
| POST | `/v1/credentials/from-template` | 按模板签发（FR2-07） |
| POST | `/v1/credentials/renew` | 自动续期（FR2-04） |
| GET | `/v1/renewals/history` | 续期历史 |
| GET | `/v1/renewals/stats` | 续期统计 |
| GET/POST | `/v1/templates` | 凭证模板列表/新建（FR2-07） |
| GET | `/v1/templates/detail` | 模板详情 |
| POST | `/v1/templates/update` | 更新模板 |
| POST | `/v1/templates/delete` | 删除模板 |
| GET | `/v1/quota/usage` | 配额用量（FR2-06） |
| GET | `/v1/quota/stats` | 配额统计 |
| POST | `/v1/quota/reset` | 重置配额 |

**委托与撤销（FR3 / FR4）**

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/v1/delegations` | 委托（支持 alg_tier、parent_cred 收敛、max_depth） |
| POST | `/v1/delegations/verify` | 委托链验证（支持混合链） |
| POST | `/v1/revocations` | 撤销 |
| POST | `/v1/revocations/by-identity` | 按标识撤销（级联下游委托） |
| GET | `/v1/revocations` | 撤销快照 |
| GET | `/v1/revocations/prove` | Merkle 累加器撤销证明（FR4-04） |
| POST | `/v1/policy` | 策略配置（含 max_delegation_depth） |

**审计与治理（FR5 / FR6）**

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/v1/audit` | 审计检索 |
| POST | `/v1/audit/anchors` | 手动触发审计锚点签名 |
| GET | `/v1/audit/anchors` | 锚点列表 |
| GET | `/v1/audit/anchors/latest` | 最新锚点 |
| POST | `/v1/audit/anchors/verify` | 锚点验签 |
| GET | `/v1/governance/inventory` | 智能体清单与凭证统计 |
| GET | `/v1/governance/topology` | 委托链拓扑（`?root_idn=&include_revoked=`） |
| GET | `/v1/governance/permissions` | 实时权限视图（`?idn=`） |
| GET | `/v1/governance/alerts` | 异常告警扫描（`?window=&threshold=`） |

**接入扩展（FR7）**

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/v1/agent-cards` | 智能体卡片列表（FR7-03） |
| POST | `/v1/agent-cards/sign` | 卡片签名 |
| POST | `/v1/agent-cards/verify` | 卡片验签 |
| GET | `/v1/agent-cards/detail` | 卡片详情 |
| GET | `/v1/agent-cards/well-known` | well-known 发现端点 |
| GET | `/v1/orchestrator/tools` | 编排框架工具清单（FR7-04） |
| POST | `/v1/orchestrator/guard` | 工具调用决策点 |

**运维端点（NFR-10）**：
- `GET /health?mode=liveness|readiness` — 存活/就绪探针（readiness 降级返 503）
- `GET /metrics` — Prometheus 文本 + 业务/运行口径指标快照
- `GET /stats` — 租户对象计数

MCP 服务端鉴权（FR7-02，`mcp_adapter.py`，进程内组件非 HTTP 路由）：
- `MCPAuthzAdapter(platform, audience, tool_scopes)`
- `authorize_tool_call(cred, tool)` / `authorize_tool_call(chain=[...], tool)`
- `authorize_resource_read(cred, uri)` / `filter_tools(cred, tools)`
- `handle_request(method, params)` — MCP JSON-RPC 统一入口

合规报表（FR5-05 / NFR-11，`compliance_report.py`，进程内组件）：
```bash
python compliance_demo.py             # 生成示例报表三件套
```
```python
rep = ComplianceReport(plat, system_name="某智能体平台", assessor="某测评中心")
rep.save("out/")   # → .md（入册）/ .json（入系统）/ .csv（交表）
```
对齐 GB/T 39786 三项指标：身份鉴别、访问控制、不可否认性；
含密码算法合规性、密钥管理、完整性证明（审计链根 / 锚点验签 /
撤销累加器证明，均可独立复核）。证据不足时结论为「部分符合」并列出缺口。

审计锚点：
- `POST /v1/audit/anchors` — 手动触发锚点签名
- `POST /v1/audit/anchors/verify` — 离线校验
- `GET /v1/audit/anchors` / `latest`

### 8. 凭证 wire 格式

SM2：
```json
{
  "sub": "agent://org/sub",
  "iss": "agent://org/iss",
  "aud": "service://api",
  "scope": ["api:read"],
  "iat": 1728662400,
  "exp": 1728666000,
  "nonce": "abcdef...",
  "alg_tier": "sm2",
  "jti": "...",
  "sig_r": "0x...",
  "sig_s": "0x..."
}
```

SM9（多一个 sig_s_y）：
```json
{
  "alg_tier": "sm9",
  "sig_r": "0x...（h）",
  "sig_s_x": "0x...（S.x）",
  "sig_s_y": "0x...（S.y）"
}
```

两个抗量子档位都用 **`pq_sig` 字段**（内层为 JSON 字符串）承载分量。

混合档 `sm2-ml-dsa`（v2.16）：携带 **SM2 与 ML-DSA 两组签名分量**，
验签时两个分量都必须通过（失败关闭）：
```json
{
  "alg_tier": "sm2-ml-dsa",
  "sig_r": "0x...（SM2 r）",
  "sig_s": "0x...（SM2 s）",
  "pq_sig": "{\"ct\":\"...（c~ hex）\",\"z\":[[...]]（l×256 整数矩阵）}"
}
```

`hash-signature` 档（v2.16）：SLH-DSA 签名，`pq_sig` 内层含
`m`（消息）、`leaf`（叶子索引）、`sig[]`（WOTS+ 签名）、
`path[]`（认证路径），bytes 字段均为 hex：
```json
{
  "alg_tier": "hash-signature",
  "pq_sig": "{\"m\":\"...\",\"leaf\":123,\"sig\":[\"...\"],\"path\":[\"...\"]}"
}
```

> 抗量子签名体积远大于国密档位（ML-DSA `z` 为 5×256 个整数），
> 走 HTTP 或窄带链路时须评估载荷。

## 三、Docker 部署（可选）

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY proto/ /app/proto/
WORKDIR /app/proto
EXPOSE 8000
ENV AC_DB=/data/prod.db
VOLUME /data
CMD ["uvicorn", "asgi_app:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t agent-cryptid .
docker run -p 8000:8000 -v /var/lib/agent-cryptid:/data agent-cryptid
```

## 四、健康检查

```bash
# 存活
curl http://localhost:8000/health

# 租户统计
curl http://localhost:8000/stats
```

## 五、可观测性

SQLite 后端自带 `count_by_table()`：
```python
backend.count_by_table()
# {"identities": 12, "revocations": 3, "audit_log": 8,
#  "revocation_state": 1, "policy": 1, "audit_anchors": 5}
```

审计锚点离线可验证（无中心化信任根依赖），适合监管报送。

## 六、合规对齐

- GB/T 39786 密评：验签热态 P95 ≤5ms（SM2 路径）
- GB/T 37092 二级：SM2/SM3/SM9 三算法全支持
- 商用密码产品认证：需申请《证书》（外部流程）

## 七、性能基准

### 国密档位（v2.15 实测，单机）

| 指标 | 实测 | PRD 要求 | 结论 |
|---|---|---|---|
| 凭证签发 P99 | 5.40 ms | NFR-01 ≤50 ms | 达标（余量 9 倍） |
| 凭证本地校验 中位 / P99 | 4.66 / 5.05 ms | NFR-02 ≤5 ms | 中位达标，**P99 贴线无余量** |
| 十跳委托链验证 | 51.7 ms | NFR-03 ≤100 ms | 达标 |
| 撤销 → 拒绝 P99 | 460 ms | FR4-03 <1000 ms | 达标（余量约 2 倍） |
| 标识注册 | 34.7 ms/个 | NFR-04 十万 | 约 1 小时（单线程） |
| 签发吞吐 | 208 TPS（全程口径）/ 166 TPS（稳态口径） | NFR-04 5000 TPS | **未达标**：单机峰值 1008 TPS @ 16 进程（效率 38%），须 ≥5 台横向扩容或国密芯片/C 扩展 |
| SM2 签名 / 验签 | 2.51 / 3.20 ms | — | — |
| SM9 签名 / 验签 | ~150 / ~220 ms | — | 纯 Python，为 SM2 的 50–70× |

> 签发 P99 依赖 `Credential.sign(pub=...)` 复用注册时缓存的公钥。
> 不复用则每张凭证多一次标量乘（约 33 ms），P99 会从 5.4 ms 恶化到
> 58 ms，直接导致 NFR-01 不达标。**不要移除该参数。**

### 抗量子档位（v2.16 实测，纯 Python 原型）

| 操作 | 实测 |
|---|---|
| ML-DSA-65 keygen | 0.17 s |
| ML-DSA-65 签名（中位） | 0.34 s（单轮接受率约 24%，平均 3–4 轮） |
| ML-DSA-65 验签 | 0.032 s |
| SLH-DSA keygen | 18.9 s |
| SLH-DSA 签名 / 验签 | 约 0.07 s |

> 抗量子档位比国密档位慢 1–2 个数量级，仅适用于低频、长周期场景
> （如根凭证、年尺度审计），**不可用于高频签发路径**。

## 八、已知限制

### 需外部基础设施（PRD 明确定为本版不做）

1. **FR1-06 国密芯片 / TEE 承载标识私钥** — 未实现，PRD 排入二点零版
2. **FR4-06 跨域撤销传播** — 未实现，PRD 排入二点零版
3. **FR5-06 委托链摘要真上链存证** — 仅有 `audit_anchor.py` 的哈希链
   锚定雏形，非真上链，PRD 排入二点零版

### 环境依赖未闭环

4. **Redis 存 nonce** — `RedisNonceStore` 已实现，但本地无 Redis 服务时
   测试为「跳过」而非真验证；生产启用前需实连验证
5. **商用密码产品认证** — 需申请《商用密码产品认证证书》（外部流程）

### 指标未闭环

6. **NFR-04 吞吐侧未达标（已压测，口径见 E11）** —
   · **十万标识持有侧已闭环**：服务路径对标识数 O(1)（N×10 → 校验中位
     ×1.041、签发中位 ×1.023）；注册 35.3 ms/个，十万外推约 58.8 分钟单线程
     （配置期批处理，非逐请求路径）。
   · **5000 TPS 未达标**：单实例稳态 **166 TPS**，**单机峰值 1008 TPS @ 16
     进程**（并行效率 38%）。达 5000 TPS 须 **≥5 台本机规格横向扩容**，
     或迁移国密芯片 / C 扩展。
   · **并发只能靠进程级并行**：线程加速比 **1.00×**（1→8 线程 187.2→180.2
     TPS，无收益），进程加速比 **6.08×**（1→16 进程 165.8→1008.4 TPS）——
     GIL 是瓶颈，线程方案无解。
   · **不要用线性外推估容量**：按核数外推得 2653 TPS，比实测峰值 **高估
     163%**。容量估算须按实测峰值效率（每实例实际贡献 63 TPS）。
   · 复现：`python research/integration/e11_clean_parallelism.py --csv`
     （串行 `--full` 会污染基线，表现为效率 >100%，须用本脚本取数）
   · **SQLite 单文件架构在高并发下是否成为新瓶颈，仍未评估** —— 需先做
     存储层改造评估，才能判断横向扩容的实际收益
7. **NFR-09 国产化未验证** — 只验证到 Docker，未在国产 OS / 国产数据库
   上跑通
8. **NFR-02 校验 P99 贴线** — 实测 5.05 ms 对 5 ms 上限，无余量

### 抗量子档位的实现偏离（v2.17 更新）

9. ~~**ML-DSA 采用 full-t 公钥变体**~~ **已修复（v2.17）**：ML-DSA 已换回 FIPS 204 标准
   t1+hint 紧凑格式（`proto/mldsa.py`），公钥仅含 `t1`、签名携带 hint、验签用
   UseHint 重建 w1，**享有完整的 FIPS 204 可证明安全归约**。原 full-t 偏离已消除。
10. **SLH-DSA 为缩减演示参数集** — 非完整 FIPS 205，仅供原型演示
11. **抗量子档位非国密算法** — `hash-signature` 档不含国密分量，
    启用前须评估 NFR-06

### 其他

12. **SM9 性能** — 纯 Python 实现，签名约 150 ms、验签约 220 ms，
    为 SM2 的 50–70×；需优化时可用 ctypes 调 C 库
13. **撤销单次约 440 ms** — 瓶颈是每次撤销全量保存累加器状态快照，
    满足 FR4-03 一秒要求但余量仅约 2 倍

> 已消除的限制（供对照，勿再当作待办）：
> FR1-05 密钥轮换（v2.13 完成）、FR2-04/06/07（v2.12 完成）、
> FR7-03/04（v2.14 完成）、FR7-05（v2.13 完成）。

## 九、版本变更

### v2.16（本次交付）— 抗量子档位真实落地

- **`shake.py`（新建）**：纯 Python Keccak-f[1600] + SHA3-256/512 +
  SHAKE128/256，5 个 NIST 已知向量全通过，零依赖。
- **`mldsa.py`（新建）**：纯 Python ML-DSA-65（FIPS 204 Table 1 参数：
  k=6, l=5, d=13, η=4, τ=49, ω=55, γ1=2^19, γ2=(q-1)/32, β=196）。
- **`slhdsa.py`（新建）**：纯 Python SLH-DSA（SPHINCS+，缩减演示参数集）。
- **三档密码敏捷接线**：`credential.py` / `agent_platform.py` /
  `delegation.py` 完成 `sm2-ml-dsa`（SM2+ML-DSA 双签名，**失败关闭**）
  与 `hash-signature`（SLH-DSA）的签发、验签与 wire 序列化。
- **`check_v21.py`（新建）**：PQ 档位集成 29 项全通过。
- 修复 ML-DSA 拒绝采样 100% 拒绝的严重缺陷（两套分解被混用，见下）。

### v2.12 – v2.15（此前交付）

- **v2.15**：验收专项 18 项（撤销时效/性能/容量基线/私钥不落盘/控制面隔离）；
  签发路径性能优化，`Credential.sign(pub=...)` 复用缓存公钥，
  P99 58 → 5.4 ms，吞吐 26 → 208 TPS。
- **v2.14**：FR7-03 智能体卡片签名扩展（`agent_card.py`，自测 23 项）；
  FR7-04 编排框架插件（`orchestrator_plugin.py`，LangChain/AutoGen/CrewAI
  鸭子类型适配，自测 38 项）。**FR7 全 5 项完结**。
- **v2.13**：FR1-05 密钥轮换（`rotate_mk`/`rotate_ks` 版本化，凭证带 `kv`）；
  FR1-07 批量导入导出；FR7-05 CLI 工具（11 条命令）。
- **v2.12**：FR2-04 自动续期、FR2-06 速率限制、FR2-07 凭证模板。

### v2.11

- **NFR-10 可观测性**：`observability.py`，`/health?mode=` 与 `/metrics`
  端点，Prometheus 文本格式零依赖。
- **FR6 治理台**：`governance.py`，4 条只读聚合 HTTP 路由。
- **FR1-04 标识检索**：`list_identities` 与 `update_identity_tags`。
- **FR3-04 委托深度限制**：策略 `max_delegation_depth`。
- **安全增强**：verify_credential 所有拒绝路径入审计。

完整验证：`entrypoint.py --check`，**GRAND TOTAL PASS=970 FAIL=0**（v2.17 ML-DSA 换回标准 t1+hint 紧凑格式，新增 decompose 特殊情形 / power2round 往返 / hint 篡改检测 / 公钥紧凑格式 4 项自检，零回归）。
