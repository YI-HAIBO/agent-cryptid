# agent-cryptid × A2A / MCP 集成可行性方案

> 调研日期：2026-10-22（Step 0 已于同日完成，结论见 §五前置）
> 目的：评估 P0 补充实验「真实多智能体端到端 + A2A/MCP 集成」的可行性与工作量，
> 并判断它对 SCI 一区论文增量的价值。
> **结论先行：可行性高，且这是本项目目前能拿到的最强差异化论据——因为两大协议都在官方规范里
> 明确承认了「授权」与「多跳委托」缺口，而这两点恰好是 agent-cryptid 的核心能力。**
> **Step 0 补充结论：官方 SDK 本机已装通（`a2a-sdk 1.2.3` + `mcp 2.3.0`，见 §0），三个挂载点全部可达；
> 但 SDK 已演进为 proto-first 设计，早期设想的 `A2AStarletteApp` / pydantic `AgentCard` 路径不存在，
> 实际接入点见 §5.1（已按实测 API 更正）。**

---

## 0. Step 0 实测结论（2026-10-22 已完成）

**环境**：专用干净 venv `C:/Users/Yi/.workbuddy/binaries/python/envs/a2amcp/`（不污染 agent-cryptid 主环境）。
已装：`a2a-sdk 1.2.3`、`mcp 2.3.0`、`fastapi 0.159.1`、`starlette 1.9.0`。

> ⚠️ **两大 SDK 均已演进，与早前设想不同，接入点须按本节更正**：
> - **A2A 1.2.3 是 proto-first**：`AgentCard` 是 protobuf message（`a2a.types.AgentCard`，非 pydantic）；
>   高层便捷类 `A2AStarletteApp` **已不存在**；`AgentCard` 无 `url` 字段（改为 `supported_interfaces`），
>   也无顶层 `extensions` 字段（扩展改为 HTTP 头协商，见 MP1）。
> - **MCP 2.x**：`FastMCP` 已更名为 **`MCPServer`**（`from mcp.server.mcpserver import MCPServer`）。

**已确认可达的真实 API（Step 0 逐条探明）**：

| 能力 | 真实 API 路径 | 结论 |
|---|---|---|
| A2A 服务入口 | `from a2a.server.routes import add_a2a_routes_to_fastapi(app)` + `DefaultRequestHandler(agent_card=, agent_executor=, task_store=InMemoryTaskStore())` | ✅ 需 `pip install fastapi uvicorn`（已装） |
| A2A 无 DB 演示 | `from a2a.server.tasks import InMemoryTaskStore` | ✅ |
| A2A Agent Card 字段 | `name, description, supported_interfaces, provider, version, documentation_url, capabilities, **security_schemes**, **security_requirements**, default_input_modes, default_output_modes, skills, signatures, icon_url` | ✅ `security_schemes`/`security_requirements` 在，MP1 有据 |
| A2A 扩展机制 | `from a2a.extensions.common import AgentExtension, HTTP_EXTENSION_HEADER, get_requested_extensions, find_extension_by_uri`；`AgentExtension`=proto(`uri, description, required, params`) | ✅ 扩展按 URI 头协商 |
| A2A 校验注入点 | ① app 上加自定义 **FastAPI 中间件**（在 `add_a2a_routes_to_fastapi` 之前）；② 自定义 `RequestContextBuilder`（把 `Authorization` 头塞进 `RequestContext.metadata` / `requested_extensions`）；③ 包一层 `AgentExecutor`。`RequestContext` 有 `.metadata/.requested_extensions/.call_context/.message` | ✅ 三条路均可 |
| MCP 服务入口 | `from mcp.server.mcpserver import MCPServer`；`MCPServer(name=, token_verifier=, ...)`；`.streamable_http_app()` / `run_streamable_http_async()` | ✅ |
| **MCP 校验注入点** | `TokenVerifier` Protocol（`mcp.server.auth.provider`）：`async def verify_token(self, token: str) -> AccessToken \| None`，**返回 `None` 即拒绝**；传给 `MCPServer(token_verifier=...)`。另有 `mcp.server.auth.middleware.bearer_auth.BearerAuthBackend` 封装 | ✅ 这就是 cryptid 校验函数的天然落点 |

**Step 0 判定：PASS**——官方 SDK 可装可跑，三个挂载点全部可达，无需退到「自建端点」降级路线
（对论文诚实性有利：可名正言顺写「集成官方 A2A/MCP SDK」）。

### 0.1 Step 1 已完成：端到端 demo 14/14 PASS（2026-10-22）

新增 `research/integration/` 四个文件（a2amcp venv 运行）：

| 文件 | 作用 | 自测 |
|---|---|---|
| `cryptid_bridge.py` | 纯桥（**零 SDK 依赖**）：wire dict ↔ base64url Bearer token 编解码 + `verify_bearer`（复用 `Platform.verify_credential` 的 aud/scope/nonce/撤销） | 11/11 |
| `mcp_guard.py` | `CryptidTokenVerifier`（结构化满足 TokenVerifier 协议）+ `build_protected_mcp_server` | 7/7 |
| `a2a_guard.py` | `CryptidAuthMiddleware`（纯 ASGI）+ `build_a2a_app`（中间件 + 真 A2A 路由 + echo executor） | 7/7 |
| `demo_step1.py` | 端到端：1 worker 持 cryptid 凭证，同时调 1 个 MCP server + 1 个 A2A agent | **14/14** |

**demo 实测结论（攻击全拒、正常全放行）**：
- MCP（真实 streamable HTTP，走 `BearerAuthBackend → TokenVerifier`）：有效 token → 工具真正执行（200 + "PAID"）；无 token / 畸形 token / **受众不符（passthrough）** / 已撤销 → 全 401。
- A2A（真实 JSON-RPC，中间件守 `SendMessage` + agent-card）：有效 token → echo 回复；无 token → 401；**把签给 MCP 的 token 透传给 A2A agent → 401**（跨协议 passthrough 防御）。

**Step 1 踩坑（写进记忆，后续复用）**：
1. MCP `streamable_http_app` 需 lifespan 初始化 task group → **TestClient 必须用 `with ... as c:` 上下文**。
2. MCP 传输层 DNS-rebinding 校验会拒 TestClient 的 `Host: testserver`（421）→ 本地测试传 `TransportSecuritySettings(enable_dns_rebinding_protection=False)`。
3. **nonce 一次性**：每个 HTTP 请求要用**新 token**（initialize 会消耗 nonce，同 token 二次用即 replay→401）。
4. A2A JSON-RPC 方法是 **PascalCase `SendMessage`**（非 `message/send`），须带 **`A2A-Version` 头**（缺省按 0.3，与 handler 期望 1.0 冲突报 -32009），params 形如 `{"message": {...}, "configuration": {...}}`。
5. `AgentCard` 需补齐 required 字段（`supported_interfaces`/`capabilities`/`default_input_modes`/`default_output_modes`/`skills[].tags`），否则互操作告警。
6. `AuthSettings` 需 `issuer_url` + `resource_server_url` + `validate_token_resource=False`（cryptid aud 形如 `service://xxx` 非 http URL，交 SDK URL 比对会误拒）。
7. protobuf 构造：`Part(text=...)` 直接建、`Role.Value("ROLE_AGENT")`。

### 0.2 Step 2 已完成：E10 集成攻击实验 8/8 全拒（2026-10-22）

新增 `research/integration/e10_integration_attacks.py`，把 §5.3 四条攻击脚本化，打到**真实集成 seam**：
MCP 侧驱动 `TokenVerifier.verify_token`（BearerAuthBackend 正是调用它），A2A 侧驱动 `CryptidAuthMiddleware`
（经 TestClient 走真 ASGI），委托侧驱动 `Platform.verify_delegation_chain` / `issue_delegation`。

| 攻击 | 边界 | 结果 | 机制 |
|---|---|---|---|
| Token 透传（aud=A 的 token 用于 server B） | MCP TokenVerifier | ✅ 拒（返 None） | aud 绑定（≡ RFC 8707 resource） |
| Token 透传（MCP token 透传给 A2A agent） | A2A 中间件 | ✅ 拒（401） | aud 绑定 |
| 多跳越权（子 scope ⊋ 父） | 委托签发侧 | ✅ 拒（reason=scope escalation） | 签发侧 scope 收敛 |
| 多跳越权（绕过签发侧构造超 scope 子凭证） | 委托链验签器 | ✅ 拒（scope_ok=False） | 交集收敛（effective ⊆ parent） |
| 混淆代理人（篡改 act 冒充委托根） | MCP TokenVerifier | ✅ 拒（签名失效） | sub/act/origin 进签名覆盖 |
| 混淆代理人（同上） | A2A 中间件 | ✅ 拒（401） | sub/act/origin 进签名覆盖 |
| 算法降级（剥混合签名 pq_sig） | MCP TokenVerifier | ✅ 拒（失败关闭） | PQ 分量失败关闭 |
| 算法降级（同上） | A2A 中间件 | ✅ 拒（401） | PQ 分量失败关闭 |

**8/8 攻击全拒**，且**正向对照通过**（合法 token 在 MCP/A2A 两端都被接受）——证明拒绝是有意义的，非一律拒绝。

**挂入 eval_framework**：新增可选 `_try_E10()` 钩子——a2amcp venv 下真实运行 E10；默认 venv 缺 a2a/mcp 时
优雅跳过（`skipped=True`，不影响 E1–E7）。返回 schema 与 E3 一致（attacks/n_attacks/all_rejected），
产出 `eval_E10_integration.csv`。E10 属**负载无关的正确性/安全断言**（与 E3/E4/E5/E7 同类），结论稳定可引用。

复跑：
```bash
# a2amcp venv
python research/integration/e10_integration_attacks.py
# 或并入框架（默认 venv 自动跳过 E10）
python research/eval_framework.py --quick
```

### 0.3 Step 3 已完成：卡片显式声明 + 3 跳委托链 26/26 PASS（2026-10-22）

**MP1 从「中间件隐式」升级为「卡片显式」**——`a2a_guard._make_agent_card()` 现在把 cryptid 正式声明
进 A2A Agent Card 的三处规范机制（非自由 `x-` 字段）：

| 声明位 | 内容 |
|---|---|
| `security_schemes["cryptid-bearer"]` | `http_auth_security_scheme`（scheme=bearer, bearerFormat=agent-cryptid） |
| `security_requirements` | `[ {cryptid-bearer: []} ]`（protobuf 的 `StringList`，注意不是裸 list） |
| `capabilities.extensions` | `AgentExtension(uri="urn:agent-cryptid:1.0", params={alg_tiers, aud_field, resource_indicator, expected_aud})` |

`GET /.well-known/agent-card.json` 返回的 JSON 已逐字段验证含上述三项。MCP 侧的等价「声明」是
`AuthSettings(resource_server_url=)` + `AccessToken.resource = aud`（MCP 无 card 概念，resource
indicator 即其声明位）。

**3 跳委托链跨协议演示** `research/integration/demo_step3.py`（26/26 PASS），对应「缺口 2：A2A
多跳委托是 open issue」：

```
根  ISSUER --[read,write,delete]--> A    issue_credential, depth 0
跳1 A      --[read,write]-------> B    issue_delegation, depth 1, parent_verified=True
跳2 B      --[read]-----------> C    issue_delegation, depth 2, parent_verified=True
```

| 断言 | 结果 |
|---|---|
| depth 沿链 0→1→2、每跳 parent_verified=True、scope 3→2→1 收窄 | ✅ |
| `verify_delegation_chain` 3 跳：交集收敛到 `{invoice:read}`，scope/audience 均满足 | ✅ |
| 向链索取 `read+write` → 交集不足被拒 | ✅ |
| C 持链尾凭证调 MCP 工具（真 streamable HTTP）→ 200 + PAID | ✅ |
| **同一张链尾凭证**调 A2A agent → 401（aud 绑定穿越委托链存活） | ✅ |
| 攻击一 越权跳（B 给 C 加 `invoice:admin`）→ 签发侧拒，reason=scope escalation，报告 escalated | ✅ |
| 攻击二 撤销祖先（根凭证）→ 整链验链失败，reasons=`['hop 0: revoked', ...]` | ✅ |
| 攻击三 `max_delegation_depth=3` → 深度 1/2/3 允许，第 4 跳拒（would_be_depth=4） | ✅ |

**复用的既有能力（无需新写密码学）**：`issue_delegation(parent_cred=)` 的签发侧 scope 收敛、
`_register_cred(depth=)` 血缘登记、`verify_delegation_chain` 的交集计算 + 逐跳撤销检查
（`reasons` 精确定位到 `hop 0: revoked`）。

两个易踩的计数坑（已固化）：
1. `issue_credential` 的返回**不含** `depth`（keys = alg_tier/cred/exp/iat/jti/ok）；根凭证 depth=0
   只存在于 `_cred_registry[jti]["depth"]`，只有 `issue_delegation` 才在返回里带 `depth`。
2. 深度判定是**严格大于**（`new_depth > max_depth`），所以 `max_delegation_depth=3` 允许深度
   1/2/3，第 4 跳（would_be_depth=4）才被拒——不是"3 跳后立刻拒"。

复跑：`python research/integration/demo_step3.py`（a2amcp venv）

### 0.4 Step 4 已完成：官方 TCK 合规 + 多语言互操作 + E11 可扩展性（2026-10-22）

#### 0.4.1 官方 A2A TCK 合规矩阵（四形态对照）

用官方 `a2aproject/a2a-tck`（commit `5daf014`，pytest，RFC 2119 MUST/SHOULD/MAY 分层，
`reports/compatibility.{json,html}`）对 `research/integration/sut_a2a_server.py` 的四形态
SUT 逐一实测。报告归档在 `research/integration/tck_reports/{baseline,gated,gated-noplugin,
gated-authenticated}/`。

| 形态 | 卡片 | 操作 | TCK 带凭证 | overall | must | 与 baseline 逐条状态一致 |
|---|---|---|---|---|---|---|
| `baseline` | 公开 | 公开 | — | 32.9% | 31.9% | — |
| `gated` | 公开 | cryptid | 否 | 18.2% | 20.3% | 83/129 = 64.3%（差异 46 条） |
| `gated-noplugin`（控制组） | 公开 | cryptid | 否 | 18.2% | 20.3% | 83/129 = 64.3%（差异 46 条） |
| `gated-authenticated` | 公开 | cryptid | **是** | **32.9%** | **31.9%** | **129/129 = 100.0%（Δ=0）** |

**核心结论：cryptid 授权层与 A2A 合规度正交。** 129/129 条 requirement 状态完全一致，
Δ=0——加上授权后 A2A 功能一项不减。掉分不是 A2A 语义回退。

**掉分是度量假象，根因是官方 TCK 没有任何认证入口**（三处证据）：

1. `conftest.py::agent_card` → `httpx.get(url)` 不带任何 header
2. `conftest.py::transport_clients` → `JsonRpcClient.__init__(self, base_url: str)` 只吃 URL，
   不接受 headers / auth / token
3. `run_tck.py` / `pytest_addoption` → CLI 只有 `--sut-host / --transport / --level /
   --webhook-host`，**无** `--header` / `--token` / `--auth`

而 A2A 规范 AUTH-SERVER-002 要求 "Server MUST authenticate every incoming request"。
于是**任何被授权门禁保护的合规 A2A 服务，用官方 TCK 都测不出来**——这是个规范级缺口，
值得单独写进论文（见 §四增量价值）。

**`card-gated` 反例**：卡片连发现都锁 → TCK 第 1 步就 401，`rc=2` 无法发现服务、报告为空
（`overall=-`）。证明必须保留 §8.2 的公开发现，授权只能加在操作上。

补齐凭证的做法 `tck_auth_plugin.py`：**不改 TCK 一行源码**，作为 pytest 插件 monkeypatch
`httpx.get` 与 `httpx.Client.__init__`，给 TCK 全部出站请求注入 Bearer。只影响测试进程
自己的请求，被测服务未改动。控制组（`--no-plugin`，同 SUT 同 token 但不注入）掉回 18.2%
且 46 条状态改变，隔离出「认证」这一个变量。

**剩余的 32.9% 天花板与 cryptid 无关**——是极简 echo SUT 的性质：返回 `Message` 而非完整
`Task` 生命周期（`DM-TASK-*` / `DM-ART-*` / `DM-STATUS-*`）、无 push notification 能力声明
（`CORE-CAP-*`）、无 `Cache-Control` 头（`CARD-CACHE-*`）、无 SSE（`JSONRPC-SSE-001`）。
这些是 A2A 功能完整度问题，与身份层正交。

复跑：`python research/integration/run_tck_step4.py`（baseline/gated/card-gated）、
`python research/integration/run_tck_authenticated.py`（补凭证 + `--no-plugin` 控制组）

#### 0.4.2 多语言互操作：两类异构客户端 14/14 PASS

`research/integration/demo_step4_multilang.py` 用**同一张凭证、同一个 gated SUT**
驱动两类客户端，各自独立发请求。

| 客户端 | 栈 | 结果 |
|---|---|---|
| `http_only_client.py` | Python 标准库 `urllib`，**零 A2A SDK** | **8/8 PASS** |
| `jsclient/multilang_client.mjs` | 官方 `@a2a-js/sdk` 1.3.0，Node v22.22.2 | **6/6 PASS** |

正向：纯 HTTP 得 `cryptid-verified echo: hello via pure http`；Node SDK 得
`cryptid-verified echo: hello from node`。同一份 Python 端 SM2 验签，服务端零改动。

四类负向对照在**两个客户端上一致被拒**（HTTP 401）：无凭证（`missing token`）、
伪造 Bearer（`malformed token`）、篡改凭证尾部破坏签名（`malformed token`）、
`aud` 改写为 MCP 域（跨协议挪用，签名同时失效）。

**协议级而非 SDK 级的接入面**——cryptid 只占用 A2A 早已定义好的两个标准位置：
`GET /.well-known/agent-card.json`（§8.2 无鉴权发现）+ `POST /` JSON-RPC
`SendMessage` + 标准 `Authorization: Bearer` 头 + `A2A-Version: 1.0`。不引入任何 SDK
绑定成本，换 curl / Java / Go / Rust 都是同一份协议面。

顺带探明的 SDK 序列化坑（可写进论文的互操作细节）：`@a2a-js/sdk` 1.3.0 是
proto-first，文本 Part 走 protobuf oneof 形态 `content: {$case:"text", value}`，
**不是**裸 `kind/text`。用 `kind/text` 发出去服务端能收（不报错）但收到空消息——
静默丢数据。手搓客户端必须用 `kind/text`，走 SDK 必须用 `content/{"$case","value"}`。

复跑：`python research/integration/demo_step4_multilang.py`（自带 SUT，含
`--external/--token` 复用外部 SUT）

#### 0.4.3 E11 可扩展性压测（NFR-04：十万标识 / 5000 TPS）

`research/integration/e11_scalability.py`，已挂入 `eval_framework.py --e11`（默认不跑，
负载相关）。CSV：`eval_E11a_scale.csv` / `eval_E11b_issue_tps.csv` /
`eval_E11c_chain_depth.csv` / `eval_E11d_concurrent_verify.csv`。

| 子实验 | 结论 | 数字 |
|---|---|---|
| E11a 标识规模 | **服务路径 O(1) 于标识数** | N×10（300→3000）：校验中位 ×1.041，签发中位 ×1.023 |
| E11a 十万外推 | 十万标识可**持有** | 注册 35.3ms/个 → 外推 58.8 分钟单线程（配置期批处理，非逐请求路径） |
| E11e 并行瓶颈归因 | **GIL 是瓶颈，已实测确立** | **线程加速比 1.00×**（1→8 线程 187.2→180.2 TPS，无收益甚至下降）vs **进程加速比 6.08×**（1→16 进程 165.8→1008.4 TPS）→ 并发只能靠**进程级**并行，线程方案无解 |
| E11e 单机吞吐上限 | **5000 TPS 未达标（如实披露）** | 单实例稳态 **166 TPS**；**单机峰值 1008 TPS @ 16 进程**（效率 38%）；达 5000 TPS 须 **≥5 台本机规格横向扩容** |
| E11e 线性外推偏差 | **外推不可信，高估 163%** | 按核数外推得 2653 TPS vs 实测峰值 1008 TPS。容量估算须按实测峰值效率（每实例实际贡献 63 TPS），理想外推会得出 31 实例的乐观错值 |
| E11c 委托链深度 | **线性，无放大** | 每跳恒定 +4.85ms（quick）/ +6.64ms（full，10 跳 67.05ms） |
| E11d 并发校验 | 中位稳、**尾延迟爆** | 中位抬升仅 3.5%（NFR-02 达标）；但 P99 从 12.03ms → 824.77ms（16 线程，放大 69×） |

> **取数口径警告**：`e11_scalability.py --full` **串行跑会污染基线**——E11a 注册
> 1.1 万标识后，E11b/E11e 的 W=1 基线被压低（12ms/op vs 安静 6ms/op），表现为
> **并行效率 >100%**（物理不可能）。代码已内置该污染自检。**论文引用绝对数字
> 请用 `e11_clean_parallelism.py --csv`**（无前置负载，约 50s，自带污染自检）。

**NFR-04 判定：整体未闭环**（吞吐子目标未达标即整体不算闭环）。十万标识持有侧已闭环，吞吐侧未达标。

两条值得单独写进论文的工程结论：
1. **「十万标识」是持有问题不是查询问题**——校验/签发对标识规模 O(1)，容量瓶颈在
   配置期批处理与持久层，不在服务路径。
2. **「中位达标 ≠ 并发达标」**——GIL 下中位几乎不抬升，尾延迟（P99）放大 **69×**
   （16 进程并发校验：中位通胀在噪声内，P99 从 12.0ms 涨到 824.8ms，max 1.57s）。
   NFR-02 按中位口径达标，但并发场景必须按 P99 设 SLO。5000 TPS 只能靠进程级并行
   或国密芯片 / C 扩展（v3.0 硬件根路线），**不能**靠线程。

- **引用并行度/吞吐绝对值**：`python research/integration/e11_clean_parallelism.py --csv`
  （干净测量，约 50s，含线程+进程对照与污染自检；产物 `eval_E11e_clean_parallelism.csv`）
- **全套六项**：`python research/integration/e11_scalability.py --full`
  （约 17 分钟；或 `eval_framework.py --e11 --full`）——注意其绝对数字受串行污染，
  仅用于看六项整体形态，取数请用上一条

---

## 一、结论摘要

| 维度 | 判断 |
|---|---|
| 技术可行性 | **高**。两者鉴权都走 HTTP `Authorization: Bearer`，agent-cryptid 的 wire 凭证（JWT-like）可直接承载，零协议改动即可接入 |
| 工作量 | P0 最小可演示集成 **约 3–5 人日**（含 demo）；完整 TCK 级合规 3–4 周 |
| 对本机环境依赖 | **中等**——需 `pip install a2a-sdk mcp`（Python 官方 SDK 均存在），本机负载重但正确性演示不受影响 |
| 论文价值 | **极高**（详见 §四）。把论文从「又一个身份框架」抬到「补上 A2A/MCP 官方承认的缺口」 |
| 主要风险 | 规范仍在演进（A2A roadmap Q3 2026 有联合互操作规范）→ 论文须声明「对齐版本」 |

---

## 二、两大协议的授权现状（带出处）

### 2.1 A2A（Agent2Agent）v1.0，Linux Foundation 治理

| 项目 | 现状 |
|---|---|
| 版本 | v1.0.0（2026 年初，首个稳定版，TSC 含 AWS/Google/MS/IBM/Salesforce 等） |
| 认证 | 在 **HTTP 传输层**，非协议语义层。支持 API Key / Bearer / OAuth2 / OIDC / **mTLS**；v1.0 移除 implicit 与 password flow，加 PKCE、Device Code |
| **授权** | ⚠️ **规范不定义标准授权框架，官方自承是 gap**："The A2A specification does not define a standard authorization framework. **This is a recognized gap.**" |
| Agent Card | v1.0 起支持 **JWS + RFC 8785 规范化签名**（但仍是 *supports but does not enforce*） |
| **多跳委托** | ⚠️ **明确列为 roadmap 开放问题**："Agent identity, delegation, and enforcement... addressing **open issues** in the GitHub repository around **multi-hop delegation**" |
| Task | 生命周期含 `AUTH_REQUIRED` 态，客户端可把授权请求**继续向上委托**（形成 Task 链） |

### 2.2 MCP（Model Context Protocol）

| 项目 | 现状 |
|---|---|
| 授权基础 | **OAuth 2.1**（IETF draft），MCP server = OAuth 2.1 **resource server** |
| 关键机制 | RFC 9728 受保护资源元数据（server **MUST**）；RFC 8707 **Resource Indicators**（client **MUST** 发送）；PKCE-S256 强制 |
| **Token 透传** | ⚠️ **明令禁止**：安全最佳实践点名两种失败模式——**audience validation failures** 与 **passthrough** |
| 委托 | 无原生委托机制；多跳场景只能「重新走授权码流程」（需人工交互，无法自动化） |

---

## 三、三个被官方承认的缺口 → agent-cryptid 的落点

这是本次调研最有价值的发现。**缺口不是我们臆断的，是规范自己写的。**

### 缺口 1：A2A 没有授权框架（规范自承）

- A2A 只解决「你是谁」（认证），把「你能干什么」（授权）完全交给实现方自定。
- **落点**：agent-cryptid 的 `scope` + **scope 收敛** + `aud` 受众绑定，正好是 A2A 缺的那一层。
- 论文写法：*"A2A v1.0 delegates authorization entirely to implementers; we supply a cryptographic authorization layer with provable scope convergence."*

### 缺口 2：A2A 多跳委托是 open issue（roadmap 明列）

- A2A 的 Task 链天然形成委托链（A 调 B，B 再调 C，授权请求可逐级上抛），但**如何追踪与审计这条链**未定义。
- **落点**：agent-cryptid 的委托链（每跳签名、scope 严格收敛、子级 exp 不超父级）+ `sub`/`act`/`origin` 三字段，正是「delegation chains tracked and audited」的答案。
- 尤其 `origin` 字段直击 A2A 未建模的**混淆代理人**问题。

### 缺口 3：MCP 禁止 token 透传，却没给替代方案（两难）

这是**最漂亮的一击**：

- MCP 禁止透传同一个 token（否则 audience 校验失效）→ 多跳调用时，下游 agent 拿什么凭证？
- 现有唯一出路：重新走 OAuth 授权码流程 → **需要资源所有者在场，无法自动化**，与自主智能体的前提直接冲突。
- **agent-cryptid 给出第三条路**：每一跳签发**子凭证**（scope 收敛、绑定 `act`/`origin`、可离线验证、可撤销），既不是透传（每跳凭证不同、`aud` 各自绑定），也不需要人工介入。
- **天然对齐**：MCP 的 RFC 8707 `resource` 参数 ≡ agent-cryptid 的 `aud` 字段——都是「把凭证钉死在特定资源上」。

### 附带缺口：两者均无后量子、无国密

A2A 与 MCP 的算法栈都是传统 OAuth/ECDSA/RSA。agent-cryptid 的**三档敏捷（SM2 → SM2+ML-DSA → SLH-DSA）** 是唯一可提供迁移路径的方案，直接命中「密码敏捷迁移」这条主线。

---

## 四、对论文的增量价值（重新定位）

把论文旗舰新颖点从「身份框架」升级为：

> **为 A2A 与 MCP 补上其官方承认缺失的密码学授权与多跳委托层，并以国密→后量子敏捷迁移实现失败关闭。**

这直接回应审稿人最可能的一句质疑——*"与 SAGA / BlockA2A 本质区别是什么？"* 答案变成：
**那些工作是在协议之外另起炉灶做身份，我们是嵌进 A2A/MCP 正在缺的那一层，且缺口由规范自己承认。**

建议在论文中新增一节 **§"Integration with A2A and MCP"**（约 1.5 页），含：
1. 一张「协议缺口 ↔ agent-cryptid 机制」映射表（就是本文 §三）
2. 架构图：A2A Agent Card 扩展 / MCP resource 绑定两个挂载点
3. 端到端演示：真实 A2A agent 调用链 + MCP 工具调用，攻击被拦的现场记录

---

## 五、集成技术方案

### 5.1 三个挂载点（均无需改协议，API 路径已按 Step 0 实测更正）

| 挂载点 | 做法（含真实 SDK 路径） | 侵入性 |
|---|---|---|
| **A2A Agent Card 声明 cryptid** | 不用自由 `x-` 字段（proto Card 无此位）；改用 **规范内两处**：① Card 的 `security_schemes` + `security_requirements` 声明一个 `http/bearer` 方案，`description` 指向 cryptid profile URI；② 用 `AgentExtension(uri="urn:agent-cryptid:1.0", params={算法档位})` 注册 cryptid 扩展，客户端经 `HTTP_EXTENSION_HEADER` 头协商、服务端 `get_requested_extensions(request)` 读取 | 零——均为标准机制 |
| **A2A / MCP 请求头** | cryptid wire 凭证（JWT-like，449 B）直接放进 `Authorization: Bearer <cred>`。A2A 侧由 FastAPI 中间件或 `RequestContextBuilder` 读出；MCP 侧由 `TokenVerifier.verify_token(token)` 读出。现有客户端本就会发 Bearer，**零改动接入** | 零 |
| **服务端校验中间件** | **A2A**：在 `add_a2a_routes_to_fastapi` 之前给 FastAPI app 挂自定义中间件（或自定义 `RequestContextBuilder` / 包 `AgentExecutor`）；**MCP**：实现 `TokenVerifier` 协议传给 `MCPServer(token_verifier=...)`。校验体复用 `proto/`：验签 → `aud` 绑定（= MCP resource URI，对齐 RFC 8707）→ scope 检查 → nonce → 累加器撤销 → 拒绝即抛/返 `None` | 仅服务端加中间件 |

### 5.2 委托链如何嵌入

- **A2A**：把委托链绑定到 **Task 链**。A 给 B 的凭证里 `origin=最终委托根`；B 再调 C 时签发子凭证（scope ⊆ 父）。A2A 的 `AUTH_REQUIRED` 上抛链与 cryptid 委托链同构，可一一对应。
- **MCP**：下游调用**不复用上游 token**（规避 passthrough），改为签发子凭证，`aud` = 下游 MCP server 的 canonical resource URI（RFC 8707 语义）。

### 5.3 演示攻击（对应 E3，可直接进论文）

| 攻击 | 在 A2A/MCP 语境下的表现 | 预期 |
|---|---|---|
| Token 透传（MCP 明令禁止项） | 把给 server A 的凭证原样用于 server B | 被 `aud` 绑定拒绝 |
| 多跳越权 | 第 2 跳的 scope 超出第 1 跳 | 被 scope 收敛拒绝 |
| 混淆代理人 | 下游冒充原始委托方 | 被 `origin`/`act` 分离拒绝 |
| 算法降级 | 剥掉 PQ 分量 | 被失败关闭拒绝 |

---

## 六、分步实施计划

| 阶段 | 任务 | 工作量 | 阻塞 |
|---|---|---|---|
| **Step 0（先验证）** | ~~`pip install a2a-sdk mcp`，确认本机可跑通官方最小示例~~ | ~~0.5 天~~ | ✅ **已完成**（2026-10-22）：官方 SDK 已装通、三挂载点 API 已逐条探明（见 §0） |
| **Step 1（P0）** | ~~写 cryptid 校验中间件 + Bearer 承载；跑通 1 个 A2A agent ↔ 1 个 MCP server 的端到端调用~~ | ~~2 天~~ | ✅ **已完成**（2026-10-22）：端到端 demo **14/14 PASS**（见 §0.1） |
| **Step 2（P0）** | ~~上述 4 条演示攻击脚本化，并入 `eval_framework` 作为 **E10 集成实验**~~ | ~~1.5 天~~ | ✅ **已完成**（2026-10-22）：E10 **8/8 攻击全拒** + 正向对照通过（见 §0.2） |
| **Step 3（P1）** | ~~A2A Agent Card `security_schemes` + `AgentExtension` 声明 + MCP resource 绑定；多跳（3 跳）委托演示~~ | ~~2 天~~ | ✅ **已完成**（2026-10-22）：卡片三处规范声明已落地并逐字段验证，3 跳委托链 demo **26/26 PASS**（见 §0.3） |
| **Step 4（P2）** | ~~对齐 A2A TCK、多语言 SDK、性能压测~~ | ~~3–4 周~~ | ✅ **已完成**（2026-10-22）：官方 TCK 四形态矩阵（**129/129 状态一致 Δ=0**）+ 多语言互操作 **14/14 PASS** + E11 可扩展性（NFR-04 未闭环，如实披露）（见 §0.4） |

**Step 0 已通过**，技术路线锁定为「官方 SDK」而非自建端点（对论文诚实性有利，见 §7.3）。

---

## 七、风险与诚实边界（论文必须写明）

1. **规范仍在演进**：A2A roadmap 列有「MCP 与 A2A 联合互操作规范，目标 Q3 2026」。论文须锁定并对齐具体版本（建议标注 A2A v1.0 / MCP 2026-07-28 spec）。
2. **Agent Card 签名非强制**：A2A v1.0 是 *supports but does not enforce*，因此不能声称「A2A 的身份问题已被解决」。
3. **官方 SDK 已装通**（Step 0），故本集成基于 **官方 `a2a-sdk` / `mcp`** 而非自建端点——这一点对论文诚实性有利；但仍须锁定并对齐具体 SDK 版本（`a2a-sdk 1.2.3` / `mcp 2.3.0`），因 SDK API 仍在演进（如 proto-first 迁移）。
4. **本方案不解决**：A2A/MCP 的传输层安全、Agent Card 声誉系统、跨组织策略框架——这些超出范围，作为 future work。

---

## 八、下一步

**Step 0–4 已全部完成**（P0 + P1 + P2 闭环）：

| Step | 优先级 | 产物 | 状态 |
|---|---|---|---|
| Step 0 | — | 官方 SDK 装通、三挂载点 API 探明（§0） | ✅ |
| Step 1 | P0 | 端到端 demo 14/14 PASS（§0.1） | ✅ |
| Step 2 | P0 | E10 集成攻击实验 8/8 全拒 + 正向对照（§0.2） | ✅ |
| Step 3 | P1 | 卡片显式声明 + 3 跳委托链 26/26 PASS（§0.3） | ✅ |
| Step 4 | P2 | 官方 TCK 四形态矩阵（129/129 一致）+ 多语言 14/14 + E11（§0.4） | ✅ |

**论文侧已可落笔的素材**（按增量价值排序；**1–3 及 6 已写入论文 v1.4，2026-10-23**）：

1. **官方 TCK 无认证入口**（§0.4.1）——规范级缺口，独立于 cryptid 也可发表：
   A2A 规范自己要求"Server MUST authenticate every incoming request"，但官方合规套件
   无法对任何受保护服务测出结果。用 `tck_auth_plugin.py` 补齐后 129/129 条 requirement
   状态与未加鉴权基线**完全一致（Δ=0）**，即"授权层与合规度正交"的可证结论。
2. **多语言互操作 14/14**（§0.4.2）——含**零 SDK 的纯 HTTP 客户端**，证明接入面是
   协议级而非 SDK 级；顺带定位了 `@a2a-js/sdk` proto-first oneof 静默丢数据的坑。
3. **E10 攻击拒绝率 8/8 + 正向对照**（§0.2），负载无关，与 E3/E4/E5/E7 同类可稳定引用。
4. **卡片显式声明**（§0.3）把 MP1 从中间件隐式升级为协议级声明（`security_schemes` +
   `AgentExtension`，非自由 `x-` 字段）。
5. **3 跳委托链收敛证明**（§0.3）——scope 交集 + 逐跳撤销定位 + 深度上界，直接回应
   A2A roadmap 的"多跳委托 open issue"。
6. **E11 的两条工程结论**（§0.4.3）——「十万标识是持有问题不是查询问题」（服务路径
   O(1)，1k→10k 标识校验中位 5.86→5.31ms 无退化）；「中位达标 ≠ 并发达标」（16 进程下
   中位通胀在噪声内，但 P99 从 12.0ms 涨到 824.8ms，**放大 69×**）。另有一条方法论结论：
   串行跑全套会自污染基线（E11a 大负载把 E11b/E11e 的 W=1 基线压低一倍，表现为效率
   >100%），已内置 `load_contaminated` 自检，论文取数一律走 `e11_clean_parallelism.py`。
   NFR-04 如实披露**未闭环**，不粉饰。

**下一步（v3.0 / 需外部基础设施，非本机可完成）**：
- 硬件根 / 侧信道防护 / 跨域撤销 / 真上链（PRD 二点零版 FR1-06）
- 国密芯片或 C 扩展承载 SM2，把单实例 166 TPS 拉过 5000——这是 NFR-04 唯一未闭环的
  子目标，且瓶颈已定位（标量乘在 GIL 下不可并行 → 进程级并行仅得 6.08×/16 进程，
  效率 38%，单机峰值 1008 TPS 仍差 5 倍）
- TCK 上游贡献：给官方 `a2a-tck` 提 PR 加 `--auth-header` 选项，把 §0.4.1 的插件化缺口
  补在规范侧（这本身是论文的独立贡献点）

商务待确认项不变（载体/启动资金/国密厂商/试点客户切入）。
