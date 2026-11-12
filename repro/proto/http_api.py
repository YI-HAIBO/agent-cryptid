# -*- coding: utf-8 -*-
"""HTTP API 层：用 stdlib http.server 包装 Platform 10 个 API。

零外部依赖（无 Flask/FastAPI），Python 3.13+。

路由：
    GET  /health                健康检查（?mode=liveness|readiness）
    GET  /metrics               指标暴露（业务口径 + 运行口径）
    GET  /v1/identities         API-01b 检索标识（?org=&owner=&tag=&status=&agent_type=）
    POST /v1/identities         API-01 注册标识
    POST /v1/identities/disable API-02 停用标识
    POST /v1/identities/enable  API-02b 重新启用标识
    POST /v1/identities/tags    API-01c 更新标识标签
    POST /v1/credentials        API-03 签发凭证
    POST /v1/credentials/verify API-04 校验凭证
    POST /v1/delegations        API-05 委托签发
    POST /v1/delegations/verify API-06 验证委托链
    POST /v1/revocations        API-07 撤销
    GET  /v1/revocations        API-08 撤销快照（?since=N）
    GET  /v1/audit              API-09 审计检索（?kind=&idn=&limit=）
    POST /v1/policy             API-10 策略配置
    GET  /v1/governance/inventory       FR6-01 智能体清单
    GET  /v1/governance/topology        FR6-02 委托拓扑（?root_idn=&include_revoked=）
    GET  /v1/governance/permissions     FR6-02 实时权限视图（?idn=）
    GET  /v1/governance/alerts          FR6-05 异常告警（?window=&threshold=）
    GET  /v1/keys/version               FR1-05 密钥版本查询
    POST /v1/keys/rotate                FR1-05 主密钥轮换
    GET  /v1/identities/export          FR1-07 批量导出标识
    POST /v1/identities/import          FR1-07 批量导入标识
    POST /v1/agent-cards/sign           FR7-03 智能体卡片签名
    POST /v1/agent-cards/verify         FR7-03 智能体卡片验签
    POST /v1/agent-cards                FR7-03 发布卡片（签名并存库）
    GET  /v1/agent-cards                FR7-03 列出已发布卡片
    GET  /v1/agent-cards/detail         FR7-03 查单张卡片（?agent_idn=）
    GET  /v1/agent-cards/well-known     FR7-03 互联协议发布端点（?agent_idn=）
    POST /v1/orchestrator/tools         FR7-04 登记工具作用域
    GET  /v1/orchestrator/tools         FR7-04 列出工具（?audience=）
    POST /v1/orchestrator/guard         FR7-04 工具调用鉴权决策

多租户：请求头 X-Tenant-Id 指定租户；缺省使用 default。
"""
import json
import sys
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform
from persistence import SQLiteBackend
from auth import AuthTable
from observability import (HealthCheck, Metrics, Logger,
                           collect_platform_metrics)
import governance  # v2.11 FR6 治理台
# v2.12 三项新能力（惰性导入，避免未使用时的启动开销）
from rate_limit import RateLimiter, QuotaConfig  # FR2-06 速率限制
from templates import (TemplateRegistry, TemplateCredentialIssuer)  # FR2-07 模板
from renewer import Renewer  # FR2-04 自动续期
from agent_card import AgentCard, AgentCardSigner  # FR7-03 卡片签名
from orchestrator_plugin import OrchestratorPlugin  # FR7-04 编排插件


# ------------------------------------------------------------------
# 多租户 Platform 池：每个 tenant 一个 Platform 实例，共用一个 SQLite 后端
# ------------------------------------------------------------------
class TenantPool:
    def __init__(self, db_path=":memory:", default_tenant="default",
                 auth=None, metrics=None, logger=None,
                 rate_limiter=None, quota_config=None):
        self._db = SQLiteBackend(db_path)
        self._pool = {}
        self._default = default_tenant
        # v2.5：鉴权表。None / 空表 = 不鉴权（向后兼容 demo 与单测）
        self._auth = auth if isinstance(auth, AuthTable) \
            else AuthTable.from_config(auth)
        # v2.10 NFR-10：运行口径指标与日志
        self.metrics = metrics if metrics is not None else Metrics()
        self.logger = logger if logger is not None else Logger("http-api")
        # v2.12 FR2-06 速率限制：整个 pool 共享一个限流器（三级窗口
        # 内部按 tenant/identity/endpoint 维度分别计数）
        if rate_limiter is not None:
            self.rate_limiter = rate_limiter
        elif quota_config is not None:
            self.rate_limiter = RateLimiter(quota_config)
        else:
            self.rate_limiter = RateLimiter(QuotaConfig())
        # v2.12 FR2-07 模板注册表（per-tenant）与 FR2-04 续期器（per-tenant）
        self._template_registries = {}
        self._renewers = {}
        # v2.14 FR7-03 卡片签名器与卡片库（per-tenant）
        self._card_signers = {}
        self._card_store = {}       # tenant -> {agent_idn: card_dict}
        # v2.14 FR7-04 编排插件（per tenant + audience）
        self._orchestrators = {}

    def get(self, tenant):
        t = tenant or self._default
        if t not in self._pool:
            self._pool[t] = Platform(tenant=t, persistence=self._db)
        return self._pool[t]

    def get_template_registry(self, tenant):
        """取（或创建）某租户的模板注册表。"""
        t = tenant or self._default
        if t not in self._template_registries:
            self._template_registries[t] = TemplateRegistry()
        return self._template_registries[t]

    def get_renewer(self, tenant):
        """取（或创建）某租户的续期器，绑定其 Platform 与模板注册表。"""
        t = tenant or self._default
        if t not in self._renewers:
            self._renewers[t] = Renewer(
                self.get(t),
                registry=self.get_template_registry(t),
            )
        return self._renewers[t]

    def get_template_issuer(self, tenant):
        """取（或创建）某租户的基于模板签发器。"""
        t = tenant or self._default
        return TemplateCredentialIssuer(
            self.get(t), self.get_template_registry(t))

    # ---- v2.14 FR7-03 卡片 ----
    def get_card_signer(self, tenant):
        """取（或创建）某租户的卡片签名器，绑定其 Platform。"""
        t = tenant or self._default
        if t not in self._card_signers:
            self._card_signers[t] = AgentCardSigner(self.get(t))
        return self._card_signers[t]

    def get_card_store(self, tenant):
        """取某租户已发布的卡片库。"""
        t = tenant or self._default
        return self._card_store.setdefault(t, {})

    # ---- v2.14 FR7-04 编排插件 ----
    def get_orchestrator(self, tenant, audience):
        """取（或创建）某租户 + 受众下的编排插件。

        HTTP 侧只做鉴权决策（工具实现在框架进程内），因此工具以
        fn=None 登记，仅保存所需作用域。
        """
        t = tenant or self._default
        key = (t, audience)
        if key not in self._orchestrators:
            self._orchestrators[key] = OrchestratorPlugin(
                self.get(t), audience=audience)
        return self._orchestrators[key]

    @property
    def db(self):
        return self._db

    @property
    def auth(self):
        return self._auth

    @property
    def auth_enabled(self):
        return self._auth is not None and self._auth.enabled \
            and not self._auth.is_empty()

    def stats(self):
        return {
            "tenants": sorted(self._pool.keys()),
            "db_counts": self._db.count_by_table(),
            "auth_enabled": self.auth_enabled,
            # v2.12：新增速率限制统计与模板/续期计数
            "quota": self.rate_limiter.stats() if self.rate_limiter else {},
            "templates_per_tenant": {
                t: len(r.list()) for t, r in self._template_registries.items()
            },
            "renewals_per_tenant": {
                t: r.stats() for t, r in self._renewers.items()
            },
            # v2.14 FR7-03 / FR7-04
            "cards_per_tenant": {
                t: len(s) for t, s in self._card_store.items()
            },
            "orchestrator_tools_per_tenant": {
                "%s@%s" % (t, a): len(p.list_tools())
                for (t, a), p in self._orchestrators.items()
            },
        }


# ------------------------------------------------------------------
# 通用路由分发：与 HTTP 传输层解耦，供 stdlib http.server 与 ASGI 共用
# ------------------------------------------------------------------
def route(pool, method, path, query, body, tenant, api_key=None):
    """路由分发：返回 (status_code, payload_dict)。

    v2.10 NFR-10：外层负责运行口径埋点（请求数、错误数、时延），
    业务口径指标由 /metrics 路由从 Platform 采集，两者合并暴露。
    """
    import time as _t
    _t0 = _t.time()
    status, payload = _route_impl(pool, method, path, query, body,
                                  tenant, api_key)
    try:
        _m = getattr(pool, "metrics", None)
        if _m is not None:
            dt = (_t.time() - _t0) * 1000.0
            _m.inc_counter("requests_total", method=method, path=path,
                           status=str(status))
            if status >= 400:
                _m.inc_counter("requests_error_total", method=method,
                               path=path, status=str(status))
            _m.observe("request_duration_ms", dt, method=method, path=path)
    except Exception:
        pass  # 埋点失败绝不影响业务响应
    return status, payload


def _route_impl(pool, method, path, query, body, tenant, api_key=None):
    """路由分发：返回 (status_code, payload_dict)。

    pool     TenantPool
    method   "GET" / "POST"
    path     纯路径（无 query string）
    query    dict[str, list[str]]
    body     dict（GET 时可 None）
    tenant   租户 ID（来自 X-Tenant-Id）
    api_key  控制面 API Key（来自 X-API-Key）；启用鉴权后必填

    v2.5：启用鉴权时先校验 (api_key, tenant)，越权直接 403，
    不进入业务逻辑——横向越权是最容易被忽略也最致命的一类漏洞。
    v2.12 FR2-06：速率限制**在鉴权之前**——否则攻击者可以用海量
    鉴权失败的请求打爆服务（鉴权爆破兼 DoS）。
    """
    try:
        # v2.12 FR2-06：速率限制前置
        rl = getattr(pool, "rate_limiter", None)
        if rl is not None:
            # 从 body 提取主体标识用于标识级限流（多种字段兜底）
            identity = None
            if isinstance(body, dict):
                for k in ("subject_idn", "idn", "delegator_idn",
                          "issuer_idn", "delegatee_idn"):
                    v = body.get(k)
                    if isinstance(v, str) and v:
                        identity = v
                        break
            ok, why = rl.check(tenant=(tenant or pool._default),
                               identity=identity, endpoint=path)
            if not ok:
                return 429, {"ok": False,
                             "reason": why.get("reason", "rate limit exceeded"),
                             "level": why.get("level"),
                             "key": why.get("key"),
                             "retry_after": why.get("retry_after", 60)}

        # v2.5 鉴权前置（未启用时 check 恒返回 True，零成本）
        if pool.auth_enabled:
            ok, why = pool.auth.check(api_key, tenant)
            if not ok:
                status = 401 if why in ("missing api key",
                                        "unknown api key") else 403
                return status, {"ok": False, "reason": why,
                                "tenant": tenant}
        if method == "GET":
            if path == "/health":
                # v2.10 NFR-10：区分存活与就绪。
                # 就绪要看依赖（DB / 密钥 / 策略 / 审计链自洽），
                # 否则流量会打到「活着但干不了活」的实例上。
                mode = (query or {}).get("mode", ["readiness"])[0]
                hc = HealthCheck(pool.get(tenant))
                res = hc.check(mode)
                return (200 if res["status"] == "ok" else 503), {
                    "ok": res["status"] == "ok",
                    "service": "agent-cryptid",
                    "tenants": pool._default, "tenant": tenant, **res}
            # v2.10 NFR-10：指标暴露
            if path == "/metrics":
                m = collect_platform_metrics(pool.get(tenant),
                                             pool.metrics)
                return 200, {"ok": True, "tenant": tenant,
                             "snapshot": m.snapshot(),
                             "prometheus": m.render_prometheus()}
            if path == "/stats":
                return 200, {"ok": True, **pool.stats()}
            if path == "/v1/revocations":
                plat = pool.get(tenant)
                since = int((query or {}).get("since", ["0"])[0])
                return 200, plat.revocation_snapshot(since)
            if path == "/v1/revocations/prove":
                plat = pool.get(tenant)
                jti = (query or {}).get("jti", [None])[0]
                if not jti:
                    return 400, {"ok": False, "reason": "missing jti"}
                return 200, plat.verify_revocation(jti)
            if path == "/v1/audit":
                plat = pool.get(tenant)
                kind = (query or {}).get("kind", [None])[0]
                idn = (query or {}).get("idn", [None])[0]
                limit = int((query or {}).get("limit", ["100"])[0])
                return 200, plat.audit_query(kind=kind, idn=idn, limit=limit)
            if path == "/v1/audit/anchors":
                plat = pool.get(tenant)
                since_ts = (query or {}).get("since_ts", [None])[0]
                since_ts = int(since_ts) if since_ts else None
                limit = int((query or {}).get("limit", ["100"])[0])
                return 200, plat.list_audit_anchors(
                    since_ts=since_ts, limit=limit)
            if path == "/v1/audit/anchors/latest":
                plat = pool.get(tenant)
                return 200, plat.latest_audit_anchor()
            # v2.11 FR1-04：按条件检索标识
            if path == "/v1/identities":
                plat = pool.get(tenant)
                q = query or {}
                def _q(k):
                    return q.get(k, [None])[0]
                limit_s = _q("limit")
                limit = int(limit_s) if limit_s else 1000
                r = plat.list_identities(
                    org=_q("org"),
                    owner=_q("owner"),
                    tag=_q("tag"),
                    status=_q("status"),
                    agent_type=_q("agent_type"),
                    limit=limit,
                )
                return 200, r
            # v2.11 FR6 治理台：只读聚合接口
            if path == "/v1/governance/inventory":
                plat = pool.get(tenant)
                q = query or {}
                def _q2(k):
                    return q.get(k, [None])[0]
                only = {k: _q2(k) for k in
                        ("org", "owner", "tag", "status", "agent_type")
                        if _q2(k)}
                return 200, governance.agent_inventory(plat, only=only)
            if path == "/v1/governance/topology":
                plat = pool.get(tenant)
                q = query or {}
                def _q3(k):
                    return q.get(k, [None])[0]
                root_idn = _q3("root_idn")
                inc_rev = (_q3("include_revoked") or "").lower() in \
                    ("1", "true", "yes", "on")
                return 200, governance.delegation_topology(
                    plat, root_idn=root_idn, include_revoked=inc_rev)
            if path == "/v1/governance/permissions":
                plat = pool.get(tenant)
                q = query or {}
                idn = (q or {}).get("idn", [None])[0]
                if not idn:
                    return 400, {"ok": False, "reason": "missing idn"}
                return 200, governance.realtime_permission_view(plat, idn)
            if path == "/v1/governance/alerts":
                plat = pool.get(tenant)
                q = query or {}
                window_s = (q or {}).get("window", ["3600"])[0]
                thresh_s = (q or {}).get("threshold", ["5"])[0]
                return 200, governance.scan_alerts(
                    plat,
                    window_seconds=int(window_s),
                    threshold=int(thresh_s))
            # ---- v2.12 FR2-07 凭证模板（只读） ----
            if path == "/v1/templates":
                reg = pool.get_template_registry(tenant)
                q = query or {}
                agent_type = (q.get("agent_type") or [None])[0]
                return 200, {"ok": True, "tenant": tenant,
                             "templates": reg.list(agent_type=agent_type)}
            # ---- v2.13 FR1-05 密钥版本（只读） ----
            if path == "/v1/keys/version":
                plat = pool.get(tenant)
                return 200, plat.key_versions()
            # ---- v2.13 FR1-07 标识批量导出（只读） ----
            if path == "/v1/identities/export":
                plat = pool.get(tenant)
                q = query or {}
                include_priv = (q.get("include_priv") or "").lower() in \
                    ("1", "true", "yes", "on")
                r = plat.list_identities(limit=10000)
                if r.get("ok"):
                    for ident in r["identities"]:
                        if include_priv:
                            # 导出含私钥（仅供迁移备份，需严格权限控制）
                            priv = plat._derive_priv(ident["idn"])
                            ident["priv_d"] = "%064x" % priv
                    return 200, {"ok": True, "tenant": tenant,
                                 "total": r["total"],
                                 "identities": r["identities"],
                                 "include_priv": include_priv,
                                 "ts": int(time.time())}
                return 400, r
            # ---- v2.14 FR7-03 智能体卡片（只读） ----
            if path == "/v1/agent-cards":
                store = pool.get_card_store(tenant)
                return 200, {"ok": True, "tenant": tenant,
                             "total": len(store),
                             "cards": list(store.values())}
            if path == "/v1/agent-cards/detail":
                store = pool.get_card_store(tenant)
                q = query or {}
                agent_idn = (q.get("agent_idn") or [None])[0]
                if not agent_idn:
                    return 400, {"ok": False, "reason": "missing agent_idn"}
                card = store.get(agent_idn)
                if card is None:
                    return 404, {"ok": False, "reason": "card not found"}
                return 200, {"ok": True, "card": card}
            if path == "/v1/agent-cards/well-known":
                # 模拟互联协议的 /.well-known/agent.json 发布端点
                store = pool.get_card_store(tenant)
                q = query or {}
                agent_idn = (q.get("agent_idn") or [None])[0]
                if agent_idn:
                    card = store.get(agent_idn)
                else:
                    card = next(iter(store.values()), None)
                if card is None:
                    return 404, {"ok": False, "reason": "no card published"}
                return 200, card
            # ---- v2.14 FR7-04 编排插件（只读） ----
            if path == "/v1/orchestrator/tools":
                q = query or {}
                audience = (q.get("audience") or [None])[0]
                if not audience:
                    return 400, {"ok": False, "reason": "missing audience"}
                plug = pool.get_orchestrator(tenant, audience)
                tools = {}
                for name in plug.list_tools():
                    tools[name] = {
                        "required_scope": plug.required_scope(name),
                        "description": plug._tools[name]["description"],
                    }
                return 200, {"ok": True, "tenant": tenant,
                             "audience": audience,
                             "total": len(tools), "tools": tools}
            if path == "/v1/templates/detail":
                q = query or {}
                tid = (q.get("template_id") or [None])[0]
                if not tid:
                    return 400, {"ok": False, "reason": "missing template_id"}
                tpl = pool.get_template_registry(tenant).get(tid)
                if tpl is None:
                    return 404, {"ok": False, "reason": "unknown template"}
                return 200, {"ok": True, "tenant": tenant,
                             "template": tpl.to_dict()}
            # ---- v2.12 FR2-06 速率限制（运维/治理台） ----
            if path == "/v1/quota/stats":
                return 200, {"ok": True, "tenant": tenant,
                             "config": pool.rate_limiter.config.to_dict(),
                             "stats": pool.rate_limiter.stats()}
            if path == "/v1/quota/usage":
                q = query or {}
                tkey = (q.get("tenant_key") or [None])[0] \
                    or (tenant or pool._default)
                ikey = (q.get("identity") or [None])[0]
                ekey = (q.get("endpoint") or [None])[0]
                return 200, {"ok": True,
                             "usage": pool.rate_limiter.quota_usage(
                                 tkey, identity=ikey, endpoint=ekey)}
            # ---- v2.12 FR2-04 续期（只读） ----
            if path == "/v1/renewals/stats":
                return 200, {"ok": True, "tenant": tenant,
                             **pool.get_renewer(tenant).stats()}
            if path == "/v1/renewals/history":
                q = query or {}
                jti = (q.get("jti") or [None])[0]
                return 200, {"ok": True, "tenant": tenant,
                             "history": pool.get_renewer(tenant).history(jti=jti)}
            return 404, {"ok": False, "reason": "not found"}

        if method == "POST":
            if not body:
                return 400, {"ok": False, "reason": "empty body"}
            plat = pool.get(tenant)
            if path == "/v1/identities":
                r = plat.register_identity(
                    body.get("idn", ""),
                    org=body.get("org"),
                    agent_type=body.get("agent_type"),
                    owner=body.get("owner"),
                    initial_scope=body.get("initial_scope"),
                    tags=body.get("tags"),   # v2.11 FR1-04
                )
                return (200 if r.get("ok") else 400), r
            if path == "/v1/identities/tags":
                r = plat.update_identity_tags(
                    body.get("idn", ""),
                    tags=body.get("tags"),
                    add=body.get("add"),
                    remove=body.get("remove"),
                )
                return (200 if r.get("ok") else 400), r
            if path == "/v1/identities/disable":
                r = plat.disable_identity(
                    body.get("idn", ""),
                    reason=body.get("reason", "user request"))
                return (200 if r.get("ok") else 400), r
            # v2.10 FR1-03：标识重新启用（复用原密钥对，非重新注册）
            if path == "/v1/identities/enable":
                r = plat.enable_identity(
                    body.get("idn", ""),
                    reason=body.get("reason", "user request"))
                return (200 if r.get("ok") else 400), r
            if path == "/v1/credentials":
                r = plat.issue_credential(
                    body["issuer_idn"], body["subject_idn"],
                    body["audience"], body["scope"],
                    ttl=body.get("ttl"),
                    alg_tier=body.get("alg_tier", "sm2"),
                )
                return (200 if r.get("ok") else 400), r
            if path == "/v1/credentials/verify":
                r = plat.verify_credential(
                    body["cred"], audience=body.get("audience"),
                    record_nonce=body.get("record_nonce", True),
                )
                return 200, r
            if path == "/v1/delegations":
                # v2.10 FR3-02/FR3-05：parent_cred 可选透传，
                # 传入即强制作用域与有效期收敛
                r = plat.issue_delegation(
                    body["delegator_idn"], body["delegatee_idn"],
                    body["audience"], body["scope"],
                    intent=body.get("intent"),
                    ttl=body.get("ttl"),
                    alg_tier=body.get("alg_tier"),
                    parent_cred=body.get("parent_cred"),
                )
                return (200 if r.get("ok") else 400), r
            if path == "/v1/delegations/verify":
                r = plat.verify_delegation_chain(
                    body["chain"], body["target_audience"],
                    body["target_scope"])
                return 200, r
            if path == "/v1/revocations":
                r = plat.revoke(body["jti"],
                                reason=body.get("reason", "user request"))
                return (200 if r.get("ok") else 400), r
            if path == "/v1/revocations/by-identity":
                r = plat.revoke_by_identity(
                    body["idn"],
                    reason=body.get("reason", "identity disabled"))
                return (200 if r.get("ok") else 400), r
            if path == "/v1/policy":
                r = plat.configure_policy(body)
                return (200 if r.get("ok") else 400), r
            # ---- v2.13 FR1-05 密钥轮换 ----
            if path == "/v1/keys/rotate":
                alg = body.get("alg", "sm2")
                reason = body.get("reason", "scheduled rotation")
                r = plat.rotate_master_key(alg=alg, reason=reason)
                return (200 if r.get("ok") else 400), r
            # ---- v2.13 FR1-07 标识批量导入 ----
            if path == "/v1/identities/import":
                identities = body.get("identities", [])
                if not isinstance(identities, list):
                    return 400, {"ok": False, "reason": "identities must be a list"}
                results = []
                for ident in identities:
                    if not isinstance(ident, dict) or "idn" not in ident:
                        results.append({"idn": None, "ok": False,
                                        "reason": "invalid entry"})
                        continue
                    try:
                        r = plat.register_identity(
                            idn=ident["idn"],
                            org=ident.get("org"),
                            agent_type=ident.get("agent_type"),
                            owner=ident.get("owner"),
                            tags=ident.get("tags"),
                        )
                        results.append(r)
                    except Exception as e:
                        results.append({"idn": ident.get("idn"),
                                        "ok": False, "reason": str(e)})
                imported = sum(1 for r in results if r.get("ok"))
                skipped = sum(1 for r in results if not r.get("ok")
                              and "already" in r.get("reason", ""))
                failed = len(results) - imported - skipped
                return 200, {"ok": True, "tenant": tenant,
                             "total": len(results), "imported": imported,
                             "skipped": skipped, "failed": failed,
                             "results": results, "ts": int(time.time())}
            # ---- v2.14 FR7-03 智能体卡片签名扩展（写） ----
            if path == "/v1/agent-cards/sign":
                cd = body.get("card")
                if not isinstance(cd, dict) or not cd.get("agent_idn"):
                    return 400, {"ok": False, "reason": "missing card.agent_idn"}
                try:
                    card = AgentCard(
                        agent_idn=cd["agent_idn"],
                        name=cd.get("name"),
                        description=cd.get("description"),
                        url=cd.get("url"),
                        version=cd.get("version", "1.0"),
                        capabilities=cd.get("capabilities"),
                        skills=cd.get("skills"),
                        provider=cd.get("provider"),
                        authentication=cd.get("authentication"),
                        iat=cd.get("iat"), exp=cd.get("exp"),
                        ttl=cd.get("ttl", 86400),
                    )
                except (ValueError, TypeError) as e:
                    return 400, {"ok": False, "reason": "bad card: %s" % e}
                r = pool.get_card_signer(tenant).sign(
                    card,
                    issuer_idn=body.get("issuer_idn") or cd["agent_idn"],
                    jti=body.get("jti"),
                    alg_tier=body.get("alg_tier", "sm2"),
                    secret_signer_idn=body.get("signer_idn"),
                )
                return (200 if r.get("ok") else 400), r
            if path == "/v1/agent-cards/verify":
                cd = body.get("card")
                card = AgentCard.from_dict(cd) if isinstance(cd, dict) else None
                if card is None:
                    return 400, {"ok": False, "reason": "invalid card"}
                ok, why = pool.get_card_signer(tenant).verify(
                    card, expected_subject=body.get("expected_subject"))
                return 200, {"ok": True, "valid": ok, "reason": why,
                             "agent_idn": card.agent_idn}
            if path == "/v1/agent-cards":
                # 发布：签名并存库（供 /.well-known 拉取）
                cd = body.get("card")
                if not isinstance(cd, dict) or not cd.get("agent_idn"):
                    return 400, {"ok": False, "reason": "missing card.agent_idn"}
                try:
                    card = AgentCard(
                        agent_idn=cd["agent_idn"],
                        name=cd.get("name"),
                        description=cd.get("description"),
                        url=cd.get("url"),
                        version=cd.get("version", "1.0"),
                        capabilities=cd.get("capabilities"),
                        skills=cd.get("skills"),
                        provider=cd.get("provider"),
                        authentication=cd.get("authentication"),
                        iat=cd.get("iat"), exp=cd.get("exp"),
                        ttl=cd.get("ttl", 86400),
                    )
                except (ValueError, TypeError) as e:
                    return 400, {"ok": False, "reason": "bad card: %s" % e}
                signer = pool.get_card_signer(tenant)
                r = signer.sign(
                    card,
                    issuer_idn=body.get("issuer_idn") or cd["agent_idn"],
                    jti=body.get("jti"),
                    alg_tier=body.get("alg_tier", "sm2"),
                    secret_signer_idn=body.get("signer_idn"),
                )
                if not r.get("ok"):
                    return 400, r
                pool.get_card_store(tenant)[cd["agent_idn"]] = r["card"]
                return 200, {"ok": True, "tenant": tenant,
                             "card": r["card"], "jti": r["jti"]}
            # ---- v2.14 FR7-04 编排插件（写） ----
            if path == "/v1/orchestrator/tools":
                audience = body.get("audience")
                name = body.get("name")
                if not audience:
                    return 400, {"ok": False, "reason": "missing audience"}
                if not name:
                    return 400, {"ok": False, "reason": "missing name"}
                plug = pool.get_orchestrator(tenant, audience)
                # HTTP 侧只登记作用域元数据（fn=None，仅决策模式）
                plug.register_tool(name, fn=None,
                                   scopes=body.get("scopes") or [],
                                   description=body.get("description"))
                return 200, {"ok": True, "tenant": tenant,
                             "audience": audience, "tool": name,
                             "required_scope": plug.required_scope(name)}
            if path == "/v1/orchestrator/guard":
                audience = body.get("audience")
                tool_name = body.get("tool")
                if not audience:
                    return 400, {"ok": False, "reason": "missing audience"}
                if not tool_name:
                    return 400, {"ok": False, "reason": "missing tool"}
                plug = pool.get_orchestrator(tenant, audience)
                # 工具未在 HTTP 侧登记时，用请求里显式给出的作用域
                if plug.required_scope(tool_name) is None:
                    rs = body.get("required_scope")
                    if rs is None:
                        return 400, {"ok": False,
                                     "reason": "tool not registered and "
                                               "no required_scope given"}
                    plug.register_tool(tool_name, fn=None, scopes=rs,
                                       description=body.get("description"))
                d = plug.guard(tool_name, body.get("arguments"),
                               credential=body.get("credential"),
                               chain=body.get("chain"))
                return 200, d
            if path == "/v1/audit/anchors":
                if "issuer_idn" not in body:
                    return 400, {"ok": False, "reason": "missing issuer_idn"}
                r = plat.anchor_audit(body["issuer_idn"],
                                       reason=body.get("reason", "manual"))
                return (200 if r.get("ok") else 400), r
            if path == "/v1/audit/anchors/verify":
                r = plat.verify_audit_anchor(
                    body.get("anchor"),
                    issuer_pub=None)
                return 200, r
            # ---- v2.12 FR2-07 凭证模板（写） ----
            if path == "/v1/templates":
                reg = pool.get_template_registry(tenant)
                r = reg.create(
                    name=body.get("name", ""),
                    agent_type=body.get("agent_type", ""),
                    default_scope=body.get("default_scope"),
                    allowed_scopes=body.get("allowed_scopes"),
                    max_ttl=body.get("max_ttl", 3600),
                    allowed_algs=body.get("allowed_algs"),
                    allowed_audiences=body.get("allowed_audiences"),
                    description=body.get("description"),
                    template_id=body.get("template_id"),
                )
                if r.get("ok"):
                    # 模板变更入审计
                    plat.audit.append({
                        "kind": "template.create", "tenant": tenant,
                        "template_id": r["template"]["template_id"],
                        "name": r["template"]["name"],
                        "agent_type": r["template"]["agent_type"],
                    })
                    # 重建该租户的 renewer 以刷新绑定
                    pool._renewers.pop(tenant or pool._default, None)
                return (200 if r.get("ok") else 400), r
            if path == "/v1/templates/update":
                reg = pool.get_template_registry(tenant)
                tid = body.get("template_id")
                if not tid:
                    return 400, {"ok": False, "reason": "missing template_id"}
                kwargs = {k: v for k, v in body.items()
                          if k in ("name", "description", "default_scope",
                                   "allowed_scopes", "max_ttl", "allowed_algs",
                                   "allowed_audiences") and v is not None}
                r = reg.update(tid, **kwargs)
                if r.get("ok"):
                    plat.audit.append({
                        "kind": "template.update", "tenant": tenant,
                        "template_id": tid, "fields": list(kwargs.keys()),
                    })
                    pool._renewers.pop(tenant or pool._default, None)
                return (200 if r.get("ok") else 400), r
            if path == "/v1/templates/delete":
                reg = pool.get_template_registry(tenant)
                tid = body.get("template_id")
                if not tid:
                    return 400, {"ok": False, "reason": "missing template_id"}
                r = reg.delete(tid)
                if r.get("ok"):
                    plat.audit.append({
                        "kind": "template.delete", "tenant": tenant,
                        "template_id": tid,
                    })
                    pool._renewers.pop(tenant or pool._default, None)
                return (200 if r.get("ok") else 400), r
            # ---- v2.12 FR2-07 基于模板签发凭证 ----
            if path == "/v1/credentials/from-template":
                issuer = pool.get_template_issuer(tenant)
                r = issuer.issue_from_template(
                    template_id=body.get("template_id", ""),
                    issuer_idn=body.get("issuer_idn", ""),
                    subject_idn=body.get("subject_idn", ""),
                    audience=body.get("audience"),
                    scope=body.get("scope"),
                    ttl=body.get("ttl"),
                    alg_tier=body.get("alg_tier", "sm2"),
                )
                return (200 if r.get("ok") else 400), r
            # ---- v2.12 FR2-04 凭证自动续期 ----
            if path == "/v1/credentials/renew":
                r = pool.get_renewer(tenant).renew(
                    jti=body.get("jti", ""),
                    cred_wire=body.get("cred"),
                    template_id=body.get("template_id"),
                    issuer_idn=body.get("issuer_idn"),
                    ttl=body.get("ttl"),
                    alg_tier=body.get("alg_tier"),
                )
                return (200 if r.get("ok") else 400), r
            # ---- v2.12 FR2-06 速率限制（运维） ----
            if path == "/v1/quota/reset":
                pool.rate_limiter.reset()
                return 200, {"ok": True, "tenant": tenant,
                             "stats": pool.rate_limiter.stats()}
            return 404, {"ok": False, "reason": "not found"}

        return 405, {"ok": False, "reason": "method not allowed"}
    except KeyError as e:
        return 400, {"ok": False, "reason": "missing field: %s" % e}
    except Exception as e:
        return 500, {"ok": False, "reason": "server error: %s" % e}


# ------------------------------------------------------------------
# HTTP Handler（stdlib 实现）
# ------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    pool = None  # 由 create_server 注入

    # ---------------- 底层工具
    def _tenant(self):
        return self.headers.get("X-Tenant-Id") or self.pool._default

    def _api_key(self):
        # v2.5：支持 X-API-Key 与 Authorization: Bearer <key> 两种写法
        k = self.headers.get("X-API-Key")
        if k:
            return k
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    def _json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # v2.12 FR2-06：429 响应带 Retry-After 头
        if code == 429 and isinstance(payload, dict) \
                and "retry_after" in payload:
            self.send_header("Retry-After", str(int(payload["retry_after"])))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, payload):
        self._send(200, payload)

    def _bad(self, msg, code=400):
        self._send(code, {"ok": False, "reason": msg})

    def log_message(self, fmt, *args):
        # 静默：生产里按需恢复
        return

    # ---------------- 分发（走通用 route()）
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        status, payload = route(self.pool, "GET", p.path, q, None,
                                 self._tenant(), self._api_key())
        self._send(status, payload)

    def do_POST(self):
        p = urlparse(self.path)
        body = self._json_body()
        status, payload = route(self.pool, "POST", p.path, {}, body,
                                 self._tenant(), self._api_key())
        self._send(status, payload)


def load_auth(path):
    """从 JSON 配置文件载入鉴权表。文件不存在 / 未启用 → None（不鉴权）。"""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    return AuthTable.from_config(cfg)


def create_server(host="127.0.0.1", port=8787,
                  db_path=":memory:", default_tenant="default",
                  auth=None, quota_config=None, rate_limiter=None):
    pool = TenantPool(db_path=db_path, default_tenant=default_tenant,
                      auth=auth, quota_config=quota_config,
                      rate_limiter=rate_limiter)
    Handler.pool = pool
    server = ThreadingHTTPServer((host, port), Handler)
    return server, pool


def self_check():
    """HTTP API 端到端烟测（本地起一个 server，用 socket 打请求）。"""
    import socket
    import time

    server, pool = create_server(host="127.0.0.1", port=0)  # 端口 0 让系统分配
    port = server.server_address[1]
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    results = []

    def req(method, path, body=None, tenant=None):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            hdrs = ["%s %s HTTP/1.1" % (method, path),
                    "Host: 127.0.0.1:%d" % port,
                    "Connection: close"]
            if tenant:
                hdrs.append("X-Tenant-Id: %s" % tenant)
            if body is not None:
                raw = json.dumps(body).encode("utf-8")
                hdrs.append("Content-Type: application/json")
                hdrs.append("Content-Length: %d" % len(raw))
                head = "\r\n".join(hdrs).encode() + b"\r\n\r\n" + raw
            else:
                head = "\r\n".join(hdrs).encode() + b"\r\n\r\n"
            sock.sendall(head)
            chunks = b""
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks += data
            # 解析 body
            raw = chunks.decode("utf-8", "replace")
            head_end = raw.find("\r\n\r\n")
            payload = raw[head_end + 4:] if head_end >= 0 else raw
            return json.loads(payload)
        finally:
            sock.close()

    try:
        # health
        r = req("GET", "/health")
        results.append(("health", r.get("ok") is True))

        # 注册
        r = req("POST", "/v1/identities",
                {"idn": "agent://http/root", "org": "http",
                 "agent_type": "issuance"}, tenant="http-t1")
        results.append(("POST /v1/identities", r.get("ok") is True))

        r = req("POST", "/v1/identities",
                {"idn": "agent://http/worker", "org": "http",
                 "agent_type": "worker"}, tenant="http-t1")
        results.append(("POST /v1/identities worker", r.get("ok") is True))

        # 签发
        r = req("POST", "/v1/credentials",
                {"issuer_idn": "agent://http/root",
                 "subject_idn": "agent://http/worker",
                 "audience": "svc://http",
                 "scope": ["http:read"], "ttl": 3600},
                tenant="http-t1")
        results.append(("POST /v1/credentials", r.get("ok") is True))
        cred = r["cred"]

        # 校验
        r = req("POST", "/v1/credentials/verify",
                {"cred": cred, "audience": "svc://http",
                 "record_nonce": False},
                tenant="http-t1")
        results.append(("POST /v1/credentials/verify",
                        r.get("ok") is True and r.get("reason") == "ok"))

        # 撤销
        r = req("POST", "/v1/revocations",
                {"jti": cred["jti"], "reason": "test"},
                tenant="http-t1")
        results.append(("POST /v1/revocations", r.get("ok") is True))

        # 撤销快照
        r = req("GET", "/v1/revocations?since=0", tenant="http-t1")
        results.append(("GET /v1/revocations",
                        r.get("ok") is True
                        and r.get("total_revoked") == 1))

        # 审计
        r = req("GET", "/v1/audit?limit=5", tenant="http-t1")
        results.append(("GET /v1/audit",
                        r.get("ok") is True
                        and r.get("chain_valid") is True
                        and len(r.get("records", [])) >= 1))

        # 策略
        r = req("POST", "/v1/policy",
                {"max_ttl_seconds": 120},
                tenant="http-t1")
        results.append(("POST /v1/policy",
                        r.get("ok") is True
                        and r["policy"]["max_ttl_seconds"] == 120))

        # 停用
        r = req("POST", "/v1/identities/disable",
                {"idn": "agent://http/worker", "reason": "test"},
                tenant="http-t1")
        results.append(("POST /v1/identities/disable",
                        r.get("ok") is True
                        and r.get("status") == "disabled"))

        # 跨租户访问被隔离
        r = req("GET", "/v1/audit?limit=5", tenant="http-t2")
        results.append(("跨租户 http-t2 审计为空",
                        r.get("ok") is True
                        and len(r.get("records", [])) == 0))

        # 404
        r = req("GET", "/v1/unknown")
        results.append(("404 not found",
                        r.get("ok") is False))

        # stats
        r = req("GET", "/stats")
        results.append(("GET /stats",
                        r.get("ok") is True
                        and "tenants" in r))
        # v2.5：stats 暴露鉴权开关状态
        results.append(("GET /stats 含 auth_enabled",
                        r.get("auth_enabled") is False))
    finally:
        server.shutdown()
        server.server_close()
        time.sleep(0.1)

    # ---- v2.5 鉴权端到端（独立 server，启用 AuthTable）----
    from auth import AuthTable
    tbl = AuthTable()
    tbl.add("k-acme", ["auth-acme"], note="Acme")
    tbl.add("k-admin", ["*"], note="管理员")
    srv2, pool2 = create_server(host="127.0.0.1", port=0, auth=tbl)
    port2 = srv2.server_address[1]
    t2 = threading.Thread(target=srv2.serve_forever, daemon=True)
    t2.start()

    def req2(method, path, body=None, tenant=None, api_key=None,
             bearer=False):
        sock = socket.create_connection(("127.0.0.1", port2), timeout=5)
        try:
            hdrs = ["%s %s HTTP/1.1" % (method, path),
                    "Host: 127.0.0.1:%d" % port2,
                    "Connection: close"]
            if tenant:
                hdrs.append("X-Tenant-Id: %s" % tenant)
            if api_key and not bearer:
                hdrs.append("X-API-Key: %s" % api_key)
            if api_key and bearer:
                hdrs.append("Authorization: Bearer %s" % api_key)
            if body is not None:
                raw = json.dumps(body).encode("utf-8")
                hdrs.append("Content-Type: application/json")
                hdrs.append("Content-Length: %d" % len(raw))
                head = "\r\n".join(hdrs).encode() + b"\r\n\r\n" + raw
            else:
                head = "\r\n".join(hdrs).encode() + b"\r\n\r\n"
            sock.sendall(head)
            chunks = b""
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks += data
            raw = chunks.decode("utf-8", "replace")
            # 解析状态码 + body
            status_line = raw.split("\r\n")[0]
            code = int(status_line.split(" ")[1])
            head_end = raw.find("\r\n\r\n")
            payload = json.loads(raw[head_end + 4:]) if head_end >= 0 else {}
            return code, payload
        finally:
            sock.close()

    try:
        code, r = req2("GET", "/health", tenant="auth-acme",
                       api_key="k-acme")
        results.append(("鉴权·本租户放行",
                        code == 200 and r.get("ok") is True))

        code, r = req2("GET", "/health", tenant="auth-acme")
        results.append(("鉴权·缺 key → 401",
                        code == 401
                        and r.get("reason") == "missing api key"))

        code, r = req2("GET", "/health", tenant="auth-acme",
                       api_key="k-wrong")
        results.append(("鉴权·错 key → 401",
                        code == 401
                        and r.get("reason") == "unknown api key"))

        code, r = req2("GET", "/health", tenant="auth-globex",
                       api_key="k-acme")
        results.append(("鉴权·跨租户 → 403",
                        code == 403
                        and r.get("reason") == "tenant not allowed"))

        code, r = req2("GET", "/health", tenant="auth-any",
                       api_key="k-admin")
        results.append(("鉴权·管理员通配放行", code == 200))

        # Bearer 写法等价
        code, r = req2("GET", "/health", tenant="auth-acme",
                       api_key="k-acme", bearer=True)
        results.append(("鉴权·Bearer 头等价", code == 200))

        # 越权写入必须被拒，且不能污染目标租户
        code, r = req2("POST", "/v1/identities",
                       {"idn": "agent://evil/root", "org": "evil",
                        "agent_type": "issuance"},
                       tenant="auth-globex", api_key="k-acme")
        results.append(("鉴权·越权写入被拒", code == 403))

        # 用正确 key 写，再确认落在正确租户
        code, r = req2("POST", "/v1/identities",
                       {"idn": "agent://acme/root", "org": "acme",
                        "agent_type": "issuance"},
                       tenant="auth-acme", api_key="k-acme")
        results.append(("鉴权·授权写入成功", code == 200))
        code, r = req2("GET", "/v1/audit?limit=5", tenant="auth-globex",
                       api_key="k-admin")
        results.append(("鉴权·被越权租户无污染",
                        code == 200 and len(r.get("records", [])) == 0))

        results.append(("鉴权·pool.auth_enabled 为真",
                        pool2.auth_enabled is True))
    finally:
        srv2.shutdown()
        srv2.server_close()
        time.sleep(0.1)

    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default=":memory:",
                    help="SQLite 路径，:memory: 用内存")
    ap.add_argument("--tenant", default="default")
    ap.add_argument("--auth", default=None,
                    help="鉴权配置文件路径（JSON，含 auth 段）；"
                         "不指定则不鉴权")
    ap.add_argument("--smoke", action="store_true",
                    help="跑一次 HTTP API 端到端烟测")
    args = ap.parse_args()
    _auth = load_auth(args.auth)

    if args.smoke:
        results = self_check()
        for name, ok in results:
            print("%-8s %s" % ("PASS" if ok else "FAIL", name))
        nfail = sum(1 for _, ok in results if not ok)
        print("SUMMARY  http_api smoke PASS=%d FAIL=%d"
              % (len(results) - nfail, nfail))
        sys.exit(0 if nfail == 0 else 1)

    server, _ = create_server(host=args.host, port=args.port,
                              db_path=args.db, default_tenant=args.tenant,
                              auth=_auth)
    print("agent-cryptid HTTP API listening on http://%s:%d"
          % (args.host, args.port))
    print("tenant header: X-Tenant-Id (default=%s)" % args.tenant)
    print("auth: %s" % ("ENABLED（校验 X-API-Key / Authorization: Bearer）"
                        if _auth is not None and server is not None
                        and _auth.enabled and not _auth.is_empty()
                        else "DISABLED（任何人可指定任意租户，仅供 demo）"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
