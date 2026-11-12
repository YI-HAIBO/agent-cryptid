# -*- coding: utf-8 -*-
"""ASGI 应用（v2.1 P1-⑦：把 HTTP 层从 stdlib 升级到生产级 ASGI）。

设计
----
- **传输层可插拔**：路由分发逻辑抽到 http_api.route()，本模块只提供
  ASGI 消息协议适配；stdlib 实现走 http.server + route()，生产级走
  Uvicorn + 本文件。两者语义完全一致。
- **零运行时依赖**：手写 ASGI scope/receive/send 循环，不依赖
  starlette/fastapi。装了 uvicorn 即可跑：
      pip install uvicorn
      uvicorn asgi_app:app --host 0.0.0.0 --port 8000
- **多租户**：请求头 X-Tenant-Id 指定租户；缺省用 default。

自测策略
--------
asgi_app 内部走 asyncio；self_check() 用 asyncio.run 直接调用 app()
并 mock scope/receive/send，不启动任何真实服务器，也不依赖 uvicorn。
因此保持零依赖、可在 CI 里跑。
"""
import asyncio
import json
import os
import sys
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from http_api import TenantPool, route, load_auth  # noqa: E402
from rate_limit import QuotaConfig  # noqa: E402


_pool = None

# 生产部署（uvicorn）时的环境变量自举：
#   AC_DB              SQLite 路径，默认 :memory:
#   AC_DEFAULT_TENANT  缺省租户，默认 default
#   AC_AUTH            鉴权配置：JSON 文件路径，或直接是 JSON 字符串
#   AC_QUOTA           限流配置 JSON（FR2-06），例如
#                      {"window_seconds":60,"tenant_limit":1000,...}
_DB_PATH = os.environ.get("AC_DB", ":memory:")
_DEFAULT_TENANT = os.environ.get("AC_DEFAULT_TENANT", "default")
_AUTH_SRC = os.environ.get("AC_AUTH", "")
_QUOTA_SRC = os.environ.get("AC_QUOTA", "")


def _parse_quota(src: str):
    if not src:
        return None
    src = src.strip()
    try:
        d = json.loads(src)
        return QuotaConfig(**d) if d else None
    except Exception:
        return None


def init_pool(db_path=":memory:", default_tenant="default", auth=None,
              quota_config=None):
    """初始化全局 TenantPool（uvicorn 加载应用时可自定义路径）。

    auth:         AuthTable 实例、配置 dict（含 "auth" 段），或配置文件路径。
    quota_config: QuotaConfig 实例（FR2-06），None 用默认配置。
    """
    global _pool
    if isinstance(auth, str):
        auth = load_auth(auth)
    _pool = TenantPool(db_path=db_path, default_tenant=default_tenant,
                       auth=auth, quota_config=quota_config)
    return _pool


def _bootstrap_pool():
    """从环境变量构造 pool（首次 get_pool 时惰性执行）。"""
    auth = None
    if _AUTH_SRC:
        if _AUTH_SRC.strip().startswith("{"):
            try:
                auth = json.loads(_AUTH_SRC)
            except Exception:
                auth = None
        else:
            auth = load_auth(_AUTH_SRC)
    return init_pool(db_path=_DB_PATH, default_tenant=_DEFAULT_TENANT,
                     auth=auth, quota_config=_parse_quota(_QUOTA_SRC))


def get_pool():
    global _pool
    if _pool is None:
        _bootstrap_pool()
    return _pool


async def app(scope, receive, send):
    """ASGI 主入口。仅处理 type=http 的 scope。"""
    if scope["type"] != "http":
        return
    pool = get_pool()

    method = scope["method"]
    path = scope["path"]
    qs = scope.get("query_string", b"") or b""
    if isinstance(qs, str):
        qs = qs.encode("utf-8")
    query = parse_qs(qs.decode("utf-8")) if qs else {}
    headers = {k.decode("latin-1").lower(): v.decode("latin-1")
               for k, v in scope.get("headers", [])}
    tenant = headers.get("x-tenant-id") or pool._default
    # v2.5：X-API-Key，或 Authorization: Bearer <key>
    api_key = headers.get("x-api-key")
    if not api_key:
        _authz = headers.get("authorization") or ""
        if _authz.lower().startswith("bearer "):
            api_key = _authz[7:].strip()

    # 收集 body
    body_bytes = b""
    while True:
        msg = await receive()
        body_bytes += msg.get("body", b"")
        if not msg.get("more_body", False):
            break
    body = None
    if body_bytes:
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            body = None

    status, payload = route(pool, method, path, query, body, tenant, api_key)
    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    resp_headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(encoded)).encode("latin-1")),
    ]
    # v2.12 FR2-06：429 响应带 Retry-After 头
    if status == 429 and isinstance(payload, dict) \
            and "retry_after" in payload:
        resp_headers.append((b"retry-after",
                             str(int(payload["retry_after"])).encode("latin-1")))
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": resp_headers,
    })
    await send({"type": "http.response.body", "body": encoded})


# ------------------------------------------------------------------
# 自测：不启动服务器，直接 mock ASGI 循环
# ------------------------------------------------------------------
def _call(scope_overrides, body=None, tenant=None, api_key=None):
    """异步调用 ASGI app，返回 (status, payload)。"""
    async def _run():
        headers = []
        if tenant:
            headers.append((b"x-tenant-id", tenant.encode("latin-1")))
        if api_key:
            headers.append((b"x-api-key", api_key.encode("latin-1")))
        raw_body = b""
        if body is not None:
            raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers.append((b"content-type", b"application/json"))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "http",
            "path": scope_overrides.get("path", "/health"),
            "raw_path": scope_overrides.get("path", "/health").encode(),
            "method": scope_overrides.get("method", "GET"),
            "query_string": scope_overrides.get("query_string", b""),
            "headers": headers,
            "client": ("127.0.0.1", 0),
            "server": ("127.0.0.1", 8000),
        }

        # receive：一次性给完整 body，然后关闭
        receive_msgs = [
            {"type": "http.request", "body": raw_body, "more_body": False},
        ]
        async def _receive():
            nonlocal receive_msgs
            return receive_msgs.pop(0) if receive_msgs else \
                {"type": "http.disconnect"}

        sent = []
        async def _send(msg):
            sent.append(msg)

        await app(scope, _receive, _send)
        start = sent[0]
        payload = json.loads(sent[1]["body"].decode("utf-8"))
        return start["status"], payload

    return asyncio.run(_run())


def self_check():
    """ASGI 应用自测。"""
    # 每次测试用独立 pool，避免状态污染
    init_pool()
    results = []

    # health
    status, r = _call({"method": "GET", "path": "/health"})
    results.append(("asgi GET /health", status == 200 and r.get("ok") is True))

    # 注册标识
    status, r = _call(
        {"method": "POST", "path": "/v1/identities"},
        body={"idn": "agent://asgi/root", "org": "asgi",
              "agent_type": "issuance"},
        tenant="asgi-t1")
    results.append(("asgi POST /v1/identities",
                    status == 200 and r.get("ok") is True))

    # 签发
    status, r = _call(
        {"method": "POST", "path": "/v1/credentials"},
        body={"issuer_idn": "agent://asgi/root",
              "subject_idn": "agent://asgi/root",
              "audience": "svc://asgi",
              "scope": ["asgi:read"], "ttl": 3600},
        tenant="asgi-t1")
    results.append(("asgi POST /v1/credentials",
                    status == 200 and r.get("ok") is True))
    cred = r["cred"]

    # 校验
    status, r = _call(
        {"method": "POST", "path": "/v1/credentials/verify"},
        body={"cred": cred, "audience": "svc://asgi", "record_nonce": False},
        tenant="asgi-t1")
    results.append(("asgi POST /v1/credentials/verify",
                    status == 200 and r.get("ok") is True))

    # 撤销
    status, r = _call(
        {"method": "POST", "path": "/v1/revocations"},
        body={"jti": cred["jti"], "reason": "test"},
        tenant="asgi-t1")
    results.append(("asgi POST /v1/revocations",
                    status == 200 and r.get("ok") is True))

    # 撤销快照
    status, r = _call(
        {"method": "GET", "path": "/v1/revocations", "query_string": "since=0"},
        tenant="asgi-t1")
    results.append(("asgi GET /v1/revocations",
                    status == 200 and r.get("total_revoked") == 1
                    and r.get("acc_version") == 1))

    # 累加器证明（v2.1 新路由）
    status, r = _call(
        {"method": "GET", "path": "/v1/revocations/prove",
         "query_string": "jti=" + cred["jti"]},
        tenant="asgi-t1")
    results.append(("asgi GET /v1/revocations/prove",
                    status == 200 and r.get("ok") is True
                    and r.get("revoked") is True
                    and r.get("verify") is True))

    # 审计
    status, r = _call(
        {"method": "GET", "path": "/v1/audit", "query_string": "limit=5"},
        tenant="asgi-t1")
    results.append(("asgi GET /v1/audit",
                    status == 200 and r.get("ok") is True
                    and r.get("chain_valid") is True))

    # 策略
    status, r = _call(
        {"method": "POST", "path": "/v1/policy"},
        body={"max_ttl_seconds": 120},
        tenant="asgi-t1")
    results.append(("asgi POST /v1/policy",
                    status == 200 and r.get("ok") is True))

    # 404
    status, r = _call({"method": "GET", "path": "/v1/unknown"})
    results.append(("asgi 404 not found",
                    status == 404 and r.get("ok") is False))

    # 405 method not allowed
    status, r = _call({"method": "DELETE", "path": "/v1/identities"})
    results.append(("asgi 405 method not allowed",
                    status == 405 and r.get("ok") is False))

    # 跨租户隔离
    status, r = _call(
        {"method": "GET", "path": "/v1/audit", "query_string": "limit=5"},
        tenant="asgi-t2")
    results.append(("asgi 跨租户 t2 审计为空",
                    status == 200 and len(r.get("records", [])) == 0))

    # ---- v2.5 鉴权（启用后横向越权必须被拦在业务逻辑之外）----
    from auth import AuthTable
    tbl = AuthTable()
    tbl.add("k-acme", ["auth-acme"], note="Acme")
    tbl.add("k-globex", ["auth-globex"], note="Globex")
    tbl.add("k-admin", ["*"], note="管理员")
    init_pool(auth=tbl)

    # 未启用鉴权时上面这批请求都应正常；启用后逐个验证
    status, r = _call({"method": "GET", "path": "/health"},
                      tenant="auth-acme", api_key="k-acme")
    results.append(("asgi 鉴权开启·本租户放行", status == 200))

    status, r = _call({"method": "GET", "path": "/health"},
                      tenant="auth-acme")
    results.append(("asgi 鉴权开启·缺 key → 401",
                    status == 401 and r.get("reason") == "missing api key"))

    status, r = _call({"method": "GET", "path": "/health"},
                      tenant="auth-acme", api_key="k-wrong")
    results.append(("asgi 鉴权开启·错 key → 401",
                    status == 401 and r.get("reason") == "unknown api key"))

    status, r = _call({"method": "GET", "path": "/health"},
                      tenant="auth-globex", api_key="k-acme")
    results.append(("asgi 鉴权开启·跨租户 → 403",
                    status == 403 and r.get("reason") == "tenant not allowed"))

    status, r = _call({"method": "GET", "path": "/health"},
                      tenant="auth-anything", api_key="k-admin")
    results.append(("asgi 鉴权开启·管理员通配放行", status == 200))

    # 越权请求不能污染目标租户：用 acme key 尝试往 globex 注册标识
    status, r = _call(
        {"method": "POST", "path": "/v1/identities"},
        body={"idn": "agent://evil/root", "org": "evil",
              "agent_type": "issuance"},
        tenant="auth-globex", api_key="k-acme")
    results.append(("asgi 鉴权开启·越权写入被拒", status == 403))

    # 恢复无鉴权 pool，避免影响后续可能的调用
    init_pool()
    return results


def main():
    results = self_check()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%-8s %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "asgi_app_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
