# -*- coding: utf-8 -*-
"""A2A 侧挂载：cryptid 校验中间件 + 受保护的 A2A server。

挂载方式（Step 0 已探明，a2a-sdk 1.2.3 = proto-first）
----------------------------------------------------
- 服务入口不再是 `A2AStarletteApp`（已不存在），而是::

      app = FastAPI()
      handler = DefaultRequestHandler(agent_executor=..., task_store=InMemoryTaskStore(), agent_card=card)
      add_a2a_routes_to_fastapi(app, agent_card_routes=..., jsonrpc_routes=...)

- 校验注入用**纯 ASGI 中间件**挂在 app 上（在 add_a2a_routes_to_fastapi 之前），
  读 `Authorization: Bearer <token>` → `cryptid_bridge.verify_bearer` → 失败即 401。
  中间件是 app 级，故 agent-card 路由与 JSON-RPC 消息路由被同一道门守住。

- 与 MCP 的 `TokenVerifier` 是「同一把 cryptid 锁的两个框架适配器」：
  两者都复用 `verify_bearer`，都做 aud 绑定 + scope + nonce + 撤销。
"""
import os
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from cryptid_bridge import verify_bearer, principal_from_result  # noqa: E402

# A2A + FastAPI SDK（a2amcp venv）
from starlette.types import ASGIApp, Receive, Scope, Send  # noqa: E402


class CryptidAuthMiddleware:
    """纯 ASGI 中间件：拦截 A2A 请求，校验 Bearer 里的 cryptid 凭证。

    - expected_aud：本 agent 的 cryptid 受众；token.aud 必须等于它。
    - exempt_paths：不放行的路径（如健康检查）。默认空。
    - record_nonce：True=登记 nonce 防重放（生产行为）。注意同一 token
      只能成功过一次；测试/演示请为每个请求签新 token。
    """

    def __init__(self, app: ASGIApp, platform, expected_aud: str,
                 exempt_paths=(), record_nonce=True):
        self.app = app
        self.platform = platform
        self.expected_aud = expected_aud
        self.exempt = tuple(exempt_paths)
        self.record_nonce = record_nonce

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in self.exempt:
            await self.app(scope, receive, send)
            return

        token = self._extract_bearer(scope)
        result = None
        if token:
            result = verify_bearer(self.platform, token,
                                   audience=self.expected_aud,
                                   record_nonce=self.record_nonce)
        if not (result and result.get("ok")):
            await self._reject(send, reason=(result or {}).get("reason", "missing token"))
            return

        # 放行：把主体信息挂到 scope，供下游 executor / 处理器读取
        scope.setdefault("state", {})
        try:
            scope["state"]["cryptid"] = principal_from_result(result)
        except Exception:
            pass
        scope["cryptid"] = principal_from_result(result)
        await self.app(scope, receive, send)

    @staticmethod
    def _extract_bearer(scope: Scope):
        headers = scope.get("headers") or []
        for k, v in headers:
            if k.lower() == b"authorization":
                val = v.decode("latin-1")
                if val.lower().startswith("bearer "):
                    return val[7:].strip()
        return None

    @staticmethod
    async def _reject(send: Send, reason: str):
        body = ('{"error":"invalid_token","error_description":"%s"}' % reason).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Bearer error="invalid_token"'),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def _make_echo_executor():
    """构造一个最小可用的 AgentExecutor：收到消息即回一条文本。"""
    from a2a.server.agent_execution import AgentExecutor
    from a2a.types import Message, Part, Role

    class CryptidEchoExecutor(AgentExecutor):
        async def execute(self, context, event_queue):
            ctx_id = getattr(context, "context_id", None)
            user_text = ""
            try:
                m = context.message
                if m is not None and m.parts:
                    user_text = m.parts[0].text or ""
            except Exception:
                pass
            reply = Message(
                message_id="reply-" + secrets.token_hex(8),
                context_id=ctx_id,
                role=Role.Value("ROLE_AGENT"),
                parts=[Part(text="cryptid-verified echo: " + (user_text or "(empty)"))],
            )
            await event_queue.enqueue_event(reply)

        async def cancel(self, context, event_queue):
            return None

    return CryptidEchoExecutor()


def _make_agent_card(card_name, card_desc, card_version, *,
                     cryptid_aud=None, declare_cryptid=True,
                     base_url="http://localhost/"):
    """构造 AgentCard；declare_cryptid=True 时把 cryptid 正式声明进卡片（MP1）。

    声明三处（均为 A2A 规范内机制，非自由 x- 字段）：
      · security_schemes["cryptid-bearer"] = http/bearer 方案（bearerFormat=agent-cryptid）
      · security_requirements = [ {cryptid-bearer: []} ]
      · capabilities.extensions = [ AgentExtension(uri="urn:agent-cryptid:1.0", ...) ]
    """
    from a2a.types import (AgentCard, AgentInterface, AgentCapabilities,
                           AgentSkill, SecurityScheme, HTTPAuthSecurityScheme,
                           SecurityRequirement, AgentExtension, StringList)

    caps = AgentCapabilities(streaming=False)
    sec_schemes = None
    sec_reqs = None
    if declare_cryptid:
        caps = AgentCapabilities(streaming=False, extensions=[
            AgentExtension(
                uri="urn:agent-cryptid:1.0",
                description="agent-cryptid verifiable credential "
                            "(SM2/SM9 + PQ hybrid, aud-bound, revocable)",
                required=False,
                params={"alg_tiers": "sm2,sm2-ml-dsa,hash-signature",
                        "aud_field": "aud",
                        "resource_indicator": "RFC8707",
                        "expected_aud": cryptid_aud or ""})])
        sec_schemes = {"cryptid-bearer": SecurityScheme(
            http_auth_security_scheme=HTTPAuthSecurityScheme(
                scheme="bearer", bearer_format="agent-cryptid",
                description="agent-cryptid credential in "
                            "Authorization: Bearer <token>"))}
        sec_reqs = [SecurityRequirement(
            schemes={"cryptid-bearer": StringList(list=[])})]

    return AgentCard(
        name=card_name, description=card_desc, version=card_version,
        supported_interfaces=[AgentInterface(
            url=base_url.rstrip("/") + "/", protocol_binding="JSONRPC",
            protocol_version="1.0")],
        capabilities=caps,
        default_input_modes=["text"], default_output_modes=["text"],
        skills=[AgentSkill(id="echo", name="echo", tags=["echo"],
                           description="cryptid-guarded echo",
                           input_modes=["text"], output_modes=["text"])],
        security_schemes=sec_schemes, security_requirements=sec_reqs,
    )


def build_a2a_app(platform, *, expected_aud, card_name, card_desc,
                  card_version="1.0.0", rpc_url="/",
                  exempt_paths=("/health",), record_nonce=True,
                  declare_cryptid=True):
    """构造带 cryptid 校验中间件的 A2A FastAPI app。

    返回 (app, meta)。meta 含 card_url / rpc_url 便于测试寻址。
    """
    from fastapi import FastAPI
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (add_a2a_routes_to_fastapi,
                                   create_agent_card_routes,
                                   create_jsonrpc_routes)

    card = _make_agent_card(card_name, card_desc, card_version,
                            cryptid_aud=expected_aud,
                            declare_cryptid=declare_cryptid)
    handler = DefaultRequestHandler(
        agent_executor=_make_echo_executor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    app = FastAPI(title=card_name)
    # 中间件须在挂 A2A 路由前加入（app 级，守住所有路由）
    app.add_middleware(CryptidAuthMiddleware, platform=platform,
                       expected_aud=expected_aud, exempt_paths=exempt_paths,
                       record_nonce=record_nonce)

    card_url = "/.well-known/agent-card.json"
    card_routes = create_agent_card_routes(card, card_url=card_url)
    jsonrpc_routes = create_jsonrpc_routes(handler, rpc_url=rpc_url)
    add_a2a_routes_to_fastapi(app, agent_card_routes=card_routes,
                              jsonrpc_routes=jsonrpc_routes)
    return app, {"card_url": card_url, "rpc_url": rpc_url, "card": card}


def self_check():
    """用 Starlette TestClient 验证中间件对真实 A2A 路由的放行/拒绝。"""
    from fastapi.testclient import TestClient
    from cryptid_bridge import CryptidAuthority
    from a2a.utils.constants import VERSION_HEADER, PROTOCOL_VERSION_CURRENT

    out = []
    auth = CryptidAuthority()
    auth.register("agent://demo/issuer", agent_type="issuance")
    auth.register("agent://demo/worker", agent_type="worker")
    app, meta = build_a2a_app(
        auth.platform, expected_aud="service://a2a-agent",
        card_name="cryptid-guarded-agent", card_desc="A2A agent guarded by cryptid")
    client = TestClient(app)
    ver_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT}

    # 1) agent-card 路由：无 token → 401
    r = client.get(meta["card_url"])
    out.append(("agent-card 无 token → 401", r.status_code == 401))

    # 2) agent-card 路由：畸形 token → 401
    r = client.get(meta["card_url"], headers={"Authorization": "Bearer !!!bad!!!"})
    out.append(("agent-card 坏 token → 401", r.status_code == 401))

    # 3) agent-card 路由：有效 token → 200 + 卡片 JSON
    tok, _ = auth.issue("agent://demo/issuer", "agent://demo/worker",
                        "service://a2a-agent", ["agent:invoke"], ttl=3600)
    r = client.get(meta["card_url"], headers={"Authorization": "Bearer " + tok})
    out.append(("agent-card 有效 token → 200", r.status_code == 200))
    out.append(("卡片含 agent 名", r.status_code == 200 and "cryptid-guarded-agent" in r.text))
    if r.status_code == 200:
        j = r.json()
        out.append(("卡片声明 cryptid-bearer 安全方案",
                    "cryptid-bearer" in j.get("securitySchemes", {})))
        out.append(("卡片声明 AgentExtension urn:agent-cryptid:1.0",
                    any(e.get("uri") == "urn:agent-cryptid:1.0"
                        for e in j.get("capabilities", {}).get("extensions", []))))

    # 4) JSON-RPC 消息路由：无 token → 401（中间件在到达 handler 前拦截）
    rpc_body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                "params": {"message": {"role": "ROLE_USER",
                                       "parts": [{"text": "hi"}],
                                       "messageId": "u1"}}}
    r = client.post(meta["rpc_url"], json=rpc_body)
    out.append(("JSON-RPC 无 token → 401", r.status_code == 401))

    # 5) JSON-RPC 消息路由：有效 token → 非 401（到达 handler；echo 回复）
    tok2, _ = auth.issue("agent://demo/issuer", "agent://demo/worker",
                         "service://a2a-agent", ["agent:invoke"], ttl=3600)
    r = client.post(meta["rpc_url"], json=rpc_body,
                    headers={**ver_hdr, "Authorization": "Bearer " + tok2})
    out.append(("JSON-RPC 有效 token → 非401", r.status_code != 401))
    out.append(("echo 回复含 cryptid-verified", "cryptid-verified" in r.text))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
