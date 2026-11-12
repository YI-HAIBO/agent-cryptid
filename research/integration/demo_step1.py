# -*- coding: utf-8 -*-
"""Step 1 端到端演示：cryptid 凭证同时保护 1 个 MCP server + 1 个 A2A agent。

场景（对应 A2A/MCP 两个官方承认的缺口）
--------------------------------------
一个智能体 worker 持 cryptid 凭证，分别：
  (MCP)  调用受保护 MCP server 的工具 invoice_read；
  (A2A)  向受保护 A2A agent 发一条 SendMessage。
两次调用都把 cryptid wire 凭证放进 `Authorization: Bearer`，
由服务端本地校验（签名 + aud 绑定 + scope + nonce + 撤销）。

攻击面（全部应被拒）：
  · 无 token                → 401
  · 畸形 token              → 401
  · 受众不符（passthrough） → 401   ← MCP 明令禁止的 token 透传
  · 已撤销 token            → 401

运行（a2amcp venv）：
    python research/integration/demo_step1.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fastapi.testclient import TestClient  # noqa: E402
from cryptid_bridge import CryptidAuthority  # noqa: E402
from mcp_guard import build_protected_mcp_server  # noqa: E402
from a2a_guard import build_a2a_app  # noqa: E402

from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from a2a.utils.constants import VERSION_HEADER, PROTOCOL_VERSION_CURRENT  # noqa: E402

ISSUER = "agent://demo-org/issuance-authority"
WORKER = "agent://demo-org/ops-agent-001"
MCP_AUD = "service://mcp-invoice"     # MCP server 的 cryptid 受众
A2A_AUD = "service://a2a-agent"       # A2A agent 的 cryptid 受众

_results = []


def check(name, ok):
    _results.append((name, bool(ok)))
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name))


def banner(title):
    print("\n" + "=" * 66 + "\n  " + title + "\n" + "=" * 66)


def main():
    auth = CryptidAuthority()
    auth.register(ISSUER, agent_type="issuance")
    auth.register(WORKER, agent_type="worker")

    # =============================================================
    # 场景 A：MCP server（streamable HTTP + BearerAuthBackend）
    # =============================================================
    banner("场景 A：受保护 MCP server（真实 streamable HTTP + TokenVerifier）")
    mcp_srv = build_protected_mcp_server(
        auth.platform, name="mcp-invoice", expected_aud=MCP_AUD,
        resource_url="https://mcp.example.com/invoice",
        issuer_url="https://cryptid.example.com")
    # 本地测试关掉 DNS-rebinding 主机校验（TestClient 的 Host=testserver）
    mcp_app = mcp_srv.streamable_http_app(
        stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False))
    H = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-06-18"}

    def mcp_token(aud=MCP_AUD, scope=("invoice:read",)):
        t, _ = auth.issue(ISSUER, WORKER, aud, list(scope), ttl=3600)
        return t

    init_body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": {"name": "cryptid-demo", "version": "1"}}}
    call_body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "invoice_read",
                            "arguments": {"invoice_id": "INV-42"}}}

    with TestClient(mcp_app) as c:
        # initialize（每个请求用新 token：nonce 一次性）
        r = c.post("/mcp", json=init_body,
                   headers={**H, "Authorization": "Bearer " + mcp_token()})
        check("MCP initialize（有效 token）→ 200", r.status_code == 200)

        # 有效 token → 工具真正执行
        r = c.post("/mcp", json=call_body,
                   headers={**H, "Authorization": "Bearer " + mcp_token()})
        check("MCP tools/call（有效 token）→ 200", r.status_code == 200)
        check("MCP 工具结果含 PAID（凭证通过后工具执行）", "PAID" in r.text)

        # 无 token → 401
        r = c.post("/mcp", json=call_body, headers=H)
        check("MCP tools/call（无 token）→ 401", r.status_code == 401)

        # 畸形 token → 401
        r = c.post("/mcp", json=call_body,
                   headers={**H, "Authorization": "Bearer !!!garbage!!!"})
        check("MCP tools/call（畸形 token）→ 401", r.status_code == 401)

        # 受众不符（把给别人的 token 透传给本 server）→ 401
        r = c.post("/mcp", json=call_body,
                   headers={**H, "Authorization": "Bearer " + mcp_token(aud="service://other")})
        check("MCP tools/call（受众不符/passthrough）→ 401", r.status_code == 401)

        # 已撤销 token → 401
        tok_rev, meta_rev = auth.issue(ISSUER, WORKER, MCP_AUD, ["invoice:read"], ttl=3600)
        auth.revoke(meta_rev["jti"], reason="demo compromise")
        r = c.post("/mcp", json=call_body,
                   headers={**H, "Authorization": "Bearer " + tok_rev})
        check("MCP tools/call（已撤销 token）→ 401", r.status_code == 401)

    # =============================================================
    # 场景 B：A2A agent（FastAPI 中间件守 JSON-RPC + agent-card）
    # =============================================================
    banner("场景 B：受保护 A2A agent（cryptid 中间件守 SendMessage + agent-card）")
    a2a_app, meta = build_a2a_app(
        auth.platform, expected_aud=A2A_AUD,
        card_name="cryptid-guarded-agent",
        card_desc="A2A agent guarded by agent-cryptid credentials")
    ver_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT}
    send_body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                 "params": {"message": {"role": "ROLE_USER",
                                        "parts": [{"text": "hello"}],
                                        "messageId": "u1"}}}

    def a2a_token(aud=A2A_AUD):
        t, _ = auth.issue(ISSUER, WORKER, aud, ["agent:invoke"], ttl=3600)
        return t

    with TestClient(a2a_app) as c:
        # agent-card：无 token → 401
        r = c.get(meta["card_url"])
        check("A2A agent-card（无 token）→ 401", r.status_code == 401)

        # agent-card：有效 token → 200 + 卡片
        r = c.get(meta["card_url"], headers={"Authorization": "Bearer " + a2a_token()})
        check("A2A agent-card（有效 token）→ 200", r.status_code == 200)
        check("A2A agent-card 含 agent 名", "cryptid-guarded-agent" in r.text)

        # SendMessage：无 token → 401
        r = c.post(meta["rpc_url"], json=send_body, headers=ver_hdr)
        check("A2A SendMessage（无 token）→ 401", r.status_code == 401)

        # SendMessage：有效 token → echo 回复
        r = c.post(meta["rpc_url"], json=send_body,
                   headers={**ver_hdr, "Authorization": "Bearer " + a2a_token()})
        check("A2A SendMessage（有效 token）→ 非401", r.status_code != 401)
        check("A2A echo 回复含 cryptid-verified", "cryptid-verified" in r.text)

        # 跨协议 passthrough：把签给 MCP 的 token 拿去调 A2A → 401
        r = c.post(meta["rpc_url"], json=send_body,
                   headers={**ver_hdr, "Authorization": "Bearer " + mcp_token()})
        check("A2A SendMessage（MCP 的 token/受众不符）→ 401", r.status_code == 401)

    # =============================================================
    # 汇总
    # =============================================================
    banner("Step 1 汇总")
    n_pass = sum(1 for _, ok in _results if ok)
    n_fail = sum(1 for _, ok in _results if not ok)
    for name, ok in _results:
        print("  %-4s %s" % ("PASS" if ok else "FAIL", name))
    print("\n  RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
