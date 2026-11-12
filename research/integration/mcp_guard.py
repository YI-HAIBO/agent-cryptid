# -*- coding: utf-8 -*-
"""MCP 侧挂载：CryptidTokenVerifier + 受保护的 MCPServer。

为什么是 TokenVerifier
---------------------
MCP 2.x 的鉴权注入点就是 `TokenVerifier` 协议
（`mcp.server.auth.provider`）::

    async def verify_token(self, token: str) -> AccessToken | None

服务端 streamable_http 把它包进 `BearerAuthBackend`：读
`Authorization: Bearer <token>` → 调 `verify_token` → 返 None 即 401。
我们让 `verify_token` 内部复用 `cryptid_bridge.verify_bearer`，
于是一次实现即获得：签名 + 时间窗 + nonce 一次性 + 累加器撤销 + **受众绑定**。

RFC 8707 对齐（最亮点）
-----------------------
MCP 的 `AccessToken.resource` 字段语义正是 RFC 8707 Resource Indicator
（= 把凭证钉死在特定资源上）。cryptid 的 `aud` 与之逐字同义，
故直接 `resource = cred.aud`。`AuthSettings.validate_token_resource=False`
（受众由我们的 verifier 自己校验；且 cryptid aud 形如 `service://xxx`
非 http URL，交给 SDK 的 URL 比对会误拒）。
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from cryptid_bridge import verify_bearer  # noqa: E402

# MCP SDK（a2amcp venv）
from mcp.server.auth.provider import AccessToken  # noqa: E402
from mcp.server.auth.settings import AuthSettings  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402


class CryptidTokenVerifier:
    """结构化满足 mcp TokenVerifier 协议（鸭子类型，无需继承 Protocol）。

    `expected_aud`：本 MCP server 接受的 cryptid 受众。token 的 aud 必须
    等于它，否则 verify_bearer 返回 audience mismatch → verify_token 返
    None → 401。这就是「MCP 禁止 token 透传」的逐跳受众绑定答案。
    """

    def __init__(self, platform, expected_aud: str):
        self.platform = platform
        self.expected_aud = expected_aud

    async def verify_token(self, token: str):
        r = verify_bearer(self.platform, token, audience=self.expected_aud,
                          record_nonce=True)
        if not r.get("ok"):
            return None
        return AccessToken(
            token=token,
            client_id=r["sub"],
            scopes=list(r.get("scope") or []),
            expires_at=r.get("exp"),
            resource=self.expected_aud,   # = cred.aud，RFC 8707 indicator
            subject=r.get("sub"),
            claims={"iss": r.get("iss"), "jti": r.get("jti")},
        )


def build_protected_mcp_server(platform, *, name, expected_aud,
                               resource_url, issuer_url,
                               required_scopes=None):
    """构造一个用 cryptid 凭证保护的 MCP server（带一个示例工具）。

    - name:            MCP server 名
    - expected_aud:    本 server 的 cryptid 受众（token.aud 必须等于它）
    - resource_url:    本 server 的 http URL（SDK 的 OAuth resource 标识）
    - issuer_url:      签发方 URL（SDK 元数据用；演示可填占位 http URL）
    - required_scopes: SDK 层强制 scope（None=仅要求已认证）
    """
    verifier = CryptidTokenVerifier(platform, expected_aud)
    auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=resource_url,
        required_scopes=required_scopes,
        validate_token_resource=False,  # 受众由 verifier 自校验（见模块 docstring）
    )
    server = MCPServer(name=name, token_verifier=verifier, auth=auth)

    @server.tool()
    def invoice_read(invoice_id: str) -> str:
        """读取一张发票（受 cryptid 凭证保护的示例工具）。"""
        return "invoice %s: PAID (via cryptid-verified MCP tool)" % invoice_id

    return server


def self_check():
    """异步自测：直接驱动 CryptidTokenVerifier.verify_token 的各分支。"""
    import asyncio
    from cryptid_bridge import CryptidAuthority

    async def run():
        out = []
        auth = CryptidAuthority()
        auth.register("agent://demo/issuer", agent_type="issuance")
        auth.register("agent://demo/worker", agent_type="worker")
        v = CryptidTokenVerifier(auth.platform, "service://invoice")

        # 有效 token → AccessToken，且 resource == aud
        tok, _ = auth.issue("agent://demo/issuer", "agent://demo/worker",
                            "service://invoice", ["invoice:read"], ttl=3600)
        at = await v.verify_token(tok)
        out.append(("有效 token → AccessToken", at is not None))
        out.append(("client_id=sub", bool(at) and at.client_id == "agent://demo/worker"))
        out.append(("resource=aud(RFC8707)", bool(at) and at.resource == "service://invoice"))
        out.append(("scopes 透传", bool(at) and at.scopes == ["invoice:read"]))

        # 错误受众（passthrough）→ None
        tok_wrong, _ = auth.issue("agent://demo/issuer", "agent://demo/worker",
                                  "service://billing", ["billing:read"], ttl=3600)
        at2 = await v.verify_token(tok_wrong)
        out.append(("错误受众 token → None", at2 is None))

        # 畸形 token → None
        at3 = await v.verify_token("!!!garbage!!!")
        out.append(("畸形 token → None", at3 is None))

        # 撤销 → None
        tok_r, meta = auth.issue("agent://demo/issuer", "agent://demo/worker",
                                 "service://invoice", ["invoice:read"], ttl=3600)
        auth.revoke(meta["jti"])
        at4 = await v.verify_token(tok_r)
        out.append(("撤销 token → None", at4 is None))

        return out

    return asyncio.run(run())


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
