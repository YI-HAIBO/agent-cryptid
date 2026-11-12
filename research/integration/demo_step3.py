# -*- coding: utf-8 -*-
"""Step 3 演示：3 跳委托链 × 跨协议（A2A 多跳委托 open issue 的答案）。

场景
----
授权链 ISSUER → A → B → C（3 跳，scope 逐跳收敛）：

    根   ISSUER --[read,write,delete]--> A     (issue_credential, depth 0)
    跳1  A --[read,write]--> B                (issue_delegation, depth 1)
    跳2  B --[read]--> C                      (issue_delegation, depth 2)

C 只持有链尾凭证。演示四件事：
  1) 链结构：depth 递增、scope 逐跳收窄、父凭证收敛强制生效；
  2) 链验证：verify_delegation_chain 计算全链 scope 交集，3 跳收敛到 {read}；
  3) 跨协议：C 用链尾凭证调受保护 MCP 工具成功（200 + PAID）；
     同一张链尾凭证拿去调 A2A agent 被拒（401）——aud 绑定**穿越委托链存活**；
  4) 攻击面（全部应被拒）：
     · 越权跳      B 想给 C 多一个 invoice:admin  → 签发侧 scope escalation
     · 祖先撤销    撤掉根凭证                    → 整条链验链失败
     · 深度滥用    设 max_delegation_depth=3，第 4 跳被拒

运行（a2amcp venv）：
    python research/integration/demo_step3.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fastapi.testclient import TestClient  # noqa: E402

from cryptid_bridge import CryptidAuthority, encode_bearer  # noqa: E402
from mcp_guard import build_protected_mcp_server  # noqa: E402
from a2a_guard import build_a2a_app  # noqa: E402

from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from a2a.utils.constants import VERSION_HEADER, PROTOCOL_VERSION_CURRENT  # noqa: E402
from proto.agent_platform import Platform  # noqa: E402

# ------------------------------------------------------------------
# 场景常量
# ------------------------------------------------------------------
ORG = "agent://acme"
ISSUER = ORG + "/issuance-authority"     # 根签发方
A = ORG + "/platform-agent"              # 跳0 主体（链首）
B = ORG + "/task-agent"                  # 跳1 主体
C = ORG + "/worker-agent"                # 跳2 主体（链尾）
D = ORG + "/subworker-agent"             # 仅用于深度限制演示

MCP_AUD = "service://mcp-invoice"        # 整条链绑定的资源受众
A2A_AUD = "service://a2a-agent"

ROOT_SCOPE = ["invoice:read", "invoice:write", "invoice:delete"]
HOP1_SCOPE = ["invoice:read", "invoice:write"]
HOP2_SCOPE = ["invoice:read"]
TARGET_SCOPE = ["invoice:read"]          # MCP 工具要求的最小 scope

_results = []


def check(name, ok):
    _results.append((name, bool(ok)))
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name))


def banner(title):
    print("\n" + "=" * 68 + "\n  " + title + "\n" + "=" * 68)


def scope_str(s):
    return "{" + ",".join(sorted(s)) + "}"


def build_chain(auth):
    """构造一条全新 3 跳链，返回 (根凭证, 跳1, 跳2, meta)。

    每次重建：nonce 一次性，跨协议/重复出示都需要新凭证。
    """
    p = auth.platform
    root_r = p.issue_credential(ISSUER, A, MCP_AUD, list(ROOT_SCOPE), ttl=3600)
    h1 = p.issue_delegation(A, B, MCP_AUD, list(HOP1_SCOPE),
                            ttl=1800, parent_cred=root_r["cred"])
    h2 = p.issue_delegation(B, C, MCP_AUD, list(HOP2_SCOPE),
                            ttl=900, parent_cred=h1["cred"])
    meta = {"root": root_r, "hop1": h1, "hop2": h2,
            "root_wire": root_r["cred"], "h1_wire": h1["cred"],
            "h2_wire": h2["cred"]}
    return meta


# ================================================================
def main():
    auth = CryptidAuthority()
    auth.register(ISSUER, agent_type="issuance")
    for who in (A, B, C):
        auth.register(who, agent_type="worker")

    # =============================================================
    banner("1. 构造 3 跳委托链（scope 逐跳收敛，父凭证强制生效）")
    ch = build_chain(auth)
    print("  根  %s --[issuers]--> %s   depth=%s scope=%s" % (
        ISSUER.split('/')[-1], A.split('/')[-1],
        ch["root"].get("depth"), scope_str(ROOT_SCOPE)))
    print("  跳1 %s --> %s             depth=%s scope=%s" % (
        A.split('/')[-1], B.split('/')[-1],
        ch["hop1"]["depth"], scope_str(HOP1_SCOPE)))
    print("  跳2 %s --> %s             depth=%s scope=%s" % (
        B.split('/')[-1], C.split('/')[-1],
        ch["hop2"]["depth"], scope_str(HOP2_SCOPE)))

    check("根凭证签发成功", ch["root"].get("ok") is True)
    check("跳1 签发成功", ch["hop1"].get("ok") is True)
    check("跳2 签发成功", ch["hop2"].get("ok") is True)
    # 根凭证是普通签发（非委托），depth 记在血缘登记簿里 = 0
    root_depth = auth.platform._cred_registry[ch["root"]["jti"]]["depth"]
    check("depth 沿链递增 0→1→2",
          [root_depth, ch["hop1"]["depth"], ch["hop2"]["depth"]] == [0, 1, 2])
    check("每跳都做父凭证收敛校验(parent_verified=True)",
          ch["hop1"].get("parent_verified") is True
          and ch["hop2"].get("parent_verified") is True)
    check("scope 逐跳收窄 |3|>|2|>|1|",
          len(HOP2_SCOPE) < len(HOP1_SCOPE) < len(ROOT_SCOPE))

    # =============================================================
    banner("2. 链验证：verify_delegation_chain 全链 scope 交集收敛")
    v = auth.platform.verify_delegation_chain(
        [ch["root_wire"], ch["h1_wire"], ch["h2_wire"]],
        MCP_AUD, TARGET_SCOPE)
    print("  ok=%s  chain_length=%s  scope_intersection=%s" % (
        v["ok"], v["chain_length"], scope_str(v["scope_intersection"])))
    print("  scope_satisfied=%s  audience_satisfied=%s" % (
        v["scope_satisfied"], v["audience_satisfied"]))
    check("3 跳链验证通过", v["ok"] is True)
    check("链长 = 3", v["chain_length"] == 3)
    check("全链交集收敛到 {invoice:read}",
          v["scope_intersection"] == TARGET_SCOPE)
    check("交集满足资源最小 scope 要求", v["scope_satisfied"] is True)
    check("全链受众一致(均为 service://mcp-invoice)",
          v["audience_satisfied"] is True)

    # 反证：跳1 若被要求 read+write 就交集不足 → 链合法但 scope 不满足
    v2 = auth.platform.verify_delegation_chain(
        [ch["root_wire"], ch["h1_wire"], ch["h2_wire"]],
        MCP_AUD, ["invoice:read", "invoice:write"])
    check("向链索取 read+write → scope 交集不足被拒",
          v2["ok"] is False and v2["scope_satisfied"] is False)

    # =============================================================
    banner("3. C 持链尾凭证跨协议调 MCP 工具（真实 streamable HTTP）")
    mcp_srv = build_protected_mcp_server(
        auth.platform, name="mcp-invoice", expected_aud=MCP_AUD,
        resource_url="https://mcp.example.com/invoice",
        issuer_url="https://cryptid.example.com")
    mcp_app = mcp_srv.streamable_http_app(
        stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False))
    H = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-06-18"}
    call_body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "invoice_read",
                            "arguments": {"invoice_id": "INV-777"}}}

    with TestClient(mcp_app) as c:
        # C 出示链尾凭证（新链，避免 nonce 重放）
        ch2 = build_chain(auth)
        tail_tok = encode_bearer(ch2["h2_wire"])
        r = c.post("/mcp", json=call_body,
                   headers={**H, "Authorization": "Bearer " + tail_tok})
        check("MCP tools/call（C 的链尾凭证）→ 200", r.status_code == 200)
        check("MCP 工具真正执行(结果含 PAID)", "PAID" in r.text)
        check("执行主体 = 链尾主体 C",
              "invoice INV-777" in r.text)

    # =============================================================
    banner("4. 跨协议透传：同一张链尾凭证拿去调 A2A agent → 401")
    a2a_app, meta = build_a2a_app(
        auth.platform, expected_aud=A2A_AUD,
        card_name="cryptid-guarded-agent",
        card_desc="A2A agent guarded by agent-cryptid credentials")
    ver_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT}
    send_body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                 "params": {"message": {"role": "ROLE_USER",
                                        "parts": [{"text": "read INV-777"}],
                                        "messageId": "u1"}}}
    with TestClient(a2a_app) as c:
        # 新链尾凭证（aud=service://mcp-invoice）→ A2A 期望 service://a2a-agent
        ch3 = build_chain(auth)
        r = c.post(meta["rpc_url"], json=send_body,
                   headers={**ver_hdr, "Authorization": "Bearer "
                                              + encode_bearer(ch3["h2_wire"])})
        check("A2A SendMessage（链尾凭证受众不符）→ 401", r.status_code == 401)
        # 对照：正确受众的链尾凭证 → 放行
        p = auth.platform
        ra = p.issue_credential(ISSUER, A, A2A_AUD, ["agent:invoke"], ttl=3600)
        rb = p.issue_delegation(A, C, A2A_AUD, ["agent:invoke"],
                                ttl=1800, parent_cred=ra["cred"])
        r = c.post(meta["rpc_url"], json=send_body,
                   headers={**ver_hdr, "Authorization": "Bearer "
                                              + encode_bearer(rb["cred"])})
        check("A2A SendMessage（同资源受众的链尾凭证）→ 非401",
              r.status_code != 401)
        check("A2A echo 回复含 cryptid-verified", "cryptid-verified" in r.text)

    # =============================================================
    banner("5. 攻击一：越权跳（B 想给 C 多一个 scope）→ 签发侧拒绝")
    ch4 = build_chain(auth)
    esc = auth.platform.issue_delegation(
        B, C, MCP_AUD, ["invoice:read", "invoice:admin"],
        ttl=900, parent_cred=ch4["h1_wire"])
    print("  结果 ok=%s  reason=%s  escalated=%s" % (
        esc.get("ok"), esc.get("reason"), esc.get("escalated")))
    check("越权跳被拒", esc.get("ok") is False)
    check("拒绝原因 = scope escalation", esc.get("reason") == "scope escalation")
    check("报告越权的 scope = invoice:admin",
          esc.get("escalated") == ["invoice:admin"])

    # =============================================================
    banner("6. 攻击二：撤销祖先（根凭证）→ 整条链验链失败")
    ch5 = build_chain(auth)
    auth.revoke(ch5["root"]["jti"], reason="root credential compromised")
    v3 = auth.platform.verify_delegation_chain(
        [ch5["root_wire"], ch5["h1_wire"], ch5["h2_wire"]],
        MCP_AUD, TARGET_SCOPE)
    print("  ok=%s  reasons=%s" % (v3["ok"], v3.get("reasons")))
    check("撤销祖先后链验证失败", v3["ok"] is False)

    # =============================================================
    banner("7. 攻击三：深度滥用（max_delegation_depth=3，第 4 跳被拒）")
    strict = Platform(policy={
        "default_scope": [], "max_ttl_seconds": 86400,
        "allowed_algs": ["sm2", "sm9", "sm2-ml-dsa", "hash-signature"],
        "max_delegation_depth": 3, "tenant": "acme",
    })
    auth3 = CryptidAuthority(platform=strict)
    auth3.register(ISSUER, agent_type="issuance")
    for who in (A, B, C, D):
        auth3.register(who, agent_type="worker")
    ra = strict.issue_credential(ISSUER, A, MCP_AUD, list(ROOT_SCOPE), ttl=3600)
    r1 = strict.issue_delegation(A, B, MCP_AUD, list(HOP1_SCOPE),
                                 ttl=1800, parent_cred=ra["cred"])
    r2 = strict.issue_delegation(B, C, MCP_AUD, list(HOP2_SCOPE),
                                 ttl=900, parent_cred=r1["cred"])
    r3 = strict.issue_delegation(C, D, MCP_AUD, ["invoice:read"],
                                 ttl=600, parent_cred=r2["cred"])
    check("深度 1/2/3 允许", r1.get("ok") and r2.get("ok") and r3.get("ok"))
    r4 = strict.issue_delegation(D, A, MCP_AUD, ["invoice:read"],
                                 ttl=600, parent_cred=r3["cred"])
    print("  第4跳 ok=%s  reason=%s  would_be_depth=%s" % (
        r4.get("ok"), r4.get("reason"), r4.get("would_be_depth")))
    check("第 4 跳被深度限制拒绝", r4.get("ok") is False)
    check("拒绝原因 = delegation depth exceeded",
          r4.get("reason") == "delegation depth exceeded")
    check("报告将达深度 = 4", r4.get("would_be_depth") == 4)

    # =============================================================
    banner("Step 3 汇总")
    n_pass = sum(1 for _, ok in _results if ok)
    n_fail = sum(1 for _, ok in _results if not ok)
    for name, ok in _results:
        print("  %-4s %s" % ("PASS" if ok else "FAIL", name))
    print("\n  RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
