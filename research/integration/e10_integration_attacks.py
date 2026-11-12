# -*- coding: utf-8 -*-
"""E10 集成实验：把 A2A/MCP 语境下的四类攻击脚本化，打到真实集成边界。

对应可行性方案 §5.3 的四条演示攻击，也对应两大协议官方承认的缺口：

  1. Token 透传（MCP 明令禁止）  —— 把给 server A 的凭证原样用于 server B
     → 机制：aud 绑定（aud ≡ RFC 8707 resource）；边界：MCP TokenVerifier + A2A 中间件
  2. 多跳越权（A2A 多跳委托 open issue）—— 第 2 跳 scope 超出第 1 跳
     → 机制：scope 收敛（child ⊆ parent）；边界：委托链验签器 + 签发侧收敛
  3. 混淆代理人（A2A 未建模）    —— 下游冒充原始委托方
     → 机制：sub/act/origin 进签名覆盖，篡改即签名失效；边界：MCP + A2A
  4. 算法降级（PQ 主线）         —— 剥掉混合签名的 PQ 分量
     → 机制：PQ 分量失败关闭；边界：MCP + A2A

每条攻击都打到**真实集成 seam**（非模拟）：MCP 侧驱动 `TokenVerifier.verify_token`
（BearerAuthBackend 正是调用它），A2A 侧驱动 `CryptidAuthMiddleware`（经 TestClient
走真 ASGI），委托侧驱动 `Platform.verify_delegation_chain` / `issue_delegation`。

另设**正向对照**（合法凭证在两端被接受），以证明拒绝是有意义的（守卫并非一律拒绝）。

运行环境：a2amcp venv（需 a2a-sdk + mcp）。
    python research/integration/e10_integration_attacks.py
返回 schema 与 eval_framework 的 E3 一致（attacks/n_attacks/all_rejected），便于合并。
"""
import asyncio
import csv
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fastapi.testclient import TestClient  # noqa: E402
from a2a.utils.constants import VERSION_HEADER, PROTOCOL_VERSION_CURRENT  # noqa: E402

from cryptid_bridge import CryptidAuthority, decode_bearer, encode_bearer  # noqa: E402
from mcp_guard import CryptidTokenVerifier, build_protected_mcp_server  # noqa: E402
from a2a_guard import build_a2a_app  # noqa: E402

ISSUER = "agent://e10/issuer"
WORKER = "agent://e10/worker"          # 被委托方 / 调用方
DOWNSTREAM = "agent://e10/downstream"  # 下游（多跳中的第二跳）
MCP_AUD = "service://mcp-invoice"
MCP_AUD_OTHER = "service://mcp-other"  # 另一台 MCP server 的受众
A2A_AUD = "service://a2a-agent"


def _mk_authority():
    auth = CryptidAuthority()
    auth.register(ISSUER, agent_type="issuance")
    auth.register(WORKER, agent_type="worker")
    auth.register(DOWNSTREAM, agent_type="worker")
    return auth


def E10_integration_attacks(quick=True):
    """执行 E10，返回匹配 eval 框架的结果 dict。"""
    auth = _mk_authority()
    attacks = []

    def rec(threat, attack, rejected, mechanism, boundary, detail=""):
        attacks.append({
            "threat": threat, "attack": attack, "rejected": bool(rejected),
            "mechanism": mechanism, "boundary": boundary, "detail": detail,
        })

    # ---- 两个真实守卫 ----
    mcp_verifier = CryptidTokenVerifier(auth.platform, MCP_AUD)
    mcp_verifier_other = CryptidTokenVerifier(auth.platform, MCP_AUD_OTHER)
    a2a_app, a2a_meta = build_a2a_app(
        auth.platform, expected_aud=A2A_AUD,
        card_name="cryptid-guarded-agent",
        card_desc="A2A agent guarded by agent-cryptid (E10)")
    a2a_client = TestClient(a2a_app)
    ver_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT}
    send_body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                 "params": {"message": {"role": "ROLE_USER",
                                        "parts": [{"text": "x"}],
                                        "messageId": "m1"}}}

    def issue(aud, scope, alg="sm2"):
        t, meta = auth.issue(ISSUER, WORKER, aud, scope, ttl=3600, alg_tier=alg)
        return t, meta

    # ============================================================
    # 正向对照：合法凭证在 MCP / A2A 两端都应被接受
    # ============================================================
    tok_ok, _ = issue(MCP_AUD, ["invoice:read"])
    at = asyncio.run(mcp_verifier.verify_token(tok_ok))
    control_mcp = at is not None and at.resource == MCP_AUD

    tok_ok_a2a, _ = issue(A2A_AUD, ["agent:invoke"])
    r_ok = a2a_client.post(a2a_meta["rpc_url"], json=send_body,
                           headers={**ver_hdr, "Authorization": "Bearer " + tok_ok_a2a})
    control_a2a = (r_ok.status_code != 401) and ("cryptid-verified" in r_ok.text)

    # ============================================================
    # 攻击 1：Token 透传（受众不符）
    # ============================================================
    # 1a @ MCP：给 mcp-invoice 的 token 拿去 mcp-other → verify_token 返 None
    tok_p, _ = issue(MCP_AUD, ["invoice:read"])
    at_p = asyncio.run(mcp_verifier_other.verify_token(tok_p))
    rec("token passthrough", "MCP token for aud=A replayed to server B",
        at_p is None, "audience binding (aud == server expected aud)",
        "MCP TokenVerifier")

    # 1b @ A2A：把签给 MCP 的 token 透传给 A2A agent → 401
    tok_p2, _ = issue(MCP_AUD, ["invoice:read"])
    r = a2a_client.post(a2a_meta["rpc_url"], json=send_body,
                        headers={**ver_hdr, "Authorization": "Bearer " + tok_p2})
    rec("token passthrough", "MCP-audience token replayed to A2A agent",
        r.status_code == 401, "audience binding (aud == agent expected aud)",
        "A2A middleware", "http=%d" % r.status_code)

    # ============================================================
    # 攻击 2：多跳越权（scope 超出父级）
    # ============================================================
    # 2a 签发侧收敛：出示父凭证委托时 scope 超集 → issue_delegation 拒绝
    parent_tok, parent_meta = issue(MCP_AUD, ["invoice:read"])
    parent_wire = decode_bearer(parent_tok)
    r_iss = auth.platform.issue_delegation(
        WORKER, DOWNSTREAM, MCP_AUD, ["invoice:read", "invoice:write"],
        parent_cred=parent_wire)
    rec("multi-hop scope escalation",
        "child delegation scope ⊊ parent, attempted at issuance",
        r_iss.get("ok") is False, "scope convergence enforced at sign-side (child ⊆ parent)",
        "delegation issue", "reason=%s" % r_iss.get("reason"))

    # 2b 验链侧收敛：绕过签发侧直接构造超scope子凭证，验链计算交集后拒绝
    child_wire_malic = auth.platform.issue_delegation(
        WORKER, DOWNSTREAM, MCP_AUD, ["invoice:read", "invoice:write"])  # 无 parent 强制
    child_wire = child_wire_malic.get("cred")
    r_chain = auth.platform.verify_delegation_chain(
        [parent_wire, child_wire], target_audience=MCP_AUD,
        target_scope=["invoice:read", "invoice:write"])
    rec("multi-hop scope escalation",
        "over-scoped child in chain, requesting escalated scope",
        r_chain.get("ok") is False, "scope intersection (effective ⊆ parent) at chain verify",
        "delegation chain verify",
        "scope_ok=%s" % r_chain.get("scope_satisfied"))

    # ============================================================
    # 攻击 3：混淆代理人（篡改 act 冒充原始委托方）
    # ============================================================
    # 先发一张委托凭证（act=WORKER，代表 WORKER 委托给 DOWNSTREAM）
    del_res = auth.platform.issue_delegation(WORKER, DOWNSTREAM, MCP_AUD,
                                             ["invoice:read"])
    del_wire = del_res.get("cred")
    tampered = dict(del_wire)
    tampered["act"] = ISSUER  # 冒充原始委托根
    tampered_tok = encode_bearer(tampered)
    at_c = asyncio.run(mcp_verifier.verify_token(tampered_tok))
    rec("confused deputy", "downstream forges act=root to impersonate delegator (MCP)",
        at_c is None, "sub/act/origin covered by signature; tampering → signature invalid",
        "MCP TokenVerifier")

    tampered_tok_a2a = encode_bearer({**tampered, "aud": A2A_AUD})
    r = a2a_client.post(a2a_meta["rpc_url"], json=send_body,
                        headers={**ver_hdr, "Authorization": "Bearer " + tampered_tok_a2a})
    rec("confused deputy", "downstream forges act=root to impersonate delegator (A2A)",
        r.status_code == 401, "sub/act/origin covered by signature; tampering → signature invalid",
        "A2A middleware", "http=%d" % r.status_code)

    # ============================================================
    # 攻击 4：算法降级（剥掉混合签名的 PQ 分量）
    # ============================================================
    tok_h, _ = issue(MCP_AUD, ["invoice:read"], alg="sm2-ml-dsa")
    wire_h = decode_bearer(tok_h)
    stripped = {k: v for k, v in wire_h.items() if k != "pq_sig"}  # 剥掉 PQ 分量
    stripped_tok = encode_bearer(stripped)
    at_d = asyncio.run(mcp_verifier.verify_token(stripped_tok))
    rec("algorithm downgrade", "strip pq_sig from hybrid sm2-ml-dsa credential (MCP)",
        at_d is None, "PQ component fail-closed (missing pq_sig → signature invalid)",
        "MCP TokenVerifier")

    stripped_tok_a2a = encode_bearer({**stripped, "aud": A2A_AUD})
    r = a2a_client.post(a2a_meta["rpc_url"], json=send_body,
                        headers={**ver_hdr, "Authorization": "Bearer " + stripped_tok_a2a})
    rec("algorithm downgrade", "strip pq_sig from hybrid sm2-ml-dsa credential (A2A)",
        r.status_code == 401, "PQ component fail-closed (missing pq_sig → signature invalid)",
        "A2A middleware", "http=%d" % r.status_code)

    # ============================================================
    # 汇总
    # ============================================================
    n = len(attacks)
    all_rejected = all(a["rejected"] for a in attacks)
    return {
        "attacks": attacks,
        "n_attacks": n,
        "n_rejected": sum(1 for a in attacks if a["rejected"]),
        "all_rejected": all_rejected,
        "controls": {
            "mcp_valid_accepted": bool(control_mcp),
            "a2a_valid_accepted": bool(control_a2a),
        },
        "integration": {
            "mcp_server": "mcp-invoice", "a2a_agent": "cryptid-guarded-agent",
            "a2a_sdk": "1.2.3", "mcp_sdk": "2.3.0",
        },
    }


def write_e10_csv(outdir, e10):
    path = os.path.join(outdir, "eval_E10_integration.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["threat", "attack", "boundary", "rejected",
                    "mechanism", "detail"])
        for a in e10["attacks"]:
            w.writerow([a["threat"], a["attack"], a["boundary"],
                        a["rejected"], a["mechanism"], a["detail"]])
    return path


def self_check():
    e10 = E10_integration_attacks(quick=False)
    out = []
    ctl = e10["controls"]
    out.append(("正向对照：合法 token 在 MCP 被接受", ctl["mcp_valid_accepted"]))
    out.append(("正向对照：合法 token 在 A2A 被接受", ctl["a2a_valid_accepted"]))
    for a in e10["attacks"]:
        out.append(("[%s] %s @ %s → 拒" % (a["threat"], a["attack"], a["boundary"]),
                    a["rejected"]))
    out.append(("全部攻击被拒 (all_rejected)", e10["all_rejected"]))
    return out


def main():
    print("=" * 64)
    print("E10 集成实验：A2A/MCP 四类攻击 @ 真实集成边界")
    print("=" * 64)
    e10 = E10_integration_attacks(quick=False)
    ctl = e10["controls"]
    print("正向对照：MCP 合法接受=%s  A2A 合法接受=%s" % (
        ctl["mcp_valid_accepted"], ctl["a2a_valid_accepted"]))
    print("-" * 64)
    for a in e10["attacks"]:
        print("  [%s] %-26s @ %-22s %s" % (
            "REJECT" if a["rejected"] else "ACCEPT",
            a["threat"], a["boundary"], a["detail"]))
    print("-" * 64)
    print("E10 集成攻击: %d/%d 被拒 => %s" % (
        e10["n_rejected"], e10["n_attacks"],
        "PASS" if (e10["all_rejected"] and ctl["mcp_valid_accepted"]
                   and ctl["a2a_valid_accepted"]) else "FAIL"))
    p = write_e10_csv(_HERE, e10)
    print("CSV:", p)
    ok = e10["all_rejected"] and ctl["mcp_valid_accepted"] and ctl["a2a_valid_accepted"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
