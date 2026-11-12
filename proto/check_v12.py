# -*- coding: utf-8 -*-
"""v2.10 测试：FR7-02 MCP 服务端鉴权适配组件。

PRD 场景三（工具调用鉴权）与场景五（异常处置与撤销）的落点：
智能体调外部工具时，由 MCP 服务端用本中台的凭证完成本地鉴权，
撤销后工具调用在秒级失效。

覆盖：
  [A] 基础工具调用鉴权
  [B] 撤销联动：撤销后工具调用立即失效
  [C] 委托链与级联撤销下的工具调用
  [D] 资源读取鉴权
  [E] SM9 无证书凭证走 MCP
  [F] 边界与失败关闭
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from mcp_adapter import MCPAuthzAdapter, _request_fingerprint
from credential import ALG_SM2, ALG_SM9

PASS = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("PASS     %s" % name)
    else:
        FAIL.append(name)
        print("FAIL     %s  %s" % (name, detail))


def new_platform(tenant, algs=None):
    p = Platform(tenant=tenant)
    p.configure_policy({"allowed_algs": algs or [ALG_SM2],
                        "max_ttl_seconds": 3600})
    return p


# ---------------------------------------------------------------------------
# [A] 基础工具调用鉴权
# ---------------------------------------------------------------------------

def test_basic_authorize():
    print("\n=== [A] 基础工具调用鉴权 ===")
    p = new_platform("mcp-a")
    for idn in ["agent://a/root", "agent://a/orch"]:
        p.register_identity(idn, org="a")
    authz = MCPAuthzAdapter(p, audience="mcp://a-server",
                            tool_scopes={"read_file": ["file:read"],
                                         "write_file": ["file:write"]})

    r = p.issue_credential("agent://a/root", "agent://a/orch",
                           "mcp://a-server", ["file:read"], ttl=3600)
    cred = r["cred"]

    d = authz.authorize_tool_call(cred, "read_file")
    check("A1 作用域匹配时放行", d["allow"] and d["reason"] == "ok")
    check("A2 返回所需作用域", d["required_scope"] == ["file:read"])
    check("A3 返回授予作用域", d["granted_scope"] == ["file:read"])
    check("A4 返回主体 sub", d["sub"] == "agent://a/orch")
    check("A5 返回授权源头 origin", d["origin"] == "agent://a/root",
          detail=str(d["origin"]))
    check("A5b 单凭证无委托时 act 等于 sub（防混淆代理人）",
          d["act"] == d["sub"] == "agent://a/orch")
    check("A6 返回撤销句柄 jti", d["jti"] == cred["jti"])

    # 作用域不足
    d = authz.authorize_tool_call(cred, "write_file")
    check("A7 作用域不足拒绝", not d["allow"])
    check("A7b 拒绝原因 insufficient scope",
          "insufficient scope" in d["reason"])

    # 未登记工具（fail-closed）
    d = authz.authorize_tool_call(cred, "rm_rf")
    check("A8 未登记工具拒绝（fail-closed）", not d["allow"])
    check("A8b 拒绝原因 tool not registered",
          d["reason"] == "tool not registered")

    # 缺凭证
    d = authz.authorize_tool_call(None, "read_file")
    check("A9 缺凭证拒绝", not d["allow"])
    check("A9b 拒绝原因 missing credential",
          d["reason"] == "missing credential")

    # 受众不符（跨服务挪用）
    r2 = p.issue_credential("agent://a/root", "agent://a/orch",
                            "mcp://b-server", ["file:read"], ttl=3600)
    d = authz.authorize_tool_call(r2["cred"], "read_file")
    check("A10 受众不符拒绝（防跨服务挪用）", not d["allow"])


# ---------------------------------------------------------------------------
# [B] 撤销联动
# ---------------------------------------------------------------------------

def test_revoke_linkage():
    print("\n=== [B] 撤销后工具调用立即失效 ===")
    p = new_platform("mcp-b")
    for idn in ["agent://b/root", "agent://b/orch"]:
        p.register_identity(idn, org="b")
    authz = MCPAuthzAdapter(p, audience="mcp://b-server",
                            tool_scopes={"read_file": ["file:read"]})

    r = p.issue_credential("agent://b/root", "agent://b/orch",
                           "mcp://b-server", ["file:read"], ttl=3600)
    cred = r["cred"]
    d = authz.authorize_tool_call(cred, "read_file")
    check("B1 撤销前放行", d["allow"])

    # 撤销
    p.revoke(cred["jti"], reason="compromised")
    d = authz.authorize_tool_call(cred, "read_file")
    check("B2 撤销后拒绝", not d["allow"])
    check("B2b 拒绝原因含 revoked", "revoked" in d["reason"],
          detail=d["reason"])

    # 按标识撤销后也失效
    r2 = p.issue_credential("agent://b/root", "agent://b/orch",
                            "mcp://b-server", ["file:read"], ttl=3600)
    check("B3 新凭证放行",
          authz.authorize_tool_call(r2["cred"], "read_file")["allow"])
    p.revoke_by_identity("agent://b/root", reason="root compromised")
    d = authz.authorize_tool_call(r2["cred"], "read_file")
    check("B4 按标识撤销后拒绝", not d["allow"])

    # 标识停用后签发不出新凭证，旧凭证虽有效但无法续期
    p.disable_identity("agent://b/root", reason="disabled")
    r3 = p.issue_credential("agent://b/root", "agent://b/orch",
                            "mcp://b-server", ["file:read"], ttl=3600)
    check("B5 标识停用后无法签发新凭证", not r3["ok"])

    # 重新启用后恢复（FR1-03 联动）
    p.enable_identity("agent://b/root", reason="cleared")
    r4 = p.issue_credential("agent://b/root", "agent://b/orch",
                            "mcp://b-server", ["file:read"], ttl=3600)
    check("B6 重新启用后可签发", r4["ok"])
    check("B7 重新启用后新凭证可调用工具",
          authz.authorize_tool_call(r4["cred"], "read_file")["allow"])


# ---------------------------------------------------------------------------
# [C] 委托链与级联撤销
# ---------------------------------------------------------------------------

def test_chain_and_cascade():
    print("\n=== [C] 委托链与级联撤销下的工具调用 ===")
    p = new_platform("mcp-c")
    ids = ["agent://c/root", "agent://c/orch", "agent://c/worker"]
    for idn in ids:
        p.register_identity(idn, org="c")
    authz = MCPAuthzAdapter(p, audience="mcp://c-server",
                            tool_scopes={"read_file": ["file:read"],
                                         "admin_cmd": ["sys:admin"]})

    r0 = p.issue_credential(ids[0], ids[1], "mcp://c-server",
                            ["file:read"], ttl=3600)
    r1 = p.issue_delegation(ids[1], ids[2], "mcp://c-server",
                            ["file:read"], ttl=3600,
                            parent_cred=r0["cred"])
    chain = [r0["cred"], r1["cred"]]

    d = authz.authorize_tool_call(chain=chain, tool_name="read_file")
    check("C1 委托链调用放行", d["allow"])
    check("C2 主体是末端 worker", d["sub"] == "agent://c/worker")
    check("C3 授权源头是链根 root", d["origin"] == "agent://c/root")
    check("C3b 代表方是委托方 orch（防混淆代理人）",
          d["act"] == "agent://c/orch", detail=str(d["act"]))
    check("C4 链长 2", d["chain_length"] == 2)

    # 链上权限不足：末端只有 file:read，调 admin_cmd 应拒绝
    d = authz.authorize_tool_call(chain=chain, tool_name="admin_cmd")
    check("C5 链上权限不足拒绝", not d["allow"])

    # 从根级联撤销 → 整链失效
    p.revoke_by_identity(ids[0], reason="root compromised")
    d = authz.authorize_tool_call(chain=chain, tool_name="read_file")
    check("C6 级联撤销后委托链调用拒绝", not d["allow"])

    # 最小权限过滤：撤销后 tools/list 应为空
    vis = authz.filter_tools(chain=chain,
                             tools=[{"name": "read_file"},
                                    {"name": "admin_cmd"}])
    check("C7 撤销后可见工具为空", vis == [])


# ---------------------------------------------------------------------------
# [D] 资源读取鉴权
# ---------------------------------------------------------------------------

def test_resource_read():
    print("\n=== [D] 资源读取鉴权 ===")
    p = new_platform("mcp-d")
    for idn in ["agent://d/root", "agent://d/orch"]:
        p.register_identity(idn, org="d")
    authz = MCPAuthzAdapter(p, audience="mcp://d-server",
                            tool_scopes={"read_file": ["file:read"]})

    r = p.issue_credential("agent://d/root", "agent://d/orch",
                           "mcp://d-server", ["resource:read"], ttl=3600)
    d = authz.authorize_resource_read(r["cred"], "file:///data/report.csv")
    check("D1 资源读取放行", d["allow"])
    check("D2 记录资源标识", d["resource"] == "file:///data/report.csv")

    # 无 resource:read 作用域
    r2 = p.issue_credential("agent://d/root", "agent://d/orch",
                            "mcp://d-server", ["file:read"], ttl=3600)
    d = authz.authorize_resource_read(r2["cred"], "file:///data/report.csv")
    check("D3 缺 resource:read 拒绝", not d["allow"])

    # 自定义所需作用域
    r3 = p.issue_credential("agent://d/root", "agent://d/orch",
                            "mcp://d-server", ["db:query"], ttl=3600)
    d = authz.authorize_resource_read(r3["cred"], "db://orders",
                                      required_scope=["db:query"])
    check("D4 自定义所需作用域放行", d["allow"])

    # 缺凭证
    d = authz.authorize_resource_read(None, "file:///x")
    check("D5 缺凭证拒绝", not d["allow"])


# ---------------------------------------------------------------------------
# [E] SM9 无证书凭证走 MCP
# ---------------------------------------------------------------------------

def test_sm9_mcp():
    print("\n=== [E] SM9 无证书凭证走 MCP ===")
    p = new_platform("mcp-e", algs=[ALG_SM2, ALG_SM9])
    for idn in ["agent://e/root", "agent://e/orch"]:
        p.register_identity(idn, org="e")
    authz = MCPAuthzAdapter(p, audience="mcp://e-server",
                            tool_scopes={"read_file": ["file:read"]})

    r = p.issue_credential("agent://e/root", "agent://e/orch",
                           "mcp://e-server", ["file:read"], ttl=3600,
                           alg_tier=ALG_SM9)
    check("E1 SM9 凭证签发成功", r["ok"])
    d = authz.authorize_tool_call(r["cred"], "read_file")
    check("E2 SM9 凭证工具调用放行", d["allow"], detail=d["reason"])

    d = authz.authorize_tool_call(r["cred"], "admin_cmd")
    check("E3 SM9 凭证越权拒绝",
          not d["allow"] and d["reason"] == "tool not registered")


# ---------------------------------------------------------------------------
# [F] 边界与失败关闭
# ---------------------------------------------------------------------------

def test_edge_and_failclosed():
    print("\n=== [F] 边界与失败关闭 ===")
    p = new_platform("mcp-f")
    for idn in ["agent://f/root", "agent://f/orch"]:
        p.register_identity(idn, org="f")
    authz = MCPAuthzAdapter(p, audience="mcp://f-server",
                            tool_scopes={"read_file": ["file:read"]})

    # 握手放行
    for m in ["initialize", "ping"]:
        res = authz.handle_request(m, {})
        check("F1 握手 %s 放行" % m, res["allow"])

    # 未知方法拒绝
    res = authz.handle_request("evil/method", {})
    check("F2 未知方法拒绝", not res["allow"])
    check("F2b 拒绝原因 unsupported method",
          res["reason"] == "unsupported method")

    # 工具清单过滤：凭证无权 → 空
    r = p.issue_credential("agent://f/root", "agent://f/orch",
                           "mcp://f-server", ["other:scope"], ttl=3600)
    vis = authz.filter_tools(r["cred"], [{"name": "read_file"}])
    check("F3 无权凭证看不到任何工具", vis == [])

    # 未登记工具不出现在清单里
    vis = authz.filter_tools(r["cred"],
                             [{"name": "read_file"}, {"name": "ghost_tool"}])
    check("F4 未登记工具不暴露",
          all(t["name"] != "ghost_tool" for t in vis))

    # once 模式：一凭证仅一次
    r2 = p.issue_credential("agent://f/root", "agent://f/orch",
                            "mcp://f-server", ["file:read"], ttl=3600)
    d1 = authz.authorize_tool_call(r2["cred"], "read_file",
                                   nonce_mode="once")
    d2 = authz.authorize_tool_call(r2["cred"], "read_file",
                                   nonce_mode="once")
    check("F5 once 模式首次放行", d1["allow"])
    check("F6 once 模式二次拒绝", not d2["allow"])

    # per-request：不同工具可各调一次
    r3 = p.issue_credential("agent://f/root", "agent://f/orch",
                            "mcp://f-server", ["file:read"], ttl=3600)
    authz.register_tool("list_dir", ["file:read"])
    d1 = authz.authorize_tool_call(r3["cred"], "read_file")
    d2 = authz.authorize_tool_call(r3["cred"], "list_dir")
    check("F7 per-request 不同工具各放行一次",
          d1["allow"] and d2["allow"],
          detail="%s / %s" % (d1["reason"], d2["reason"]))

    # per-request：完全相同的请求重放被拒
    d3 = authz.authorize_tool_call(r3["cred"], "read_file")
    check("F8 per-request 相同请求重放拒绝", not d3["allow"])
    check("F8b 拒绝原因 replay detected", d3["reason"] == "replay detected")

    # 请求指纹：工具不同则指纹不同
    f1 = _request_fingerprint("jti-1", "read_file", None)
    f2 = _request_fingerprint("jti-1", "list_dir", None)
    check("F9 请求指纹按工具区分", f1 != f2)

    # 受众不可为空（构造期强制）
    try:
        MCPAuthzAdapter(p, audience="")
        check("F10 空受众构造被拒", False)
    except ValueError:
        check("F10 空受众构造被拒", True)

    # 鉴权决策入审计
    a = p.audit_query(kind="mcp.authorize", limit=200)
    recs = a.get("records", [])
    check("F11 鉴权决策全部入审计", len(recs) >= 6,
          detail=str(len(recs)))
    denied = [r for r in recs
              if r.get("event", {}).get("allow") is False]
    check("F12 拒绝决策同样入审计", len(denied) >= 3,
          detail=str(len(denied)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_basic_authorize()
    test_revoke_linkage()
    test_chain_and_cascade()
    test_resource_read()
    test_sm9_mcp()
    test_edge_and_failclosed()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v12_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v12 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
