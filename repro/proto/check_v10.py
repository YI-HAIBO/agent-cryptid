# -*- coding: utf-8 -*-
"""v2.10 测试：FR3-02 作用域收敛 + FR3-05 有效期收敛。

FR3-02（必备）：子级作用域不得超出父级，超出即拒绝。
FR3-05（必备）：委托有效期不得超出父级有效期。

覆盖两条防线：
  [A] 签发侧（Platform.issue_delegation 的 parent_cred 参数）
  [B] 验链侧（delegation.verify_chain 的跳间收敛检查）
  [C] Platform.verify_delegation_chain 端到端
  [D] 边界条件（相等不算越权）
  [E] 向后兼容（不传 parent_cred 仍可签发）
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from credential import Credential, ALG_SM2
from delegation import verify_chain

PASS = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("PASS     %s" % name)
    else:
        FAIL.append(name)
        print("FAIL     %s  %s" % (name, detail))


# ---------------------------------------------------------------------------
# [A] 签发侧收敛：issue_delegation(parent_cred=...)
# ---------------------------------------------------------------------------

def test_issue_side_convergence():
    print("\n=== [A] 签发侧收敛（parent_cred） ===")
    p = Platform(tenant="conv")
    for idn in ["agent://conv/root", "agent://conv/a1", "agent://conv/a2"]:
        p.register_identity(idn, org="conv")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 7200})

    # 父凭证：root → a1，scope 两项
    r0 = p.issue_credential("agent://conv/root", "agent://conv/a1",
                            "service://conv", ["c:read", "c:list"], ttl=3600)
    check("A1 父凭证签发成功", r0["ok"])
    parent_cred = r0["cred"]

    # A2 合法收敛：子 scope 是父的子集
    r = p.issue_delegation("agent://conv/a1", "agent://conv/a2",
                           "service://conv", ["c:read"], ttl=3600,
                           parent_cred=parent_cred)
    check("A2 子级作用域收敛时签发成功", r["ok"])
    check("A2b 返回 parent_verified=True", r.get("parent_verified") is True)

    # A3 scope 越权 → 拒绝
    r = p.issue_delegation("agent://conv/a1", "agent://conv/a2",
                           "service://conv", ["c:read", "c:write"],
                           ttl=3600, parent_cred=parent_cred)
    check("A3 子级作用域越权被拒绝", not r["ok"])
    check("A3b 拒绝原因 scope escalation",
          r.get("reason") == "scope escalation")
    check("A3c 返回越权项 c:write",
          r.get("escalated") == ["c:write"])

    # A4 父凭证主体不是委托方 → 拒绝
    r = p.issue_delegation("agent://conv/a2", "agent://conv/a1",
                           "service://conv", ["c:read"], ttl=3600,
                           parent_cred=parent_cred)
    check("A4 父凭证不属于委托方被拒绝", not r["ok"])
    check("A4b 拒绝原因 parent credential not held by delegator",
          r.get("reason") == "parent credential not held by delegator")

    # A5 父凭证受众不一致 → 拒绝
    r = p.issue_delegation("agent://conv/a1", "agent://conv/a2",
                           "service://other", ["c:read"], ttl=3600,
                           parent_cred=parent_cred)
    check("A5 父凭证受众不一致被拒绝", not r["ok"])
    check("A5b 拒绝原因 parent audience mismatch",
          r.get("reason") == "parent audience mismatch")

    # A6 父凭证已撤销 → 不得再派生
    p.revoke(parent_cred["jti"], reason="test revoke parent")
    r = p.issue_delegation("agent://conv/a1", "agent://conv/a2",
                           "service://conv", ["c:read"], ttl=3600,
                           parent_cred=parent_cred)
    check("A6 父凭证已撤销后不得派生", not r["ok"])
    check("A6b 拒绝原因 parent credential revoked",
          r.get("reason") == "parent credential revoked")

    # A7 非法父凭证格式 → 拒绝
    r = p.issue_delegation("agent://conv/a1", "agent://conv/a2",
                           "service://conv", ["c:read"], ttl=3600,
                           parent_cred={"bad": "payload"})
    check("A7 非法父凭证格式被拒绝", not r["ok"])
    check("A7b 拒绝原因 invalid parent credential",
          r.get("reason") == "invalid parent credential")


# ---------------------------------------------------------------------------
# [A8] 有效期截断 FR3-05
# ---------------------------------------------------------------------------

def test_exp_truncation():
    print("\n=== [A8] 有效期截断（FR3-05） ===")
    p = Platform(tenant="conv2")
    for idn in ["agent://conv2/root", "agent://conv2/a1", "agent://conv2/a2"]:
        p.register_identity(idn, org="conv2")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 86400})

    # 父凭证 ttl=60（短）
    r0 = p.issue_credential("agent://conv2/root", "agent://conv2/a1",
                            "service://conv2", ["c:read"], ttl=60)
    parent_cred = r0["cred"]
    parent_exp = parent_cred["exp"]

    # 子凭证请求 ttl=3600（远超父级）→ 应被截断到父级 exp
    r = p.issue_delegation("agent://conv2/a1", "agent://conv2/a2",
                           "service://conv2", ["c:read"], ttl=3600,
                           parent_cred=parent_cred)
    check("A8 子级 ttl 超父级时签发成功", r["ok"])
    check("A8b 标记 exp_truncated", r.get("exp_truncated") is True)
    check("A8c 子级 exp 被截断到父级",
          r["cred"]["exp"] == parent_exp,
          detail="child=%s parent=%s" % (r["cred"]["exp"], parent_exp))

    # 父凭证 ttl 大时不应该截断
    r0b = p.issue_credential("agent://conv2/root", "agent://conv2/a1",
                             "service://conv2", ["c:read"], ttl=7200)
    r2 = p.issue_delegation("agent://conv2/a1", "agent://conv2/a2",
                            "service://conv2", ["c:read"], ttl=60,
                            parent_cred=r0b["cred"])
    check("A8d 子级 ttl 更短时不截断",
          r2["ok"] and r2.get("exp_truncated") is False)

    # 审计记录含 parent_jti
    audit = p.audit_query(kind="delegation.issue", limit=10)
    evs = [rec.get("event", {}) for rec in audit.get("records", [])]
    check("A8e 审计记录含 parent_verified 字段",
          any("parent_verified" in e for e in evs))


# ---------------------------------------------------------------------------
# [B] 验链侧收敛：verify_chain（隔离测试，签名有效但越权）
# ---------------------------------------------------------------------------

def test_verify_side_convergence():
    print("\n=== [B] 验链侧收敛（verify_chain） ===")
    p = Platform(tenant="conv3")
    for idn in ["agent://conv3/root", "agent://conv3/a1", "agent://conv3/a2"]:
        p.register_identity(idn, org="conv3")

    now = int(time.time())
    issuers = {
        "agent://conv3/root": p._identities["agent://conv3/root"]["pub"],
        "agent://conv3/a1": p._identities["agent://conv3/a1"]["pub"],
    }

    def mk(sub, iss, scope, exp, act=None):
        c = Credential(sub=sub, iss=iss, aud="service://conv3",
                       scope=scope, exp=exp, act=act or iss,
                       alg_tier=ALG_SM2)
        c.sign(iss, p._derive_priv(iss))
        return c

    # B1 合法链（scope 收敛、exp 收敛）→ 通过
    parent = mk("agent://conv3/a1", "agent://conv3/root",
                ["c:read", "c:list"], now + 3600)
    child = mk("agent://conv3/a2", "agent://conv3/a1", ["c:read"],
               now + 3600)
    ok, reasons = verify_chain([parent, child], issuers, now=now)
    check("B1 收敛链验证通过", ok, detail=str(reasons))

    # B2 scope 越权（签名有效，但子 scope 超出父）→ 失败
    bad_scope = mk("agent://conv3/a2", "agent://conv3/a1",
                   ["c:read", "c:write"], now + 3600)
    ok, reasons = verify_chain([parent, bad_scope], issuers, now=now)
    check("B2 子级作用域越权验链失败", not ok)
    check("B2b 失败原因含 scope escalation",
          any("scope escalation" in r for r in reasons),
          detail=str(reasons))

    # B3 exp 越权（子 exp 超过父）→ 失败
    bad_exp = mk("agent://conv3/a2", "agent://conv3/a1", ["c:read"],
                 now + 7200)
    ok, reasons = verify_chain([parent, bad_exp], issuers, now=now)
    check("B3 子级有效期超父级验链失败", not ok)
    check("B3b 失败原因含 exp exceeds parent",
          any("exp exceeds parent" in r for r in reasons),
          detail=str(reasons))

    # B4 完全越权（完全不相干的 scope）→ 失败
    bad_all = mk("agent://conv3/a2", "agent://conv3/a1", ["x:admin"],
                 now + 3600)
    ok, reasons = verify_chain([parent, bad_all], issuers, now=now)
    check("B4 完全越权作用域验链失败", not ok)


# ---------------------------------------------------------------------------
# [C] Platform.verify_delegation_chain 端到端
# ---------------------------------------------------------------------------

def test_platform_chain_e2e():
    print("\n=== [C] Platform 委托链端到端收敛 ===")
    p = Platform(tenant="conv4")
    ids = ["agent://conv4/h%d" % i for i in range(4)]
    for idn in ids:
        p.register_identity(idn, org="conv4")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    # 合法 3 跳链，逐级收敛 scope
    r0 = p.issue_credential(ids[0], ids[1], "service://conv4",
                            ["c:read", "c:list", "c:write"], ttl=3600)
    r1 = p.issue_delegation(ids[1], ids[2], "service://conv4",
                            ["c:read", "c:list"], ttl=3600,
                            parent_cred=r0["cred"])
    r2 = p.issue_delegation(ids[2], ids[3], "service://conv4",
                            ["c:read"], ttl=3600,
                            parent_cred=r1["cred"])
    check("C1 逐级收敛签发全部成功",
          r0["ok"] and r1["ok"] and r2["ok"])

    res = p.verify_delegation_chain([r0["cred"], r1["cred"], r2["cred"]],
                                    "service://conv4", ["c:read"])
    check("C2 收敛链验证通过", res["ok"], detail=str(res.get("reasons")))
    check("C3 权限交集为末端 scope",
          res["scope_intersection"] == ["c:read"],
          detail=str(res["scope_intersection"]))
    check("C4 链长为 3", res["chain_length"] == 3)

    # 末端请求超出交集的能力 → 不满足
    res2 = p.verify_delegation_chain([r0["cred"], r1["cred"], r2["cred"]],
                                     "service://conv4", ["c:write"])
    check("C5 请求超出交集时 scope_satisfied=False",
          res2["scope_satisfied"] is False)


# ---------------------------------------------------------------------------
# [D] 边界条件：相等不算越权
# ---------------------------------------------------------------------------

def test_boundary():
    print("\n=== [D] 边界条件 ===")
    p = Platform(tenant="conv5")
    for idn in ["agent://conv5/root", "agent://conv5/a1", "agent://conv5/a2"]:
        p.register_identity(idn, org="conv5")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    r0 = p.issue_credential("agent://conv5/root", "agent://conv5/a1",
                            "service://conv5", ["c:read"], ttl=3600)
    # 子 scope 与父完全相等 → 不算越权（issubset 非严格）
    r = p.issue_delegation("agent://conv5/a1", "agent://conv5/a2",
                           "service://conv5", ["c:read"], ttl=3600,
                           parent_cred=r0["cred"])
    check("D1 子级 scope 与父相等允许", r["ok"])
    res = p.verify_delegation_chain([r0["cred"], r["cred"]],
                                    "service://conv5", ["c:read"])
    check("D2 相等 scope 链验证通过", res["ok"],
          detail=str(res.get("reasons")))

    # 子 ttl 与父相同 → exp 可能相等或截断，不应失败
    check("D3 相等 ttl 不触发越权判定",
          r["cred"]["exp"] <= r0["cred"]["exp"])

    # 空 scope 子集
    r2 = p.issue_delegation("agent://conv5/a1", "agent://conv5/a2",
                            "service://conv5", [], ttl=3600,
                            parent_cred=r0["cred"])
    check("D4 空作用域是任意父级的子集", r2["ok"])


# ---------------------------------------------------------------------------
# [E] 向后兼容：不传 parent_cred
# ---------------------------------------------------------------------------

def test_backward_compat():
    print("\n=== [E] 向后兼容 ===")
    p = Platform(tenant="conv6")
    for idn in ["agent://conv6/root", "agent://conv6/a1", "agent://conv6/a2"]:
        p.register_identity(idn, org="conv6")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    r0 = p.issue_credential("agent://conv6/root", "agent://conv6/a1",
                            "service://conv6", ["c:read"], ttl=3600)
    # 不传 parent_cred：仍可签发（老调用方式不变）
    r = p.issue_delegation("agent://conv6/a1", "agent://conv6/a2",
                           "service://conv6", ["c:read"], ttl=3600)
    check("E1 不传 parent_cred 仍可签发", r["ok"])
    check("E2 标记 parent_verified=False",
          r.get("parent_verified") is False)
    check("E3 返回不含 exp_truncated 截断",
          r.get("exp_truncated") is False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_issue_side_convergence()
    test_exp_truncation()
    test_verify_side_convergence()
    test_platform_chain_e2e()
    test_boundary()
    test_backward_compat()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v10_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v10 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
