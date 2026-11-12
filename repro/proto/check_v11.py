# -*- coding: utf-8 -*-
"""v2.10 测试：FR1-03 标识重新启用 + FR4-02 下游委托级联撤销。

FR1-03（必备）：支持标识的停用与重新启用。
    关键语义：重新启用必须复用原密钥对，不能靠「重新注册」代替。
FR4-02（必备）：支持按标识废止该智能体全部凭证及其下游委托。
    关键语义：级联——下游委托链上的凭证一并废止（传递闭包）。

覆盖：
  [A] FR1-03 进程内语义
  [B] FR1-03 持久化重启
  [C] FR1-03 HTTP 路由
  [D] FR4-02 级联撤销
  [E] FR4-02 级联边界
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from http_api import route as http_route, TenantPool
from persistence import SQLiteBackend
from credential import ALG_SM2

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
# [A] FR1-03 进程内语义
# ---------------------------------------------------------------------------

def test_enable_semantics():
    print("\n=== [A] FR1-03 标识重新启用 ===")
    p = Platform(tenant="en")
    reg = p.register_identity("agent://en/iss", org="en")
    p.register_identity("agent://en/sub", org="en")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})
    pub_before = p._identities["agent://en/iss"]["pub"]
    pub_x_before = reg["pub_x"]

    # 停用
    r = p.disable_identity("agent://en/iss", reason="suspicious")
    check("A1 停用成功", r["ok"] and r["status"] == "disabled")

    # 停用后不得签发
    r = p.issue_credential("agent://en/iss", "agent://en/sub",
                           "service://en", ["en:read"], ttl=3600)
    check("A2 停用后签发被拒", not r["ok"])
    check("A2b 拒绝原因 issuer disabled",
          r.get("reason") == "issuer disabled")

    # 重新启用
    r = p.enable_identity("agent://en/iss", reason="cleared")
    check("A3 重新启用成功", r["ok"] and r["status"] == "active")

    # 核心语义：密钥对未变（与重新注册的区别）
    pub_after = p._identities["agent://en/iss"]["pub"]
    check("A4 重新启用后密钥对未变（非换身份）",
          pub_before == pub_after,
          detail="before=%s after=%s" % (pub_before, pub_after))
    check("A4b pub_x 与注册时一致",
          "%064x" % pub_after[0] == pub_x_before)

    # 重新启用后可正常签发
    r = p.issue_credential("agent://en/iss", "agent://en/sub",
                           "service://en", ["en:read"], ttl=3600)
    check("A5 重新启用后可签发凭证", r["ok"])
    if r["ok"]:
        v = p.verify_credential(r["cred"], audience="service://en")
        check("A6 重新启用后签发的凭证可校验", v["ok"])

    # 已 active 再 enable → 拒绝
    r = p.enable_identity("agent://en/iss")
    check("A7 对已启用标识再 enable 被拒", not r["ok"])
    check("A7b 拒绝原因 already active",
          r.get("reason") == "already active")

    # 未知标识 → 拒绝
    r = p.enable_identity("agent://en/nonexistent")
    check("A8 未知标识 enable 被拒", not r["ok"])
    check("A8b 拒绝原因 unknown identity",
          r.get("reason") == "unknown identity")

    # 停用原因已清空（当前状态不应还挂着 disable_reason）
    meta = p._identities["agent://en/iss"]["meta"]
    check("A9 重新启用后 disable_reason 已清空",
          meta.get("disable_reason") is None)
    check("A9b disabled_at 保留为历史痕迹",
          meta.get("disabled_at") is not None)

    # 审计留痕
    audit = p.audit_query(kind="identity.enable", limit=10)
    check("A10 审计含 identity.enable 事件",
          len(audit.get("records", [])) >= 1)


# ---------------------------------------------------------------------------
# [B] FR1-03 持久化重启
# ---------------------------------------------------------------------------

def test_enable_persistence():
    print("\n=== [B] FR1-03 持久化重启 ===")
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "enable.db")
    try:
        p1 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
        reg = p1.register_identity("agent://pe/iss", org="pe")
        p1.register_identity("agent://pe/sub", org="pe")
        p1.configure_policy({"allowed_algs": [ALG_SM2],
                             "max_ttl_seconds": 3600})
        p1.disable_identity("agent://pe/iss", reason="test")
        check("B1 停用已持久化",
              p1._identities["agent://pe/iss"]["status"] == "disabled")

        p1.enable_identity("agent://pe/iss", reason="test-cleared")
        pub_before = p1._identities["agent://pe/iss"]["pub"]
        p1._pers.close()
        del p1

        # 重启
        p2 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
        st = p2._identities["agent://pe/iss"]["status"]
        check("B2 重启后仍为 active", st == "active", detail=st)
        check("B3 重启后密钥对一致",
              p2._identities["agent://pe/iss"]["pub"] == pub_before)
        p2.configure_policy({"allowed_algs": [ALG_SM2],
                             "max_ttl_seconds": 3600})
        r = p2.issue_credential("agent://pe/iss", "agent://pe/sub",
                                "service://pe", ["pe:read"], ttl=3600)
        check("B4 重启后可正常签发", r["ok"])
        p2._pers.close()
        del p2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# [C] FR1-03 HTTP 路由
# ---------------------------------------------------------------------------

def test_enable_http():
    print("\n=== [C] FR1-03 HTTP 路由 ===")
    pool = TenantPool()
    plat = pool.get("t1")
    plat.register_identity("agent://he/iss", org="he")
    plat.configure_policy({"allowed_algs": [ALG_SM2],
                           "max_ttl_seconds": 3600})

    r = http_route(pool, "POST", "/v1/identities/disable", None,
                   {"idn": "agent://he/iss", "reason": "test"},
                   tenant="t1")
    check("C1 HTTP 停用成功", r[0] == 200 and r[1]["status"] == "disabled")

    r = http_route(pool, "POST", "/v1/identities/enable", None,
                   {"idn": "agent://he/iss", "reason": "cleared"},
                   tenant="t1")
    check("C2 HTTP 重新启用成功", r[0] == 200 and r[1]["ok"])
    check("C3 返回 status=active", r[1].get("status") == "active")

    r = http_route(pool, "POST", "/v1/identities/enable", None,
                   {"idn": "agent://he/nonexistent"}, tenant="t1")
    check("C4 HTTP 未知标识 enable 返回 400", r[0] == 400)


# ---------------------------------------------------------------------------
# [D] FR4-02 级联撤销
# ---------------------------------------------------------------------------

def test_cascade_revoke():
    print("\n=== [D] FR4-02 下游委托级联撤销 ===")
    p = Platform(tenant="cas")
    ids = ["agent://cas/h%d" % i for i in range(5)]
    for idn in ids:
        p.register_identity(idn, org="cas")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    # 构造 4 跳链：h0 → h1 → h2 → h3 → h4
    r0 = p.issue_credential(ids[0], ids[1], "service://cas",
                            ["cas:read"], ttl=3600)
    chain = [r0["cred"]]
    prev = r0["cred"]
    for i in range(1, 4):
        r = p.issue_delegation(ids[i], ids[i + 1], "service://cas",
                               ["cas:read"], ttl=3600, parent_cred=prev)
        chain.append(r["cred"])
        prev = r["cred"]
    check("D1 4 跳链构造成功", len(chain) == 4)

    # 撤销全链前：全部有效
    res = p.verify_delegation_chain(chain, "service://cas", ["cas:read"])
    check("D2 撤销前整链验证通过", res["ok"])

    # 从根（h0）撤销 → 全链级联废止
    r = p.revoke_by_identity(ids[0], reason="root compromised")
    check("D3 从根撤销 4 张凭证", r["revoked"] == 4, detail=str(r))

    res = p.verify_delegation_chain(chain, "service://cas", ["cas:read"])
    check("D4 级联后整链验证失败", not res["ok"])

    # 每一跳单独校验也都失败
    all_fail = all(
        not p.verify_credential(c, audience="service://cas")["ok"]
        for c in chain)
    check("D5 每一跳单独校验均失败", all_fail)


def test_cascade_from_middle():
    print("\n=== [D6] 从中间节点撤销 ===")
    p = Platform(tenant="cas2")
    ids = ["agent://cas2/h%d" % i for i in range(5)]
    for idn in ids:
        p.register_identity(idn, org="cas2")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    r0 = p.issue_credential(ids[0], ids[1], "service://cas2",
                            ["c:read"], ttl=3600)
    chain = [r0["cred"]]
    prev = r0["cred"]
    for i in range(1, 4):
        r = p.issue_delegation(ids[i], ids[i + 1], "service://cas2",
                               ["c:read"], ttl=3600, parent_cred=prev)
        chain.append(r["cred"])
        prev = r["cred"]

    # 从 h2 撤销：r1(iss=h2? no) —— h2 是 chain[1].sub
    # 种子 = iss==h2 (chain[2]) ∪ sub==h2 (chain[1])
    # 级联 = chain[2] 的子 chain[3]
    # 故应撤销 chain[1], chain[2], chain[3]，chain[0] 保留
    r = p.revoke_by_identity(ids[2], reason="mid compromised")
    check("D6 从中间撤销 3 张（含其持有的与其派生的）",
          r["revoked"] == 3, detail=str(r))
    check("D7 上游根凭证不受影响",
          p.verify_credential(chain[0],
                              audience="service://cas2")["ok"] is True)
    check("D8 该节点持有的凭证被废",
          not p.verify_credential(chain[1],
                                  audience="service://cas2")["ok"])


# ---------------------------------------------------------------------------
# [E] FR4-02 级联边界
# ---------------------------------------------------------------------------

def test_cascade_edge():
    print("\n=== [E] FR4-02 级联边界 ===")
    p = Platform(tenant="cas3")
    ids = ["agent://cas3/h%d" % i for i in range(3)]
    for idn in ids:
        p.register_identity(idn, org="cas3")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    r0 = p.issue_credential(ids[0], ids[1], "service://cas3",
                            ["c:read"], ttl=3600)
    r1 = p.issue_delegation(ids[1], ids[2], "service://cas3",
                            ["c:read"], ttl=3600, parent_cred=r0["cred"])

    # cascade=False 退化为 v2.9 行为：只撤种子（iss==h0 的 r0），不扩散
    r = p.revoke_by_identity(ids[0], reason="no cascade", cascade=False)
    check("E1 cascade=False 只撤 1 张", r["revoked"] == 1, detail=str(r))
    check("E2 cascade=False 时下游委托仍有效",
          p.verify_credential(r1["cred"],
                              audience="service://cas3")["ok"] is True)

    # 补撤：再级联撤 h1，应把 r1 收进来
    r = p.revoke_by_identity(ids[1], reason="cascade now")
    check("E3 再撤 h1 级联收编下游", r["revoked"] == 1, detail=str(r))
    check("E4 下游委托最终被废",
          not p.verify_credential(r1["cred"],
                                  audience="service://cas3")["ok"])

    # 未知标识
    r = p.revoke_by_identity("agent://cas3/none")
    check("E5 未知标识撤销被拒", not r["ok"])
    check("E5b 拒绝原因 unknown identity",
          r.get("reason") == "unknown identity")

    # 幂等：重复撤销同一标识，第二次实际撤销数为 0
    r = p.revoke_by_identity(ids[0], reason="again")
    check("E6 重复撤销幂等（实际撤销 0）", r["ok"] and r["revoked"] == 0,
          detail=str(r))


def test_cascade_persistence():
    print("\n=== [E7] 重启后级联能力保留 ===")
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "cascade.db")
    try:
        p1 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
        ids = ["agent://cp/h%d" % i for i in range(3)]
        for idn in ids:
            p1.register_identity(idn, org="cp")
        p1.configure_policy({"allowed_algs": [ALG_SM2],
                             "max_ttl_seconds": 3600})
        r0 = p1.issue_credential(ids[0], ids[1], "service://cp",
                                 ["c:read"], ttl=3600)
        r1 = p1.issue_delegation(ids[1], ids[2], "service://cp",
                                 ["c:read"], ttl=3600,
                                 parent_cred=r0["cred"])
        wire0, wire1 = r0["cred"], r1["cred"]
        p1._pers.close()
        del p1

        # 重启：血缘从审计日志重建，级联仍应生效
        p2 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
        check("E7 重启后重建凭证血缘",
              len(p2._cred_registry) >= 2,
              detail=str(len(p2._cred_registry)))
        r = p2.revoke_by_identity(ids[0], reason="after restart")
        check("E8 重启后级联撤销 2 张", r["revoked"] == 2, detail=str(r))
        check("E9 重启后下游委托被废",
              not p2.verify_credential(wire1,
                                       audience="service://cp")["ok"])
        check("E10 根凭证也被废",
              not p2.verify_credential(wire0,
                                       audience="service://cp")["ok"])
        p2._pers.close()
        del p2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_enable_semantics()
    test_enable_persistence()
    test_enable_http()
    test_cascade_revoke()
    test_cascade_from_middle()
    test_cascade_edge()
    test_cascade_persistence()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v11_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v11 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
