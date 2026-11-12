# -*- coding: utf-8 -*-
"""v2.9 测试：FR4-02 按标识批量撤销 + NFR-03 十跳委托链性能。

覆盖：
  [A] FR4-02：revoke_by_identity 废止某标识的全部凭证
  [B] FR4-02：HTTP 路由 /v1/revocations/by-identity
  [C] FR4-02：撤销后下游委托也被废止
  [D] NFR-03：十跳委托链验证时延 ≤100ms
  [E] NFR-03：二十跳委托链验证时延（基准）
  [F] FR4-05：撤销原因记录在审计中
  [G] 撤销原因透传到 audit entry
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from http_api import route as http_route, TenantPool
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


# ---------------------------------------------------------------------------
# [A] FR4-02：revoke_by_identity
# ---------------------------------------------------------------------------

def test_revoke_by_identity():
    print("\n=== [A] FR4-02 按标识批量撤销 ===")
    p = Platform(tenant="t1")
    p.register_identity("agent://root/iss", org="root")
    p.register_identity("agent://root/sub", org="root")
    p.register_identity("agent://root/sub2", org="root")
    p.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                         "max_ttl_seconds": 3600})

    # 签发 3 张凭证（同一 issuer）
    r1 = p.issue_credential("agent://root/iss", "agent://root/sub",
                            "service://a", ["a:read"], ttl=3600)
    r2 = p.issue_credential("agent://root/iss", "agent://root/sub2",
                            "service://a", ["a:read"], ttl=3600)
    check("A1 签发 3 张凭证", r1["ok"] and r2["ok"])

    # 全部校验通过
    v1 = p.verify_credential(r1["cred"], audience="service://a")
    v2 = p.verify_credential(r2["cred"], audience="service://a")
    check("A2 撤销前全部校验通过", v1["ok"] and v2["ok"])

    # 按标识批量撤销
    r3 = p.revoke_by_identity("agent://root/iss", reason="compromise")
    check("A3 revoke_by_identity 成功", r3["ok"])
    check("A4 撤销 2 张凭证", r3["revoked"] == 2)
    check("A5 返回 jti 列表", len(r3["jtis"]) == 2)

    # 撤销后全部校验失败
    v1b = p.verify_credential(r1["cred"], audience="service://a")
    v2b = p.verify_credential(r2["cred"], audience="service://a")
    check("A6 撤销后全部校验失败",
          not v1b["ok"] and not v2b["ok"])

    # 撤销原因记录在审计中（reason 在 event 子字典里）
    audit_records = p.audit_query(kind="revoke", limit=10)
    reasons = [r.get("event", {}).get("reason")
               for r in audit_records.get("records", [])]
    check("A7 撤销原因记录在审计中", "compromise" in reasons)


# ---------------------------------------------------------------------------
# [B] HTTP 路由
# ---------------------------------------------------------------------------

def test_http_revoke_by_identity():
    print("\n=== [B] HTTP /v1/revocations/by-identity ===")
    pool = TenantPool()
    plat = pool.get("t1")
    plat.register_identity("agent://h/iss", org="h")
    plat.register_identity("agent://h/sub", org="h")
    plat.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                            "max_ttl_seconds": 3600})

    r1 = http_route(pool, "POST", "/v1/credentials", None,
                     {"issuer_idn": "agent://h/iss",
                      "subject_idn": "agent://h/sub",
                      "audience": "service://h",
                      "scope": ["h:read"],
                      "ttl": 3600}, tenant="t1")
    check("B1 HTTP 签发凭证", r1[0] == 200 and r1[1]["ok"])

    r2 = http_route(pool, "POST", "/v1/revocations/by-identity", None,
                     {"idn": "agent://h/iss",
                      "reason": "test-revoke"}, tenant="t1")
    check("B2 HTTP 按标识撤销成功", r2[0] == 200 and r2[1]["ok"])
    check("B3 撤销数量为 1", r2[1]["revoked"] == 1)

    # 校验失败
    r3 = http_route(pool, "POST", "/v1/credentials/verify", None,
                     {"cred": r1[1]["cred"], "audience": "service://h"},
                     tenant="t1")
    check("B4 撤销后 HTTP 校验失败", r3[0] == 200 and not r3[1]["ok"])

    # 未知标识
    r4 = http_route(pool, "POST", "/v1/revocations/by-identity", None,
                     {"idn": "agent://unknown/iss"}, tenant="t1")
    check("B5 未知标识撤销返回 400", r4[0] == 400)


# ---------------------------------------------------------------------------
# [C] 撤销后下游委托也被废止
# ---------------------------------------------------------------------------

def test_revoke_cascade():
    print("\n=== [C] 撤销下游委托级联 ===")
    p = Platform(tenant="t1")
    p.register_identity("agent://c/root", org="c")
    p.register_identity("agent://c/a1", org="c")
    p.register_identity("agent://c/a2", org="c")
    p.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                         "max_ttl_seconds": 3600})

    # root → a1（根凭证）
    r1 = p.issue_credential("agent://c/root", "agent://c/a1",
                            "service://c", ["c:read"], ttl=3600)
    # a1 → a2（委托）：出示 a1 持有的父凭证 r1，触发 FR3-02/FR3-05 收敛
    r2 = p.issue_delegation("agent://c/a1", "agent://c/a2",
                            "service://c", ["c:read"], ttl=3600,
                            parent_cred=r1["cred"])

    # 撤销 root 的凭证 → 沿委托图级联，a2 的委托一并失效（v2.10）
    r3 = p.revoke_by_identity("agent://c/root", reason="root revoked")
    check("C1 root 撤销并级联 2 张凭证", r3["revoked"] == 2,
          detail=str(r3))

    v1 = p.verify_credential(r1["cred"], audience="service://c")
    v2 = p.verify_credential(r2["cred"], audience="service://c")
    check("C2 根凭证校验失败", not v1["ok"])
    # v2.10：FR4-02 要求「及其下游委托」，r2 是 r1 的子凭证，一并废止
    check("C3 下游委托被级联废止", not v2["ok"])


# ---------------------------------------------------------------------------
# [D] NFR-03：十跳委托链验证时延
# ---------------------------------------------------------------------------

def test_chain_perf():
    print("\n=== [D] NFR-03 委托链验证性能 ===")
    p = Platform(tenant="perf")
    ids = ["agent://perf/hop%d" % i for i in range(11)]
    for idn in ids:
        p.register_identity(idn, org="perf")
    p.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                         "max_ttl_seconds": 3600})

    # 构建 10 跳委托链（每跳出示父凭证，保证 scope/exp 收敛）
    chain = []
    r = p.issue_credential(ids[0], ids[1], "service://perf",
                           ["perf:read"], ttl=3600)
    chain.append(r["cred"])
    prev_cred = r["cred"]
    for i in range(1, 10):
        r = p.issue_delegation(ids[i], ids[i + 1], "service://perf",
                               ["perf:read"], ttl=3600,
                               parent_cred=prev_cred)
        chain.append(r["cred"])
        prev_cred = r["cred"]

    # 验证 10 跳链
    t0 = time.time()
    r = p.verify_delegation_chain(chain, "service://perf", ["perf:read"])
    t10 = (time.time() - t0) * 1000
    check("D1 10 跳委托链验证通过", r["ok"])
    check("D2 10 跳验证 ≤100ms (NFR-03)", t10 <= 100,
          detail="%.1fms" % t10)

    # 20 跳基准
    ids20 = ["agent://perf20/hop%d" % i for i in range(21)]
    for idn in ids20:
        p.register_identity(idn, org="perf20")
    chain20 = []
    r = p.issue_credential(ids20[0], ids20[1], "service://perf20",
                           ["perf20:read"], ttl=3600)
    chain20.append(r["cred"])
    prev20 = r["cred"]
    for i in range(1, 20):
        r = p.issue_delegation(ids20[i], ids20[i + 1], "service://perf20",
                               ["perf20:read"], ttl=3600,
                               parent_cred=prev20)
        chain20.append(r["cred"])
        prev20 = r["cred"]
    t0 = time.time()
    r = p.verify_delegation_chain(chain20, "service://perf20", ["perf20:read"])
    t20 = (time.time() - t0) * 1000
    check("D3 20 跳委托链验证通过", r["ok"])
    check("D4 20 跳验证基准", t20 > 0, detail="%.1fms" % t20)


# ---------------------------------------------------------------------------
# [E] 撤销原因透传
# ---------------------------------------------------------------------------

def test_revoke_reason_propagation():
    print("\n=== [E] 撤销原因透传 ===")
    p = Platform(tenant="t1")
    p.register_identity("agent://r/iss", org="r")
    p.register_identity("agent://r/sub", org="r")
    p.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                         "max_ttl_seconds": 3600})
    r = p.issue_credential("agent://r/iss", "agent://r/sub",
                           "service://r", ["r:read"], ttl=3600)
    p.revoke(r["jti"], reason="key_compromise_detected")

    audit = p.audit_query(kind="revoke", limit=10)
    records = audit.get("records", [])
    reasons = [rec.get("event", {}).get("reason") for rec in records]
    check("E1 撤销原因 key_compromise_detected 在审计中",
          "key_compromise_detected" in reasons)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_revoke_by_identity()
    test_http_revoke_by_identity()
    test_revoke_cascade()
    test_chain_perf()
    test_revoke_reason_propagation()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v9_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v9 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())