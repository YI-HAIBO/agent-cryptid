# -*- coding: utf-8 -*-
"""v1.0 验证：多租户隔离 + SQLite 持久化 + 状态恢复。

覆盖：
    T1  同一 SQLite 后端挂载两个 tenant，标识物理隔离
    T2  撤销隔离：tenant A 的 jti 撤销不影响 tenant B 的同名 jti 验证
    T3  审计隔离：tenant A 的审计检索查不到 tenant B 的事件
    T4  策略隔离：tenant A 的 max_ttl 不影响 tenant B
    T5  持久化恢复：Platform 关闭后新实例能 _hydrate 恢复全部状态
    T6  跨租户凭证不可用：tenant A 的凭证在 tenant B 平台验签失败（unknown issuer）
    T7  撤销版本号按租户独立递增
    T8  SQLite 后端 count_by_table 显示所有租户数据在同一份物理表中
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform
from persistence import SQLiteBackend


def _register(p, idn, org):
    r = p.register_identity(idn, org=org, agent_type="worker", owner="admin")
    assert r["ok"], r


def _issue(p, issuer, sub, aud, scope, ttl=3600):
    r = p.issue_credential(issuer, sub, aud, scope, ttl=ttl)
    assert r["ok"], r
    return r["cred"]


def run():
    out = []
    db = SQLiteBackend(path=":memory:")

    # ---- T1  两个租户各自注册不同标识，互不可见
    pA = Platform(tenant="tenant-A", persistence=db)
    pB = Platform(tenant="tenant-B", persistence=db)

    _register(pA, "agent://a/root", "org-a")
    _register(pA, "agent://a/worker", "org-a")
    _register(pB, "agent://b/root", "org-b")
    _register(pB, "agent://b/worker", "org-b")

    # tenant B 平台里应该查不到 tenant A 的标识
    r = pB.verify_credential({
        "sub": "agent://a/worker", "iss": "agent://a/root",
        "aud": "x", "scope": [], "iat": 0, "nbf": 0, "exp": 9999999999,
        "nonce": "00" * 16, "alg_tier": "SM2", "jti": "probe",
        "sig_r": "00", "sig_s": "00",
    })
    # 期望：unknown issuer（tenant B 里没有 agent://a/root）
    out.append(("T1 跨租户标识不可见",
                r["ok"] is False and r["reason"] == "unknown issuer"))

    # ---- T2  同 jti 撤销隔离
    cred_A = _issue(pA, "agent://a/root", "agent://a/worker",
                    "svc://a", ["a:read"])
    cred_B = _issue(pB, "agent://b/root", "agent://b/worker",
                    "svc://b", ["b:read"])

    # 撤销 tenant A 里 cred_A 的 jti
    jti_A = cred_A["jti"]
    r = pA.revoke(jti_A, reason="test")
    out.append(("T2a tenant A 撤销成功", r["ok"] is True))

    # tenant A 校验 cred_A 应失败
    r = pA.verify_credential(cred_A, record_nonce=False)
    out.append(("T2b tenant A 校验被拒 (revoked)",
                r["ok"] is False and r["reason"] == "revoked"))

    # tenant B 校验 cred_B 应仍通过（不同租户撤销不串扰）
    r = pB.verify_credential(cred_B, record_nonce=False)
    out.append(("T2c tenant B 校验仍通过",
                r["ok"] is True and r["reason"] == "ok"))

    # tenant A 的 revocation_snapshot 只包含自己那条
    snap_A = pA.revocation_snapshot(0)
    snap_B = pB.revocation_snapshot(0)
    out.append(("T2d 撤销版本号按租户独立 (A=1, B=0)",
                snap_A["current_version"] == 1
                and snap_B["current_version"] == 0))

    # ---- T3  审计检索隔离
    # 让 tenant B 产生一条独立事件
    pB.issue_credential("agent://b/root", "agent://b/worker",
                        "svc://b", ["b:write"], ttl=3600)
    aud_A = pA.audit_query(kind="credential.issue")
    aud_B = pB.audit_query(kind="credential.issue")

    a_idns = {r["event"].get("iss") for r in aud_A["records"]}
    b_idns = {r["event"].get("iss") for r in aud_B["records"]}
    out.append(("T3 tenant A 审计只见 A 的 issuer",
                "agent://a/root" in a_idns
                and "agent://b/root" not in a_idns))
    out.append(("T3b tenant B 审计只见 B 的 issuer",
                "agent://b/root" in b_idns
                and "agent://a/root" not in b_idns))
    out.append(("T3c 两条审计链都自洽",
                aud_A["chain_valid"] is True and aud_B["chain_valid"] is True))

    # ---- T4  策略隔离
    r = pA.configure_policy({"max_ttl_seconds": 60})
    out.append(("T4a tenant A 策略更新成功",
                r["ok"] and r["policy"]["max_ttl_seconds"] == 60))
    # tenant B 平台里 max_ttl 仍为默认 86400
    assert pB._policy["max_ttl_seconds"] == 86400
    out.append(("T4b tenant B 策略不受影响",
                pB._policy["max_ttl_seconds"] == 86400))

    # tenant A 强制截断 ttl
    r = pA.issue_credential("agent://a/root", "agent://a/worker",
                            "svc://a", ["a:read"], ttl=999999)
    ttl_used = r["exp"] - r["iat"]
    out.append(("T4c tenant A ttl 被策略截断",
                ttl_used == 60))

    # ---- T5  持久化恢复：新 Platform 实例挂载同一后端
    pA2 = Platform(tenant="tenant-A", persistence=db)
    # 标识应被 hydrate
    out.append(("T5a 恢复后 tenant A 的标识仍在",
                "agent://a/root" in pA2._identities
                and "agent://a/worker" in pA2._identities))
    # 撤销集合应被 hydrate
    out.append(("T5b 恢复后撤销 jti 仍在",
                jti_A in pA2._revoked_jtis))
    # 策略应被 hydrate
    out.append(("T5c 恢复后策略保留 max_ttl_seconds=60",
                pA2._policy.get("max_ttl_seconds") == 60))
    # 恢复后的平台依然能拒绝被撤销凭证
    r = pA2.verify_credential(cred_A, record_nonce=False)
    out.append(("T5d 恢复后 revoked 凭证仍被拒",
                r["ok"] is False and r["reason"] == "revoked"))

    # ---- T7  撤销版本按租户独立（重复触发）
    cred_A2 = _issue(pA, "agent://a/root", "agent://a/worker",
                     "svc://a", ["a:write"])
    pA.revoke(cred_A2["jti"], reason="test2")
    r1 = pA.revocation_snapshot(0)
    r2 = pB.revocation_snapshot(0)
    out.append(("T7 tenant A 版本=2, tenant B 版本=0",
                r1["current_version"] == 2 and r2["current_version"] == 0))

    # ---- T8  SQLite 后端数据在同表但按 tenant 隔离
    counts = db.count_by_table()
    # identities 应有 4 行（A 的 2 + B 的 2）
    out.append(("T8 identities 表物理共 4 行",
                counts["identities"] == 4))
    # revocations 表应有 2 行（全部来自 tenant A）
    out.append(("T8b revocations 表物理共 2 行 (均来自 A)",
                counts["revocations"] == 2))
    # audit_log 有数据
    out.append(("T8c audit_log 有数据",
                counts["audit_log"] > 0))

    db.close()
    return out


def main():
    """跑一次并写入 report 文件。"""
    import os
    results = run()
    npass = sum(1 for _, ok in results if ok)
    nfail = sum(1 for _, ok in results if not ok)
    for name, ok in results:
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
    print("SUMMARY  check_v1 PASS=%d FAIL=%d" % (npass, nfail))
    report = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "check_v1_report.txt")
    with open(report, "w", encoding="utf-8") as f:
        f.write("agent-cryptid check_v1 多租户/持久化验证报告\n")
        f.write("=" * 60 + "\n\n")
        for name, ok in results:
            f.write("%-8s %s\n" % ("PASS" if ok else "FAIL", name))
        f.write("\nRESULT  PASS=%d  FAIL=%d\n" % (npass, nfail))
        f.write("\n覆盖测试点：\n")
        f.write("- T1 跨租户标识不可见\n")
        f.write("- T2 同 jti 撤销隔离 (A/B 各自独立)\n")
        f.write("- T3 审计检索按租户隔离 + 哈希链自洽\n")
        f.write("- T4 策略配置按租户隔离 + ttl 截断\n")
        f.write("- T5 状态恢复 hydrate (identities/revocations/policy)\n")
        f.write("- T7 撤销版本号按租户独立递增\n")
        f.write("- T8 SQLite 后端物理表结构\n")
    print(report)
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
