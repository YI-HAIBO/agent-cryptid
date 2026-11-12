# -*- coding: utf-8 -*-
"""
验证 agent-cryptid 论文的两大安全 headline 声明（与机器负载无关的纯正确性断言）：
  * E3 威胁驱动：--full 模式 14/14 攻击被拒（quick 仅 12/12）
  * E5 KAT 符合性：七原语 54/54 通过（quick 仅 SM2/SM3 + SHA3/SHAKE）
  * E4 混合失败关闭；E7 密码敏捷迁移（含 SLH-DSA 档）
只跑正确性实验，跳过 E1/E2/E6 的受负载污染的时序测量，秒级~分钟级即可完成。
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import eval_framework as ef

print("=" * 64)
print("agent-cryptid headline 声明验证（full 正确性模式）")
print("=" * 64)

# ---- E3 威胁驱动安全测评（full：含两条算法降级攻击）----
print("\n[E3] 威胁驱动安全测评 (full) ...")
e3 = ef.E3_threat_driven(quick=False)
n_rej = sum(1 for a in e3["attacks"] if a["rejected"])
print("  攻击总数: %d, 被拒: %d, all_rejected=%s" % (
    e3["n_attacks"], n_rej, e3["all_rejected"]))
for a in e3["attacks"]:
    flag = "REJECTED" if a["rejected"] else "ACCEPTED(!)"
    print("    [%s] %s | %s -> %s" % (flag, a["threat"], a["attack"], a["mechanism"]))
E3_OK = (e3["n_attacks"] == 14 and e3["all_rejected"])

# ---- E5 KAT 符合性（full：含 SM9/ML-DSA/SLH-DSA）----
print("\n[E5] 密码学原语 KAT 符合性 (full) ...")
e5 = ef.E5_kat(quick=False)
tot_pass = sum(r["pass"] for r in e5["kat"])
tot_total = sum(r["total"] for r in e5["kat"])
print("  原语数: %d, KAT 总数: %d, 通过: %d, all_ok=%s" % (
    len(e5["kat"]), tot_total, tot_pass, e5["all_ok"]))
for r in e5["kat"]:
    print("    %-22s %d/%d  ok=%s" % (r["primitive"], r["pass"], r["total"], r["ok"]))
E5_OK = (e5["all_ok"] and tot_total == 54 and tot_pass == 54)

# ---- E4 混合签名失败关闭 ----
print("\n[E4] 混合签名失败关闭 ...")
e4 = ef.E4_hybrid_failclosed()
print("  cases=%s fail_closed_ok=%s" % (e4["cases"], e4["fail_closed_ok"]))
E4_OK = e4["fail_closed_ok"]

# ---- E7 密码敏捷迁移（full：含 SLH-DSA 新档）----
print("\n[E7] 密码敏捷迁移 (full) ...")
e7 = ef.E7_crypto_agility(quick=False)
print("  backward_compat=%s strip_pq_blocked=%s alg_blocked=%s migration_security_ok=%s" % (
    e7["backward_compat"], e7["downgrade_strip_pq_blocked"],
    e7["downgrade_alg_blocked"], e7["migration_security_ok"]))
for c in e7["coexistence"]:
    print("    %-28s verify_ok=%s median=%.2fms" % (
        c["tier"], c["verify_ok"], c["verify_median_ms"]))
E7_OK = e7["migration_security_ok"]

print("\n" + "=" * 64)
print("结论")
print("=" * 64)
print("  E3  14/14 威胁被拒 : %s  (期望 14/14)" % ("PASS" if E3_OK else "FAIL"))
print("  E5  54/54 KAT      : %s  (期望 54/54)" % ("PASS" if E5_OK else "FAIL"))
print("  E4  混合失败关闭   : %s" % ("PASS" if E4_OK else "FAIL"))
print("  E7  迁移失败关闭   : %s" % ("PASS" if E7_OK else "FAIL"))
overall = E3_OK and E5_OK and E4_OK and E7_OK
print("  OVERALL           : %s" % ("PASS" if overall else "FAIL"))
sys.exit(0 if overall else 1)
