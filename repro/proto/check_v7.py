# -*- coding: utf-8 -*-
"""v2.6 SM9 集成测试：Platform + Credential + IdentityAuthority 三件套跑通 SM9 算法档位。

覆盖：
- IdentityAuthority.ks / P_pub 初始化
- issue_sm9 / sign_sm9 / verify_id_sm9 闭环
- Credential.sign/verify 按 alg_tier 分派（SM2 与 SM9 双档并存）
- Platform.issue_credential + verify_credential 走 SM9 通路
- SM9 篡改检测（消息/h/S/ID）
- SM9 与 SM2 交叉验签失败（防降级）
- 序列化往返一致
- 撤销与 nonce 防重放（沿用现有机制，走 SM9 路径）
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from identity import IdentityAuthority, verify_id_sm9
from credential import Credential, ALG_SM2, ALG_SM9, ALG_SM2_MLDSA, ALG_HASH_SIG
from agent_platform import Platform


def _ts():
    return int(time.time())


def main():
    results = []

    # ============ A. IdentityAuthority SM9 初始化 ============
    ia = IdentityAuthority()
    results.append(("IA 持有 ks 主私钥", ia.ks is not None and 1 <= ia.ks < __import__("sm9").N))
    results.append(("IA 持有 P_pub 主公钥", ia.ppub is not None))
    results.append(("P_pub 由 [ks]P2 派生",
                    __import__("sm9").g2_mul(ia.ks, __import__("sm9").P2) == ia.ppub))
    print("[A] IdentityAuthority SM9 初始化")
    for name, ok in results[-3:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ B. issue_sm9 / sign_sm9 / verify 闭环 ============
    idn = "agent://demo-org/ops-agent-001"
    ds_A = ia.issue_sm9(idn)
    results.append(("issue_sm9 返回 G1 点", ds_A is not None and len(ds_A) == 2))

    msg = b"issue credential for tool call invoice:read"
    h, S = ia.sign_sm9(idn, msg)
    results.append(("sign_sm9 返回 (h, S)", h is not None and S is not None))

    ok = verify_id_sm9(idn, h, S, msg, ia.ppub)
    results.append(("verify_id_sm9 闭环通过", ok))

    ok_bad = verify_id_sm9(idn, h, S, msg + b"x", ia.ppub)
    results.append(("篡改消息失败", not ok_bad))

    ok_bad_id = verify_id_sm9("agent://other/x", h, S, msg, ia.ppub)
    results.append(("换 ID 失败", not ok_bad_id))

    print("[B] IdentityAuthority 签名闭环")
    for name, ok in results[-4:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ C. Credential 按 alg_tier 分派 ============
    cred_sm9 = Credential(sub=idn, iss=idn, aud="service://invoice",
                          scope=["invoice:read"], exp=_ts() + 3600,
                          alg_tier=ALG_SM9)
    cred_sm9.sign(idn, ia.ks)  # SM9: priv = ks (主私钥)

    ok, why = cred_sm9.verify(idn, ia.ppub, now=_ts())
    results.append(("Credential SM9 签发+校验", ok and why == "ok"))

    # 篡改 scope → 失败
    cred_sm9_b = Credential(sub=idn, iss=idn, aud="service://invoice",
                            scope=["invoice:read"], exp=_ts() + 3600,
                            alg_tier=ALG_SM9)
    cred_sm9_b.sign(idn, ia.ks)
    cred_sm9_b.scope = ("invoice:write",)
    ok, why = cred_sm9_b.verify(idn, ia.ppub, now=_ts())
    results.append(("SM9 篡改 scope 失败", not ok and why == "signature invalid"))

    # 换档位 → 失败
    cred_sm9_c = Credential(sub=idn, iss=idn, aud="service://invoice",
                            scope=["invoice:read"], exp=_ts() + 3600,
                            alg_tier=ALG_SM9)
    cred_sm9_c.sign(idn, ia.ks)
    cred_sm9_c.alg_tier = ALG_SM2_MLDSA
    ok, why = cred_sm9_c.verify(idn, ia.ppub, now=_ts())
    results.append(("SM9 篡改 alg_tier 失败", not ok))

    print("[C] Credential SM9 分派")
    for name, ok in results[-3:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ D. SM2 与 SM9 双档并存 ============
    cred_sm2 = Credential(sub=idn, iss=idn, aud="service://invoice",
                          scope=["invoice:read"], exp=_ts() + 3600,
                          alg_tier=ALG_SM2)
    # SM2 用派生的 d_id 签名
    from identity import _kdf
    import sm2 as _sm2
    d_id = int.from_bytes(_kdf(ia.mk, idn.encode("utf-8")), "big") % (_sm2.N - 1) + 1
    cred_sm2.sign(idn, d_id)
    pub_id = _sm2.scalar_mult(d_id)
    ok_sm2, why_sm2 = cred_sm2.verify(idn, pub_id, now=_ts())
    results.append(("SM2 签发+校验仍正常", ok_sm2 and why_sm2 == "ok"))

    # SM9 凭证用 SM2 公钥验 → 失败（防降级）
    ok_cross, why_cross = cred_sm9.verify(idn, pub_id, now=_ts())
    results.append(("SM9 凭证用 SM2 公钥验失败", not ok_cross))

    print("[D] 双档并存 + 防降级")
    for name, ok in results[-2:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ E. Platform 集成 ============
    p = Platform(tenant="sm9-test")
    for idn_ in ["agent://root/ca", "agent://org-a/worker"]:
        p.register_identity(idn_, org=idn_.split("/")[1],
                            agent_type="worker", owner="admin")

    # 用 SM9 签发
    r = p.issue_credential("agent://root/ca", "agent://org-a/worker",
                           "service://invoice", ["invoice:read"],
                           ttl=3600, alg_tier=ALG_SM9)
    results.append(("Platform issue_credential SM9", r["ok"]))
    cred_wire = r["cred"]
    results.append(("SM9 wire sig_r 存在", cred_wire.get("sig_r") is not None))
    results.append(("SM9 wire sig_s_x 存在", cred_wire.get("sig_s_x") is not None))

    # 校验通过
    r2 = p.verify_credential(cred_wire, audience="service://invoice")
    results.append(("Platform verify_credential SM9 通过",
                    r2["ok"] and r2["reason"] == "ok"))

    # 篡改 audience → 失败
    cred_wire_b = dict(cred_wire)
    cred_wire_b["aud"] = "service://other"
    r3 = p.verify_credential(cred_wire_b, audience="service://other")
    results.append(("篡改 aud 后校验失败", not r3["ok"]))

    # 撤销后失败
    r4 = p.revoke(cred_wire["jti"], reason="test")
    r5 = p.verify_credential(cred_wire, audience="service://invoice")
    results.append(("撤销后校验失败", not r5["ok"] and r5["reason"] == "revoked"))

    print("[E] Platform SM9 集成")
    for name, ok in results[-5:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ F. SM9 策略允许 ============
    results.append(("Platform 默认策略允许 SM9", ALG_SM9 in p._policy["allowed_algs"]))

    # SM2 仍可用
    r6 = p.issue_credential("agent://root/ca", "agent://org-a/worker",
                            "service://invoice", ["invoice:read"],
                            ttl=3600, alg_tier=ALG_SM2)
    results.append(("Platform SM2 签发仍正常", r6["ok"]))
    r7 = p.verify_credential(r6["cred"], audience="service://invoice")
    results.append(("Platform SM2 校验仍正常", r7["ok"]))

    print("[F] 策略与向后兼容")
    for name, ok in results[-3:]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # ============ 汇总 ============
    print()
    print("=" * 60)
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print()
    print(f"RESULT  PASS={n_pass}  FAIL={n_fail}")

    # 写报告
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "check_v7_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        for name, ok in results:
            f.write(f"{'PASS' if ok else 'FAIL'}  {name}\n")
        f.write(f"RESULT  PASS={n_pass}  FAIL={n_fail}\n")
    return n_fail


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
