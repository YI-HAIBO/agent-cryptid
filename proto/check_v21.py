# -*- coding: utf-8 -*-
"""v2.16 抗量子档位专项：SM2+ML-DSA 混合签名与 SLH-DSA hash-signature。

补齐《产品需求文档》里"密码敏捷（三档）"此前只有防降级测试、
没有任何真实算法实现的部分——本轮把两档真实落地：

    sm2-ml-dsa      SM2 + ML-DSA（FIPS 204 / Dilithium）混合签名。
                    两个分量各自独立、失败关闭（fail-closed）：
                    任一分量校验失败即整体拒绝。这是迁移期的安全底座——
                    经典攻击者能破 SM2 时 ML-DSA 仍然挡住，
                    量子攻击者能破 ML-DSA 时 SM2 仍然挡住。
    hash-signature  SLH-DSA（FIPS 205 / SPHINCS+）。
                    纯哈希、无格/无离散对数假设，年尺度长期审计凭证用。

实现说明（重要，别改坏）：
    零第三方依赖，全部纯 Python：
        shake.py    Keccak-f[1600] + SHA3-256/512 + SHAKE128/256（FIPS 202）
        mldsa.py    NTT + CBD 采样 + SampleNTT/InBall + 分解 + 拒绝采样
        slhdsa.py   WOTS+ 一次性签名 + MERKLE 超树 + ADRS
    参数集：
        mldsa.py 用 ML-DSA-65 安全参数，公钥采用 FIPS 204 标准 t1+hint 紧凑格式
                  （pk=(ρ,t1)，签名含 hint h，验签用 UseHint 重建 w1），
                  享有完整的可证明安全归约。
        slhdsa.py 用缩减演示参数集（n=16, h=15, d=3, a=10, k=12, lg_w=4），
                  不是完整 FIPS 205 参数集；纯 Python 下完整参数集
                  （h=63）签名耗时不可接受。缩减集只用于功能验证，
                  生产须换完整参数集或改用 C/汇编实现。
    密钥派生：
        PQ 密钥由 mk[kv] 经 KDF 确定性派生，域分隔保证同一标识的
        ML-DSA 与 SLH-DSA 种子互不相关、且与 SM2 派生密钥互不相关。
        惰性派生 + 进程内缓存：SLH-DSA 公钥树构造较慢（约 20 秒），
        绝不放在标识注册路径上，只在真正按 PQ 档位签发/校验时派生一次。
        私钥可确定性重建，因此无需落盘。

    防降级：alg_tier 进入签名覆盖，且 verify 先做签名结构一致性检查
        ——每个档位的签名结构（SM2 二元整数组 / SM9 二元组 / 混合
        ((r,s), dict) / hash-signature dict）都不兼容，篡改 alg_tier
        必然结构不匹配而拒绝。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def self_check():
    out = []
    from agent_platform import (
        Platform, ALG_SM2, ALG_SM9, ALG_SM2_MLDSA, ALG_HASH_SIG,
        _MLD_AVAILABLE, _SLH_AVAILABLE,
        _cred_to_wire, _cred_from_wire,
    )

    print("    [环境] ML-DSA=%s  SLH-DSA=%s" % (_MLD_AVAILABLE, _SLH_AVAILABLE))

    p = Platform(tenant="pq")
    for idn in ("agent://pq/root", "agent://pq/mid", "agent://pq/leaf"):
        p.register_identity(idn, org="pq")

    # ==================================================================
    # [A] 混合档位 SM2 + ML-DSA
    # ==================================================================
    if _MLD_AVAILABLE:
        t0 = time.perf_counter()
        r = p.issue_credential(
            issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
            audience="svc://pq", scope=["read"], ttl=3600,
            alg_tier=ALG_SM2_MLDSA)
        mld_issue_ms = (time.perf_counter() - t0) * 1000
        out.append(("A1 混合档位签发成功", r.get("ok") is True))
        out.append(("A2 混合档位 alg_tier 正确",
                    r.get("alg_tier") == ALG_SM2_MLDSA))

        v = p.verify_credential(r["cred"], audience="svc://pq")
        out.append(("A3 混合档位本地校验通过", v.get("ok") is True))
        out.append(("A4 混合档位校验原因为 ok", v.get("reason") == "ok"))

        # wire 往返
        w = _cred_to_wire(_cred_from_wire(r["cred"]))
        v2 = p.verify_credential(w, audience="svc://pq", record_nonce=False)
        out.append(("A5 混合档位 wire 往返后校验通过", v2.get("ok") is True))

        # 篡改 scope
        tam = dict(r["cred"])
        tam["scope"] = ["write"]
        vt = p.verify_credential(tam, audience="svc://pq", record_nonce=False)
        out.append(("A6 混合档位篡改 scope 失败", vt.get("ok") is False))

        # 篡改 alg_tier（降级到纯 SM2）
        tam2 = dict(r["cred"])
        tam2["alg_tier"] = ALG_SM2
        vt2 = p.verify_credential(tam2, audience="svc://pq", record_nonce=False)
        out.append(("A7 混合档位篡改 alg_tier 失败", vt2.get("ok") is False))

        # 篡改 SM2 分量（混合签名的一半被换掉）
        tam3 = dict(r["cred"])
        tam3["sig_r"] = ("00" * 32) if tam3["sig_r"][:2] != "00" else "01" * 32
        vt3 = p.verify_credential(tam3, audience="svc://pq", record_nonce=False)
        out.append(("A8 混合档位篡改 SM2 分量失败", vt3.get("ok") is False))

        # 篡改 ML-DSA 分量（混合签名的另一半被换掉）
        tam4 = dict(r["cred"])
        tam4["pq_sig"] = tam4["pq_sig"][::-1]
        vt4 = p.verify_credential(tam4, audience="svc://pq", record_nonce=False)
        out.append(("A9 混合档位篡改 ML-DSA 分量失败", vt4.get("ok") is False))

        # 签名缺失失败关闭
        tam5 = dict(r["cred"])
        tam5.pop("pq_sig")
        vt5 = p.verify_credential(tam5, audience="svc://pq", record_nonce=False)
        out.append(("A10 混合档位缺 PQ 分量失败关闭", vt5.get("ok") is False))

        print("    [实测] 混合档位签发 %.1fms（含 ML-DSA 拒绝采样，波动大）"
              % mld_issue_ms)

        # ==================================================================
        # [C] 混合档位委托链
        # ==================================================================
        r0 = p.issue_credential(
            issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
            audience="svc://chain", scope=["read", "write"], ttl=7200,
            alg_tier=ALG_SM2_MLDSA)
        chain = [r0["cred"]]
        rd = p.issue_delegation(
            delegator_idn="agent://pq/mid", delegatee_idn="agent://pq/leaf",
            audience="svc://chain", scope=["read"], ttl=3600,
            alg_tier=ALG_SM2_MLDSA, parent_cred=r0["cred"])
        out.append(("C1 混合档位委托签发成功", rd.get("ok") is True))
        if rd.get("ok"):
            chain.append(rd["cred"])
        vc = p.verify_delegation_chain(chain, "svc://chain", ["read"])
        out.append(("C2 混合档位两跳链验证通过", vc.get("ok") is True))

        # 委托链中子级 scope 越权（收敛校验仍生效）
        rd_esc = p.issue_delegation(
            delegator_idn="agent://pq/mid", delegatee_idn="agent://pq/leaf",
            audience="svc://chain", scope=["read", "admin"], ttl=3600,
            alg_tier=ALG_SM2_MLDSA, parent_cred=r0["cred"])
        out.append(("C3 混合档位委托链 scope 收敛仍生效",
                    rd_esc.get("ok") is False))

    # ==================================================================
    # [B] hash-signature SLH-DSA
    # ==================================================================
    if _SLH_AVAILABLE:
        t0 = time.perf_counter()
        rs = p.issue_credential(
            issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
            audience="svc://pq", scope=["read"], ttl=3600,
            alg_tier=ALG_HASH_SIG)
        slh_issue_ms = (time.perf_counter() - t0) * 1000
        out.append(("B1 hash-signature 签发成功", rs.get("ok") is True))
        out.append(("B2 hash-signature alg_tier 正确",
                    rs.get("alg_tier") == ALG_HASH_SIG))

        vs = p.verify_credential(rs["cred"], audience="svc://pq")
        out.append(("B3 hash-signature 本地校验通过", vs.get("ok") is True))

        ws = _cred_to_wire(_cred_from_wire(rs["cred"]))
        vs2 = p.verify_credential(ws, audience="svc://pq", record_nonce=False)
        out.append(("B4 hash-signature wire 往返后校验通过",
                    vs2.get("ok") is True))

        # 篡改 scope
        tams = dict(rs["cred"])
        tams["scope"] = ["write"]
        vts = p.verify_credential(tams, audience="svc://pq",
                                  record_nonce=False)
        out.append(("B5 hash-signature 篡改 scope 失败",
                    vts.get("ok") is False))

        # 篡改 alg_tier（伪装成混合档位）
        tams2 = dict(rs["cred"])
        tams2["alg_tier"] = ALG_SM2_MLDSA
        vts2 = p.verify_credential(tams2, audience="svc://pq",
                                   record_nonce=False)
        out.append(("B6 hash-signature 篡改 alg_tier 失败",
                    vts2.get("ok") is False))

        # 篡改签名分量（WOTS 分量之一换零）
        tams3 = dict(rs["cred"])
        tams3["pq_sig"] = tams3["pq_sig"][::-1]
        vts3 = p.verify_credential(tams3, audience="svc://pq",
                                   record_nonce=False)
        out.append(("B7 hash-signature 篡改签名分量失败",
                    vts3.get("ok") is False))

        # 签名缺失失败关闭
        tams4 = dict(rs["cred"])
        tams4.pop("pq_sig")
        vts4 = p.verify_credential(tams4, audience="svc://pq",
                                   record_nonce=False)
        out.append(("B8 hash-signature 缺签名失败关闭",
                    vts4.get("ok") is False))

        print("    [实测] hash-signature 签发 %.1fms" % slh_issue_ms)

        # 校验时延（多次取中位）
        lat = []
        for _ in range(5):
            t0 = time.perf_counter()
            p.verify_credential(rs["cred"], audience="svc://pq",
                                record_nonce=False)
            lat.append((time.perf_counter() - t0) * 1000)
        print("    [实测] hash-signature 校验中位 %.2fms（纯哈希实现，"
              "远慢于 SM2 的 5ms）" % sorted(lat)[len(lat) // 2])

    # ==================================================================
    # [D] PQ 密钥确定性派生（清缓存后重建必须得到同一密钥）
    # ==================================================================
    if _MLD_AVAILABLE:
        kv = p._identities["agent://pq/root"].get("key_version", 0)
        before = p._pq_pk("agent://pq/root", kv, "mldsa")
        p._pq_cache.clear()
        after = p._pq_pk("agent://pq/root", kv, "mldsa")
        out.append(("D1 PQ 密钥清缓存后确定性重建", before == after))

    if _MLD_AVAILABLE and _SLH_AVAILABLE:
        kv = 0
        k1 = p._pq_seed("agent://pq/root", kv, b"mldsa")
        k2 = p._pq_seed("agent://pq/root", kv, b"slhdsa")
        k3 = p._pq_seed("agent://pq/root", kv, b"other")
        out.append(("D2 PQ 各档种子域分隔互不相关",
                    len({k1, k2, k3}) == 3))

    # ==================================================================
    # [E] 策略管控：未放开 PQ 档位时拒绝签发
    # ==================================================================
    p_strict = Platform(tenant="pq-strict",
                        policy={
                            "default_scope": [],
                            "max_ttl_seconds": 86400,
                            "allowed_algs": [ALG_SM2, ALG_SM9],
                            "max_delegation_depth": None,
                            "tenant": "pq-strict",
                        })
    p_strict.register_identity("agent://s/root", org="s")
    p_strict.register_identity("agent://s/worker", org="s")
    rr = p_strict.issue_credential(
        issuer_idn="agent://s/root", subject_idn="agent://s/worker",
        audience="svc://s", scope=["read"], ttl=600,
        alg_tier=ALG_SM2_MLDSA)
    out.append(("E1 策略未放开时拒绝 PQ 档位", rr.get("ok") is False))
    out.append(("E2 策略拒绝原因为 alg_tier not allowed",
                rr.get("reason") == "alg_tier not allowed"))

    # ==================================================================
    # [F] 四档并存与交叉验证
    # ==================================================================
    tiers_ok = []
    for tier in (ALG_SM2, ALG_SM9):
        ri = p.issue_credential(
            issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
            audience="svc://mix", scope=["read"], ttl=600, alg_tier=tier)
        vi = p.verify_credential(ri["cred"], audience="svc://mix")
        tiers_ok.append(vi.get("ok") is True)
    out.append(("F1 经典档位（SM2/SM9）回归不受影响",
                all(tiers_ok) and len(tiers_ok) == 2))

    # SM2 签名不得被采信为抗量子档位
    r_sm2 = p.issue_credential(
        issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
        audience="svc://cross", scope=["read"], ttl=600, alg_tier=ALG_SM2)
    for fake in (ALG_SM2_MLDSA, ALG_HASH_SIG):
        tam_x = dict(r_sm2["cred"])
        tam_x["alg_tier"] = fake
        vx = p.verify_credential(tam_x, audience="svc://cross",
                                 record_nonce=False)
        out.append(("F2 SM2 签名伪装成 %s 失败" % fake,
                    vx.get("ok") is False))

    # 撤销 + 撤销证明对 PQ 档位同样生效
    if _SLH_AVAILABLE:
        r_rev = p.issue_credential(
            issuer_idn="agent://pq/root", subject_idn="agent://pq/mid",
            audience="svc://rev", scope=["read"], ttl=600,
            alg_tier=ALG_HASH_SIG)
        p.revoke(r_rev["jti"], reason="pq revocation")
        vr = p.verify_credential(r_rev["cred"], audience="svc://rev",
                                 record_nonce=False)
        out.append(("F3 PQ 档位撤销后校验失败", vr.get("ok") is False))

    # ==================================================================
    # 汇总
    # ==================================================================
    pass_count = sum(1 for _, ok in out if ok)
    fail_count = sum(1 for _, ok in out if not ok)
    print("\n" + "=" * 60)
    print("v2.16 抗量子档位：SM2+ML-DSA 混合 / SLH-DSA hash-signature")
    print("=" * 60)
    for name, ok in out:
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
    print("-" * 60)
    print("RESULT  PASS=%d  FAIL=%d" % (pass_count, fail_count))
    print("=" * 60)

    report_path = os.path.join(
        os.path.dirname(__file__), "check_v21_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        for name, ok in out:
            f.write("%-8s %s\n" % ("PASS" if ok else "FAIL", name))
        f.write("\nRESULT  PASS=%d  FAIL=%d\n" % (pass_count, fail_count))

    return out


if __name__ == "__main__":
    self_check()
