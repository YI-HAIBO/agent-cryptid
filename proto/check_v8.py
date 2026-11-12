# -*- coding: utf-8 -*-
"""v2.8 端到端测试：HTTP / ASGI / 委托链 SM9 全通路。

覆盖：
  [A] HTTP API：SM9 凭证签发→wire→校验（sig_s_x/sig_s_y 序列化）
  [B] HTTP API：SM9 委托签发（alg_tier=sm9）
  [C] HTTP API：SM9 委托链验证（含混合 SM2+SM9 链）
  [D] ASGI：SM9 凭证端到端
  [E] ASGI：混合 SM2+SM9 委托链
  [F] 持久化：SM9 凭证 SQLite 落库→重启→校验
  [G] 跨租户隔离（多租户 SM9 场景）
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform, _cred_to_wire, _cred_from_wire
from http_api import route as http_route, TenantPool
import asgi_app  # noqa: F401  # 仅验证模块能加载
from persistence import SQLiteBackend
from credential import Credential, ALG_SM2, ALG_SM9

import sm9  # 用于生成 G2 主公钥

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
# 工具：构造一个带 SM9 能力的最小 HTTP TenantPool
# ---------------------------------------------------------------------------

def make_pool(tenants=None):
    """tenants: list[str]，默认 ['t1']。每个租户独立 Platform。"""
    tenants = tenants or ["t1"]
    pool = TenantPool()
    for t in tenants:
        pool.get(t)  # 触发懒加载创建
    return pool


def get_platform(tenants):
    """直接从 pool 拿 Platform（绕开 HTTP 层，用来看内部状态）。"""
    pool = make_pool(tenants)
    return {t: pool._pool[t] for t in tenants}


# ---------------------------------------------------------------------------
# [A] HTTP API：SM9 凭证签发→wire→校验
# ---------------------------------------------------------------------------

def test_http_sm9_credential():
    print("\n=== [A] HTTP API SM9 凭证端到端 ===")
    pool = make_pool(["t1"])
    plat = pool._pool["t1"]

    # 注册两个身份
    r = http_route(pool, "POST", "/v1/identities", None,
                    {"idn": "agent://org/issuer", "org": "org"},
                    tenant="t1")
    check("HTTP A1 注册 issuer 身份", r[0] == 200 and r[1]["ok"])
    r = http_route(pool, "POST", "/v1/identities", None,
                    {"idn": "agent://org/subject", "org": "org"},
                    tenant="t1")
    check("HTTP A2 注册 subject 身份", r[0] == 200 and r[1]["ok"])

    # 配置策略允许 SM9
    r = http_route(pool, "POST", "/v1/policy", None,
                    {"allowed_algs": [ALG_SM2, ALG_SM9],
                     "max_ttl_seconds": 3600},
                    tenant="t1")
    check("HTTP A3 策略允许 SM9", r[0] == 200 and r[1]["ok"])

    # 签发 SM9 凭证
    r = http_route(pool, "POST", "/v1/credentials", None,
                    {"issuer_idn": "agent://org/issuer",
                     "subject_idn": "agent://org/subject",
                     "audience": "service://api",
                     "scope": ["api:read"],
                     "ttl": 3600,
                     "alg_tier": ALG_SM9},
                    tenant="t1")
    check("HTTP A4 SM9 凭证签发 200", r[0] == 200 and r[1]["ok"])
    if not r[1].get("ok"):
        print("  reason:", r[1].get("reason"))
        return None
    cred_wire = r[1]["cred"]

    # Wire 格式校验：sig_s_x / sig_s_y 存在（不是 sig_s）
    check("HTTP A5 wire 含 sig_s_x", "sig_s_x" in cred_wire)
    check("HTTP A6 wire 含 sig_s_y", "sig_s_y" in cred_wire)
    check("HTTP A7 wire 无 sig_s（SM9 用元组）", "sig_s" not in cred_wire)
    check("HTTP A8 wire alg_tier=sm9", cred_wire["alg_tier"] == ALG_SM9)

    # 回环校验
    r2 = http_route(pool, "POST", "/v1/credentials/verify", None,
                     {"cred": cred_wire, "audience": "service://api"},
                     tenant="t1")
    check("HTTP A9 SM9 凭证回环校验通过", r2[0] == 200 and r2[1]["ok"],
          detail=str(r2[1]))

    # 篡改 alg_tier → 拒绝（防降级）
    bad = dict(cred_wire)
    bad["alg_tier"] = ALG_SM2
    r3 = http_route(pool, "POST", "/v1/credentials/verify", None,
                     {"cred": bad, "audience": "service://api"},
                     tenant="t1")
    check("HTTP A10 SM9 wire 篡改 alg_tier → 拒绝",
          r3[0] == 200 and not r3[1]["ok"])

    # 篡改 scope → 拒绝
    bad2 = dict(cred_wire)
    bad2["scope"] = ["api:write"]
    r4 = http_route(pool, "POST", "/v1/credentials/verify", None,
                     {"cred": bad2, "audience": "service://api"},
                     tenant="t1")
    check("HTTP A11 SM9 wire 篡改 scope → 拒绝",
          r4[0] == 200 and not r4[1]["ok"])

    return cred_wire


# ---------------------------------------------------------------------------
# [B] HTTP API：SM9 委托签发
# ---------------------------------------------------------------------------

def test_http_sm9_delegation():
    print("\n=== [B] HTTP API SM9 委托 ===")
    pool = make_pool(["t1"])
    # 准备身份
    for idn in ("agent://org/root", "agent://org/agent1", "agent://org/agent2"):
        http_route(pool, "POST", "/v1/identities", None,
                    {"idn": idn, "org": "org"}, tenant="t1")
    http_route(pool, "POST", "/v1/policy", None,
                {"allowed_algs": [ALG_SM2, ALG_SM9],
                 "max_ttl_seconds": 3600},
                tenant="t1")

    # root 先用 SM2 给 agent1 签根凭证
    r1 = http_route(pool, "POST", "/v1/credentials", None,
                     {"issuer_idn": "agent://org/root",
                      "subject_idn": "agent://org/agent1",
                      "audience": "service://api",
                      "scope": ["api:read", "api:write"],
                      "ttl": 3600, "alg_tier": ALG_SM2},
                     tenant="t1")
    check("HTTP B1 SM2 根凭证签发", r1[0] == 200 and r1[1]["ok"])

    # agent1 用 SM9 委托给 agent2（出示父凭证，触发 FR3-02/FR3-05 收敛）
    r2 = http_route(pool, "POST", "/v1/delegations", None,
                     {"delegator_idn": "agent://org/agent1",
                      "delegatee_idn": "agent://org/agent2",
                      "audience": "service://api",
                      "scope": ["api:read"],
                      "ttl": 3600, "alg_tier": ALG_SM9,
                      "parent_cred": r1[1]["cred"]},
                     tenant="t1")
    check("HTTP B2 SM9 委托签发", r2[0] == 200 and r2[1]["ok"],
          detail=str(r2[1]))

    # 链验证：[cred0(SM2), cred1(SM9)]
    chain_wires = [r1[1]["cred"], r2[1]["cred"]]
    r3 = http_route(pool, "POST", "/v1/delegations/verify", None,
                     {"chain": chain_wires,
                      "target_audience": "service://api",
                      "target_scope": ["api:read"]},
                     tenant="t1")
    check("HTTP B3 SM2+SM9 混合链验证通过", r3[0] == 200 and r3[1]["ok"],
          detail=str(r3[1]))

    # SM9 委托单独也允许
    r4 = http_route(pool, "POST", "/v1/delegations", None,
                     {"delegator_idn": "agent://org/agent1",
                      "delegatee_idn": "agent://org/agent2",
                      "audience": "service://api",
                      "scope": ["api:read"],
                      "ttl": 3600, "alg_tier": ALG_SM9},
                     tenant="t1")
    check("HTTP B4 SM9 委托重复签发不冲突（各自 jti）",
          r4[0] == 200 and r4[1]["ok"])

    return r2[1]["cred"]


# ---------------------------------------------------------------------------
# [C] HTTP API：SM9 委托链篡改检测
# ---------------------------------------------------------------------------

def test_http_sm9_delegation_chain_tamper():
    print("\n=== [C] HTTP API SM9 链篡改检测 ===")
    pool = make_pool(["t1"])
    for idn in ("agent://org/root", "agent://org/agent1", "agent://org/agent2"):
        http_route(pool, "POST", "/v1/identities", None,
                    {"idn": idn, "org": "org"}, tenant="t1")
    http_route(pool, "POST", "/v1/policy", None,
                {"allowed_algs": [ALG_SM2, ALG_SM9],
                 "max_ttl_seconds": 3600},
                tenant="t1")
    r1 = http_route(pool, "POST", "/v1/credentials", None,
                     {"issuer_idn": "agent://org/root",
                      "subject_idn": "agent://org/agent1",
                      "audience": "service://api",
                      "scope": ["api:read"],
                      "ttl": 3600, "alg_tier": ALG_SM2},
                     tenant="t1")
    r2 = http_route(pool, "POST", "/v1/delegations", None,
                     {"delegator_idn": "agent://org/agent1",
                      "delegatee_idn": "agent://org/agent2",
                      "audience": "service://api",
                      "scope": ["api:read"],
                      "ttl": 3600, "alg_tier": ALG_SM9},
                     tenant="t1")
    chain = [r1[1]["cred"], r2[1]["cred"]]

    # 篡改 SM9 hop 的 sig_s_x → 校验失败
    bad = [dict(chain[0]), dict(chain[1])]
    bad[1]["sig_s_x"] = "%064x" % (int(bad[1]["sig_s_x"], 16) + 1)
    r3 = http_route(pool, "POST", "/v1/delegations/verify", None,
                     {"chain": bad,
                      "target_audience": "service://api",
                      "target_scope": ["api:read"]},
                     tenant="t1")
    check("HTTP C1 篡改 SM9 sig_s_x → 链校验失败",
          r3[0] == 200 and not r3[1]["ok"],
          detail=str(r3[1]))

    # 篡改 SM9 hop 的 alg_tier（降级攻击）→ 失败
    bad2 = [dict(chain[0]), dict(chain[1])]
    bad2[1]["alg_tier"] = ALG_SM2
    r4 = http_route(pool, "POST", "/v1/delegations/verify", None,
                     {"chain": bad2,
                      "target_audience": "service://api",
                      "target_scope": ["api:read"]},
                     tenant="t1")
    check("HTTP C2 篡改 SM9 alg_tier → 链校验失败",
          r4[0] == 200 and not r4[1]["ok"])


# ---------------------------------------------------------------------------
# [D] ASGI：SM9 凭证端到端（走真正的 ASGI scope/receive/send 循环）
# ---------------------------------------------------------------------------

def test_asgi_sm9():
    print("\n=== [D] ASGI SM9 端到端 ===")
    asgi_app.init_pool()
    _call = asgi_app._call

    # 注册
    status, r = _call({"method": "POST", "path": "/v1/identities"},
                      body={"idn": "agent://asgi/iss", "org": "asgi"},
                      tenant="sm9-t")
    check("ASGI D1 注册 issuer", status == 200 and r.get("ok") is True)
    status, r = _call({"method": "POST", "path": "/v1/identities"},
                      body={"idn": "agent://asgi/sub", "org": "asgi"},
                      tenant="sm9-t")
    check("ASGI D2 注册 subject", status == 200 and r.get("ok") is True)

    # 策略：允许 SM9
    status, r = _call({"method": "POST", "path": "/v1/policy"},
                      body={"allowed_algs": [ALG_SM2, ALG_SM9],
                            "max_ttl_seconds": 3600},
                      tenant="sm9-t")
    check("ASGI D3 策略允许 SM9", status == 200 and r.get("ok") is True)

    # 签发 SM9
    status, r = _call({"method": "POST", "path": "/v1/credentials"},
                      body={"issuer_idn": "agent://asgi/iss",
                            "subject_idn": "agent://asgi/sub",
                            "audience": "service://asgi-svc",
                            "scope": ["svc:read"],
                            "ttl": 3600, "alg_tier": ALG_SM9},
                      tenant="sm9-t")
    check("ASGI D4 SM9 签发", status == 200 and r.get("ok") is True,
          detail=str(r))
    if not r.get("ok"):
        return

    cred = r["cred"]
    check("ASGI D5 wire 有 sig_s_x/sig_s_y",
          "sig_s_x" in cred and "sig_s_y" in cred)

    # 校验
    status, r2 = _call({"method": "POST", "path": "/v1/credentials/verify"},
                       body={"cred": cred,
                             "audience": "service://asgi-svc",
                             "record_nonce": False},
                       tenant="sm9-t")
    check("ASGI D6 SM9 校验通过", status == 200 and r2.get("ok") is True,
          detail=str(r2))


# ---------------------------------------------------------------------------
# [E] ASGI 混合 SM2+SM9 委托链
# ---------------------------------------------------------------------------

def test_asgi_mixed_chain():
    print("\n=== [E] ASGI 混合链验证 ===")
    asgi_app.init_pool()
    _call = asgi_app._call

    for idn in ("agent://asgi2/root", "agent://asgi2/a1", "agent://asgi2/a2"):
        _call({"method": "POST", "path": "/v1/identities"},
              body={"idn": idn, "org": "asgi2"}, tenant="sm9-t2")
    _call({"method": "POST", "path": "/v1/policy"},
          body={"allowed_algs": [ALG_SM2, ALG_SM9],
                "max_ttl_seconds": 3600}, tenant="sm9-t2")

    # hop0 SM2
    status, r1 = _call({"method": "POST", "path": "/v1/credentials"},
                       body={"issuer_idn": "agent://asgi2/root",
                             "subject_idn": "agent://asgi2/a1",
                             "audience": "service://s",
                             "scope": ["s:read"],
                             "ttl": 3600, "alg_tier": ALG_SM2},
                       tenant="sm9-t2")
    check("ASGI E1 hop0 SM2", status == 200 and r1.get("ok") is True)

    # hop1 SM9 委托
    status, r2 = _call({"method": "POST", "path": "/v1/delegations"},
                       body={"delegator_idn": "agent://asgi2/a1",
                             "delegatee_idn": "agent://asgi2/a2",
                             "audience": "service://s",
                             "scope": ["s:read"],
                             "ttl": 3600, "alg_tier": ALG_SM9,
                             "parent_cred": r1["cred"]},
                       tenant="sm9-t2")
    check("ASGI E2 hop1 SM9 委托", status == 200 and r2.get("ok") is True,
          detail=str(r2))

    chain = [r1["cred"], r2["cred"]]
    status, r3 = _call({"method": "POST", "path": "/v1/delegations/verify"},
                       body={"chain": chain,
                             "target_audience": "service://s",
                             "target_scope": ["s:read"]},
                       tenant="sm9-t2")
    check("ASGI E3 混合链验证通过", status == 200 and r3.get("ok") is True,
          detail=str(r3))


# ---------------------------------------------------------------------------
# [F] 持久化：SM9 凭证 SQLite 落库→重启→校验
# ---------------------------------------------------------------------------

def test_persistence_sm9():
    print("\n=== [F] SM9 凭证持久化 ===")
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")

    # 第一次：签发 SM9 凭证并落库
    p1 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
    p1.register_identity("agent://t/iss", org="t")
    p1.register_identity("agent://t/sub", org="t")
    p1.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                          "max_ttl_seconds": 3600})
    r = p1.issue_credential("agent://t/iss", "agent://t/sub",
                             "service://t", ["t:read"],
                             ttl=3600, alg_tier=ALG_SM9)
    check("F1 SM9 签发（持久化后端）", r["ok"])
    wire = r["cred"]
    jti = wire["jti"]

    # 校验（同一实例）
    r2 = p1.verify_credential(wire, audience="service://t")
    check("F2 同一实例 SM9 校验通过", r2["ok"])

    # 撤销
    r3 = p1.revoke(jti, reason="test")
    check("F3 SM9 撤销成功", r3["ok"])

    # 关闭并重启
    p1._pers.close()
    del p1
    p2 = Platform(tenant="t1", persistence=SQLiteBackend(db_path))
    # 重启后凭证校验应仍拒绝（已撤销）
    r4 = p2.verify_credential(wire, audience="service://t")
    check("F4 重启后 SM9 撤销状态保留", not r4["ok"])

    # 撤销证明（撤销累加器）
    p2.register_identity("agent://t/iss2", org="t")
    r5 = p2.verify_revocation(jti)
    check("F5 SM9 撤销累加器可查", r5["ok"] and r5["revoked"])

    # 清理
    p2._pers.close()
    del p2
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# [G] 多租户隔离：两个租户各自 SM9 不互相污染
# ---------------------------------------------------------------------------

def test_multi_tenant_sm9():
    print("\n=== [G] 多租户 SM9 隔离 ===")
    pool = make_pool(["tA", "tB"])

    for t in ("tA", "tB"):
        plat = pool._pool[t]
        plat.register_identity("agent://%s/iss" % t, org=t)
        plat.register_identity("agent://%s/sub" % t, org=t)
        plat.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                                "max_ttl_seconds": 3600})

    # tA 签发
    rA = http_route(pool, "POST", "/v1/credentials", None,
                     {"issuer_idn": "agent://tA/iss",
                      "subject_idn": "agent://tA/sub",
                      "audience": "service://a",
                      "scope": ["a:read"],
                      "ttl": 3600, "alg_tier": ALG_SM9},
                     tenant="tA")
    check("G1 tA SM9 签发", rA[0] == 200 and rA[1]["ok"])

    # tA 的凭证在 tB 校验失败（unknown issuer）
    rA_on_B = http_route(pool, "POST", "/v1/credentials/verify", None,
                          {"cred": rA[1]["cred"], "audience": "service://a"},
                          tenant="tB")
    check("G2 tA 凭证在 tB 校验失败", rA_on_B[0] == 200 and not rA_on_B[1]["ok"])

    # tB 签发 + 校验
    rB = http_route(pool, "POST", "/v1/credentials", None,
                     {"issuer_idn": "agent://tB/iss",
                      "subject_idn": "agent://tB/sub",
                      "audience": "service://b",
                      "scope": ["b:read"],
                      "ttl": 3600, "alg_tier": ALG_SM9},
                     tenant="tB")
    check("G3 tB SM9 签发", rB[0] == 200 and rB[1]["ok"])
    rB_v = http_route(pool, "POST", "/v1/credentials/verify", None,
                       {"cred": rB[1]["cred"], "audience": "service://b"},
                       tenant="tB")
    check("G4 tB SM9 校验通过", rB_v[0] == 200 and rB_v[1]["ok"])

    # tA 的 P_pub 与 tB 的 P_pub 不同（各自独立 IA）
    check("G5 tA 与 tB P_pub 不同（IA 独立）",
          pool._pool["tA"].ia.ppub != pool._pool["tB"].ia.ppub)


# ---------------------------------------------------------------------------
# [H] HTTP 拒绝未启用的 SM9（策略不允许多档位）
# ---------------------------------------------------------------------------

def test_policy_reject_sm9():
    print("\n=== [H] 策略拒绝未启用的 SM9 ===")
    pool = make_pool(["t1"])
    plat = pool._pool["t1"]
    plat.register_identity("agent://p/iss", org="p")
    plat.register_identity("agent://p/sub", org="p")
    # 只允许 SM2
    plat.configure_policy({"allowed_algs": [ALG_SM2],
                            "max_ttl_seconds": 3600})

    r = http_route(pool, "POST", "/v1/credentials", None,
                    {"issuer_idn": "agent://p/iss",
                     "subject_idn": "agent://p/sub",
                     "audience": "service://p",
                     "scope": ["p:read"],
                     "ttl": 3600, "alg_tier": ALG_SM9},
                    tenant="t1")
    check("H1 策略只允许 SM2 → SM9 签发拒绝",
          r[0] == 400 and not r[1]["ok"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_http_sm9_credential()
    test_http_sm9_delegation()
    test_http_sm9_delegation_chain_tamper()
    test_asgi_sm9()
    test_asgi_mixed_chain()
    test_persistence_sm9()
    test_multi_tenant_sm9()
    test_policy_reject_sm9()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v8_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v8 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
