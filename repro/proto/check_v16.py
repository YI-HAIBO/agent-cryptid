# -*- coding: utf-8 -*-
"""check_v16：FR1-04 标识检索 + FR3-04 委托深度限制。

覆盖：
    [A] register_identity 接受 tags 参数
    [B] list_identities 各过滤条件
    [C] update_identity_tags 增删标签
    [D] FR3-04 委托深度正常签发
    [E] FR3-04 委托深度超限拒绝
    [F] FR3-04 策略可配置
    [G] FR3-04 无父凭证的委托（遗留调用）
    [H] FR3-04 深度在审计与登记表中记录
    [I] HTTP 路由：GET /v1/identities 与 POST /v1/identities/tags
    [J] 持久化往返
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform


def _setup(p):
    p.register_identity("agent://root/ca", org="root",
                        agent_type="issuance", owner="admin",
                        tags=["root", "ca", "tier1"])
    p.register_identity("agent://org-a/orchestrator", org="org-a",
                        agent_type="orchestrator", owner="alice",
                        tags=["org-a", "tier1"])
    p.register_identity("agent://org-a/worker-1", org="org-a",
                        agent_type="worker", owner="bob",
                        tags=["org-a", "tier2"])
    p.register_identity("agent://org-a/worker-2", org="org-a",
                        agent_type="worker", owner="bob",
                        tags=["org-a", "tier2"])
    p.register_identity("agent://org-b/agent1", org="org-b",
                        agent_type="worker", owner="carol",
                        tags=["org-b", "tier2"])
    p.register_identity("agent://org-c/svc", org="org-c",
                        agent_type="service", owner="dave",
                        tags=["org-c"])


def main():
    out = []
    p = Platform(tenant="v16-test")
    _setup(p)

    # ---------------- [A] register_identity 接受 tags ----------------
    r = p.register_identity("agent://new/tagged", org="new",
                            agent_type="worker", owner="eve",
                            tags=["experimental", "priority"])
    out.append(("A1 注册含 tags 成功",
                r["ok"] and r["meta"]["tags"] == ["experimental",
                                                 "priority"]))

    # 不传 tags 时默认为空
    r = p.register_identity("agent://new/untagged", org="new",
                            agent_type="worker", owner="eve")
    out.append(("A2 未传 tags 为空列表",
                r["ok"] and r["meta"]["tags"] == []))

    # ---------------- [B] list_identities 各过滤条件 ----------------
    # 默认返回全部
    r = p.list_identities()
    out.append(("B1 默认返回全部 8 条", r["ok"] and r["total"] == 8))

    # 按 org 过滤
    r = p.list_identities(org="org-a")
    out.append(("B2 org=org-a 3 条", r["total"] == 3))

    # 按 owner 过滤
    r = p.list_identities(owner="bob")
    out.append(("B3 owner=bob 2 条", r["total"] == 2))

    # 按 tag 过滤
    r = p.list_identities(tag="tier2")
    out.append(("B4 tag=tier2 3 条", r["total"] == 3))

    # 按 status 过滤
    p.disable_identity("agent://org-b/agent1", reason="test")
    r = p.list_identities(status="active")
    out.append(("B5 active 7 条", r["total"] == 7))
    r = p.list_identities(status="disabled")
    out.append(("B6 disabled 1 条", r["total"] == 1))
    out.append(("B7 disabled 是 org-b/agent1",
                r["identities"][0]["idn"] == "agent://org-b/agent1"))

    # 按 agent_type 过滤
    # worker: worker-1, worker-2, org-b/agent1, new/tagged, new/untagged = 5
    r = p.list_identities(agent_type="worker")
    out.append(("B8 agent_type=worker 5 条", r["total"] == 5))

    # 组合过滤
    r = p.list_identities(org="org-a", tag="tier2")
    out.append(("B9 org=org-a AND tag=tier2 2 条", r["total"] == 2))

    # 组合 + 状态
    r = p.list_identities(org="org-a", status="active",
                          tag="tier2")
    out.append(("B10 三重过滤 2 条", r["total"] == 2))

    # 无匹配的过滤
    r = p.list_identities(org="org-zzz")
    out.append(("B11 无匹配 0 条", r["total"] == 0))

    # limit 参数
    r = p.list_identities(limit=3)
    out.append(("B12 limit=3 返回 3 条", r["total"] == 3))

    # 排序：先 active 后 disabled，再按 idn 升序
    r = p.list_identities()
    first = r["identities"][0]
    last = r["identities"][-1]
    out.append(("B13 active 排在 disabled 前",
                first["status"] == "active"
                and last["status"] == "disabled"))

    # 返回结构含 meta
    row = r["identities"][0]
    out.append(("B14 返回含 meta.org",
                "meta" in row and "org" in row["meta"]))
    out.append(("B15 返回含 meta.tags", "tags" in row["meta"]))

    # ---------------- [C] update_identity_tags ----------------
    r = p.update_identity_tags("agent://new/untagged", tags=["tag-a", "tag-b"])
    out.append(("C1 覆盖式设置 tags 成功",
                r["ok"] and r["tags"] == ["tag-a", "tag-b"]))

    # 追加
    r = p.update_identity_tags("agent://new/untagged", add=["tag-c"])
    out.append(("C2 add 追加 tag-c",
                "tag-c" in r["tags"] and "tag-a" in r["tags"]))

    # 删除
    r = p.update_identity_tags("agent://new/untagged", remove=["tag-a"])
    out.append(("C3 remove 删除 tag-a",
                "tag-a" not in r["tags"] and "tag-b" in r["tags"]))

    # 混合：add + remove
    r = p.update_identity_tags("agent://new/untagged",
                               add=["tag-d"], remove=["tag-b"])
    out.append(("C4 混合 add+remove 正确",
                "tag-d" in r["tags"] and "tag-b" not in r["tags"]
                and "tag-c" in r["tags"]))

    # 未知标识
    r = p.update_identity_tags("agent://nobody", tags=["x"])
    out.append(("C5 未知标识被拒",
                not r["ok"] and r["reason"] == "unknown identity"))

    # 按更新后的 tag 检索
    r = p.list_identities(tag="tag-d")
    out.append(("C6 按新 tag 检索命中",
                any(i["idn"] == "agent://new/untagged"
                    for i in r["identities"])))

    # ---------------- [D] FR3-04 委托深度正常签发 ----------------
    # 构造链：root -> l1 (cred depth=0) -> l2 (d1) -> l3 (d2) -> ... -> l9 (d8)
    p2 = Platform(tenant="v16-depth")
    p2.configure_policy({"max_delegation_depth": 8})
    p2.register_identity("agent://d/root", org="d", agent_type="issuance",
                         owner="x")
    for i in range(1, 11):
        p2.register_identity("agent://d/l%d" % i, org="d",
                             agent_type="worker", owner="x")

    r1 = p2.issue_credential("agent://d/root", "agent://d/l1",
                             "svc://d", ["d:read"], ttl=3600)
    out.append(("D1 根凭证签发成功", r1["ok"]))
    out.append(("D2 根凭证无 depth 字段", "depth" not in r1))

    # 逐级委托：第 k 跳的深度为 k（k=1..8 允许）
    cur = r1
    for k in range(1, 9):
        delegator = "agent://d/l%d" % k
        delegatee = "agent://d/l%d" % (k + 1)
        cur = p2.issue_delegation(delegator, delegatee, "svc://d",
                                  ["d:read"], parent_cred=cur["cred"])
        out.append(("D3.%d 第 %d 跳委托 depth=%d" % (k, k, k),
                    cur["ok"] and cur["depth"] == k))

    # ---------------- [E] FR3-04 委托深度超限拒绝 ----------------
    # 第 9 跳（would_be_depth=9 > max_depth=8）应被拒
    r9 = p2.issue_delegation("agent://d/l9", "agent://d/l10",
                             "svc://d", ["d:read"], parent_cred=cur["cred"])
    out.append(("E1 第 9 跳超限被拒",
                not r9["ok"]
                and r9["reason"] == "delegation depth exceeded"))
    out.append(("E2 拒绝返回 max_depth=8",
                r9["max_depth"] == 8))
    out.append(("E3 拒绝返回 would_be_depth=9",
                r9["would_be_depth"] == 9))
    out.append(("E4 拒绝返回 parent_jti",
                r9.get("parent_jti") == cur["jti"]))

    # 边界：正好 8 深度允许签发（D3.8 已验证），第 9 跳被拒（E1 已验证）
    # 再验证：max_depth=8 时 depth=8 允许、depth=9 拒绝，两侧都已覆盖

    # ---------------- [F] FR3-04 策略可配置 ----------------
    p4 = Platform(tenant="v16-policy")
    p4.register_identity("agent://p/root", org="p", agent_type="issuance",
                         owner="x")
    p4.register_identity("agent://p/l1", org="p", agent_type="worker",
                         owner="x")
    p4.register_identity("agent://p/l2", org="p", agent_type="worker",
                         owner="x")
    p4.register_identity("agent://p/l3", org="p", agent_type="worker",
                         owner="x")

    # 默认策略 max_delegation_depth=8
    r0 = p4.issue_credential("agent://p/root", "agent://p/l1",
                             "svc://p", ["p:read"], ttl=3600)
    r1 = p4.issue_delegation("agent://p/l1", "agent://p/l2",
                             "svc://p", ["p:read"],
                             parent_cred=r0["cred"])
    r2 = p4.issue_delegation("agent://p/l2", "agent://p/l3",
                             "svc://p", ["p:read"],
                             parent_cred=r1["cred"])
    out.append(("F1 默认策略允许 depth=2",
                r2["ok"] and r2["depth"] == 2))

    # 收紧到 2
    p4.configure_policy({"max_delegation_depth": 2})
    r3 = p4.issue_delegation("agent://p/l3", "agent://p/l1",
                             "svc://p", ["p:read"],
                             parent_cred=r2["cred"])
    out.append(("F2 收紧到 2 后 depth=3 被拒",
                not r3["ok"]
                and r3["reason"] == "delegation depth exceeded"))

    # 放松到 5
    p4.configure_policy({"max_delegation_depth": 5})
    r4 = p4.issue_delegation("agent://p/l3", "agent://p/l1",
                             "svc://p", ["p:read"],
                             parent_cred=r2["cred"])
    out.append(("F3 放松到 5 后 depth=3 允许",
                r4["ok"] and r4["depth"] == 3))

    # 设为 None 表示不限制
    p4.configure_policy({"max_delegation_depth": None})
    r5 = p4.issue_delegation("agent://p/l1", "agent://p/l3",
                             "svc://p", ["p:read"],
                             parent_cred=r4["cred"])
    out.append(("F4 max=None 表示不限制",
                r5["ok"] and r5["depth"] == 4))

    # ---------------- [G] FR3-04 无父凭证的委托 ----------------
    p5 = Platform(tenant="v16-legacy")
    p5.register_identity("agent://legacy/a", org="l", agent_type="worker",
                         owner="x")
    p5.register_identity("agent://legacy/b", org="l", agent_type="worker",
                         owner="x")
    r = p5.issue_delegation("agent://legacy/a", "agent://legacy/b",
                            "svc://legacy", ["legacy:read"])
    out.append(("G1 无 parent_cred 仍允许签发（向后兼容）",
                r["ok"]))
    out.append(("G2 无 parent_cred 时 depth=1", r["depth"] == 1))
    out.append(("G3 无 parent_cred 时 parent_verified=False",
                r["parent_verified"] is False))

    # ---------------- [H] FR3-04 深度在审计与登记表中记录 ----------------
    # 检查审计事件里含 depth 字段
    audit = p2.audit_query(kind="delegation.issue")
    depths = [r["event"].get("depth") for r in audit["records"]]
    out.append(("H1 审计事件含 depth 字段",
                all(d is not None for d in depths)))
    out.append(("H2 审计深度递增 1,2,3,4,5,6,7,8",
                depths == [1, 2, 3, 4, 5, 6, 7, 8]))

    # 检查登记簿
    reg = p2._cred_registry
    depths_reg = [m["depth"] for m in reg.values()
                  if m.get("depth") is not None]
    out.append(("H3 登记簿含 depth",
                len(depths_reg) >= 8))

    # 级联撤销仍工作（回归）
    p2.revoke_by_identity("agent://d/l1", reason="test")
    snap = p2.revocation_snapshot(0)
    out.append(("H4 级联撤销仍工作",
                snap["total_revoked"] >= 1))

    # ---------------- [I] HTTP 路由 ----------------
    from http_api import route, TenantPool
    pool = TenantPool()
    plat = pool.get("v16-http")
    plat.register_identity("agent://h/root", org="h", agent_type="issuance",
                           owner="a", tags=["root", "tier1"])
    plat.register_identity("agent://h/worker", org="h", agent_type="worker",
                           owner="b", tags=["worker"])
    plat.register_identity("agent://h/svc", org="h", agent_type="service",
                           owner="c", tags=["service"])

    # GET /v1/identities
    status, res = route(pool, "GET", "/v1/identities", {}, None, "v16-http")
    out.append(("I1 GET /v1/identities 200", status == 200))
    out.append(("I2 默认返回 3 条", res["total"] == 3))

    # 带过滤参数
    status, res = route(pool, "GET", "/v1/identities",
                        {"org": ["h"], "agent_type": ["worker"]},
                        None, "v16-http")
    out.append(("I3 组合过滤 1 条", res["total"] == 1))
    out.append(("I4 命中 worker",
                res["identities"][0]["idn"] == "agent://h/worker"))

    # 按 tag 过滤
    status, res = route(pool, "GET", "/v1/identities",
                        {"tag": ["tier1"]}, None, "v16-http")
    out.append(("I5 tag=tier1 命中 root",
                res["identities"][0]["idn"] == "agent://h/root"))

    # POST /v1/identities 含 tags
    status, res = route(pool, "POST", "/v1/identities", {},
                        {"idn": "agent://h/new", "org": "h",
                         "agent_type": "worker", "owner": "d",
                         "tags": ["new", "hot"]},
                        "v16-http")
    out.append(("I6 注册含 tags 成功", res["meta"]["tags"] == ["new", "hot"]))

    # POST /v1/identities/tags
    status, res = route(pool, "POST", "/v1/identities/tags", {},
                        {"idn": "agent://h/new", "add": ["cold"]},
                        "v16-http")
    out.append(("I7 update tags add=cold", "cold" in res["tags"]))

    status, res = route(pool, "POST", "/v1/identities/tags", {},
                        {"idn": "agent://h/new", "remove": ["hot"]},
                        "v16-http")
    out.append(("I8 update tags remove=hot", "hot" not in res["tags"]))

    # POST /v1/policy 设置 max_delegation_depth
    status, res = route(pool, "POST", "/v1/policy", {},
                        {"max_delegation_depth": 3}, "v16-http")
    out.append(("I9 policy max_delegation_depth=3",
                res["policy"]["max_delegation_depth"] == 3))

    # ---------------- [J] 持久化往返 ----------------
    from persistence import SQLiteBackend
    import tempfile
    db_path = os.path.join(tempfile.gettempdir(), "v16_persist_test.db")
    try:
        pers = SQLiteBackend(db_path)
        pa = Platform(tenant="v16-pers", persistence=pers)
        pa.register_identity("agent://pers/root", org="pers",
                             agent_type="issuance", owner="x",
                             tags=["root", "hot"])
        pa.register_identity("agent://pers/worker", org="pers",
                             agent_type="worker", owner="y",
                             tags=["worker"])
        r = pa.issue_credential("agent://pers/root", "agent://pers/worker",
                                "svc://pers", ["pers:read"], ttl=3600)
        pa.issue_delegation("agent://pers/worker", "agent://pers/worker",
                            "svc://pers", ["pers:read"],
                            parent_cred=r["cred"])
        # 重启
        pers2 = SQLiteBackend(db_path)
        pb = Platform(tenant="v16-pers", persistence=pers2)
        # 检查 tags 保留
        r = pb.list_identities(tag="hot")
        out.append(("J1 重启后 tags 保留",
                    any(i["idn"] == "agent://pers/root"
                        for i in r["identities"])))
        # 检查深度仍记录
        reg = pb._cred_registry
        depths = [m["depth"] for m in reg.values()
                  if m.get("depth") is not None]
        out.append(("J2 重启后 depth 保留",
                    1 in depths))
    finally:
        try:
            os.remove(db_path)
        except Exception:
            pass

    # 打印
    print("=" * 60)
    for name, ok in out:
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
    n_pass = sum(1 for _, ok in out if ok)
    n_fail = len(out) - n_pass
    print("=" * 60)
    print("PASS %d / FAIL %d" % (n_pass, n_fail))
    print("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))

    report_path = os.path.join(os.path.dirname(__file__),
                               "check_v16_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("PASS=%d  FAIL=%d\n" % (n_pass, n_fail))
    print(report_path)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
