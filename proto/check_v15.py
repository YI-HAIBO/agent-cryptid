# -*- coding: utf-8 -*-
"""check_v15：FR6-01 / FR6-02 / FR6-05 治理台数据接口验证。

覆盖：
    [A] 智能体清单统计（FR6-01）
    [B] 委托拓扑（FR6-02）
    [C] 实时权限视图（FR6-02）
    [D] 异常告警扫描（FR6-05）
    [E] HTTP /v1/governance/* 路由
    [F] 边界与向后兼容
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform
import governance


def _build_platform(with_persistence=False):
    p = Platform(tenant="gov-test")
    p.register_identity("agent://root/ca", org="root",
                        agent_type="issuance", owner="admin",
                        tags=["root", "ca"])
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
    p.register_identity("agent://org-c/service", org="org-c",
                        agent_type="service", owner="dave",
                        tags=["org-c"])
    return p


def _seed_credentials(p):
    """root -> org-a/orchestrator -> worker-1；worker-2；org-b/agent1"""
    r1 = p.issue_credential("agent://root/ca",
                            "agent://org-a/orchestrator",
                            "service://invoice",
                            ["invoice:read", "invoice:write"], ttl=3600)
    r2 = p.issue_delegation("agent://org-a/orchestrator",
                            "agent://org-a/worker-1",
                            "service://invoice", ["invoice:read"],
                            intent="process", parent_cred=r1["cred"])
    r3 = p.issue_delegation("agent://org-a/orchestrator",
                            "agent://org-a/worker-2",
                            "service://invoice", ["invoice:read"],
                            intent="backup", parent_cred=r1["cred"])
    r4 = p.issue_credential("agent://root/ca", "agent://org-b/agent1",
                            "service://report", ["report:read"], ttl=3600)
    p.disable_identity("agent://org-c/service", reason="test")
    return r1, r2, r3, r4


def main():
    out = []
    p = _build_platform()
    r1, r2, r3, r4 = _seed_credentials(p)

    # ---------------- [A] FR6-01 智能体清单 ----------------
    inv = governance.agent_inventory(p)
    out.append(("A1 total=6",
                inv["ok"] and inv["total"] == 6))
    out.append(("A2 active=5", inv["active"] == 5))
    out.append(("A3 disabled=1", inv["disabled"] == 1))
    out.append(("A4 by_org org-a=3",
                inv["by_org"].get("org-a") == 3))
    out.append(("A5 by_type worker=3",
                inv["by_type"].get("worker") == 3))
    out.append(("A6 by_owner bob=2",
                inv["by_owner"].get("bob") == 2))
    out.append(("A7 by_tag tier2=3",
                inv["by_tag"].get("tier2") == 3))
    out.append(("A8 rows 数=6", len(inv["identities"]) == 6))

    # worker-1 作为 sub 持有 1 张未撤销凭证
    w1 = next(r for r in inv["identities"]
              if r["idn"] == "agent://org-a/worker-1")
    out.append(("A9 worker-1 delegated_in_active=1",
                w1["delegated_in_active"] == 1))
    out.append(("A10 worker-1 delegated_in_total=1",
                w1["delegated_in_total"] == 1))

    # orchestrator 作为 sub 有 1 张未撤销凭证
    orch = next(r for r in inv["identities"]
                if r["idn"] == "agent://org-a/orchestrator")
    out.append(("A11 orchestrator delegated_in_active=1",
                orch["delegated_in_active"] == 1))

    # 按 org 过滤
    inv_a = governance.agent_inventory(p, only={"org": "org-a"})
    out.append(("A12 按 org=org-a 过滤 3 条",
                inv_a["total"] == 3))

    # 按 status 过滤
    inv_dis = governance.agent_inventory(p, only={"status": "disabled"})
    out.append(("A13 按 status=disabled 过滤 1 条",
                inv_dis["total"] == 1))
    out.append(("A14 disabled 的 idn 为 org-c/service",
                inv_dis["identities"][0]["idn"] == "agent://org-c/service"))

    # 按 tag 过滤
    inv_t2 = governance.agent_inventory(p, only={"tag": "tier2"})
    out.append(("A15 按 tag=tier2 过滤 3 条",
                inv_t2["total"] == 3))

    # 按 agent_type 过滤
    inv_w = governance.agent_inventory(p, only={"agent_type": "worker"})
    out.append(("A16 按 agent_type=worker 过滤 3 条",
                inv_w["total"] == 3))

    # 组合过滤：org-a AND tag=tier2
    inv_combo = governance.agent_inventory(
        p, only={"org": "org-a", "tag": "tier2"})
    out.append(("A17 组合 org-a AND tag=tier2 = 2 条",
                inv_combo["total"] == 2))

    # ---------------- [B] FR6-02 委托拓扑 ----------------
    topo = governance.delegation_topology(p)
    # 边：root->orch, orch->worker-1, orch->worker-2, root->org-b/agent1
    out.append(("B1 边数=4", topo["edge_count"] == 4))
    out.append(("B2 节点数=5", topo["node_count"] == 5))
    out.append(("B3 max_depth=1", topo["max_depth"] == 1))
    out.append(("B4 roots 包含 root/ca",
                "agent://root/ca" in topo["roots"]))

    # 子图：以 orchestrator 为根
    sub = governance.delegation_topology(
        p, root_idn="agent://org-a/orchestrator")
    out.append(("B5 子图边数=2", sub["edge_count"] == 2))
    out.append(("B6 子图节点数=3", sub["node_count"] == 3))

    # 已撤销：先撤销 worker-1 的凭证，再看拓扑
    jti2 = r2["jti"]
    p.revoke(jti2, reason="test")
    topo_after = governance.delegation_topology(p)
    out.append(("B7 撤销后边数=3", topo_after["edge_count"] == 3))
    topo_include = governance.delegation_topology(p, include_revoked=True)
    out.append(("B8 include_revoked=True 边数=4",
                topo_include["edge_count"] == 4))

    # ---------------- [C] FR6-02 实时权限视图 ----------------
    # 撤销后 worker-1 应不再有 service://invoice 权限
    rtv1 = governance.realtime_permission_view(p, "agent://org-a/worker-1")
    out.append(("C1 worker-1 视图 ok", rtv1["ok"]))
    inv_aud = [a for a in rtv1["audiences"]
               if a["audience"] == "service://invoice"]
    out.append(("C2 worker-1 撤销后 invoice 权限消失",
                len(inv_aud) == 0))

    # worker-2 仍有权限
    rtv2 = governance.realtime_permission_view(p, "agent://org-a/worker-2")
    w2_inv = [a for a in rtv2["audiences"]
              if a["audience"] == "service://invoice"]
    out.append(("C3 worker-2 有 invoice 权限", len(w2_inv) == 1))
    out.append(("C4 worker-2 权限 scope=invoice:read",
                w2_inv[0]["scope"] == ["invoice:read"]))

    # 空权限视图（org-c/service 是 disabled，且无任何凭证）
    rtv3 = governance.realtime_permission_view(p, "agent://org-c/service")
    out.append(("C5 disabled 标识权限视图为空",
                rtv3["audience_count"] == 0))

    # ---------------- [D] FR6-05 异常告警扫描 ----------------
    # 制造几次校验失败（未知 issuer、受众不一致）
    for _ in range(6):
        p.verify_credential(r4["cred"], audience="wrong://aud",
                            record_nonce=False)
    # 制造几次校验通过
    for _ in range(2):
        p.verify_credential(r4["cred"], audience="service://report",
                            record_nonce=False)

    al = governance.scan_alerts(p, window_seconds=600, threshold=3)
    out.append(("D1 scan 返回 ok", al["ok"]))
    out.append(("D2 rules 数≥8", len(al["rules"]) >= 8))
    out.append(("D3 window_seconds 正确",
                al["window_seconds"] == 600))
    out.append(("D4 totals 含 verify_ok",
                "verify_ok" in al["totals"]))
    out.append(("D5 totals 含 audience_mismatch",
                al["totals"]["audience_mismatch"] >= 1))
    out.append(("D6 高频校验失败触发告警",
                al["alert_count"] >= 1))
    # 找到 audience mismatch 告警（reason=audience mismatch，count>=3）
    am_alerts = [a for a in al["alerts"]
                 if a["rule"] == "verify_fail_hot"
                 and a.get("reason_code") == "audience mismatch"]
    out.append(("D7 audience mismatch 高频告警存在",
                len(am_alerts) >= 1))

    # 空告警：窗口过短或阈值过高
    al2 = governance.scan_alerts(p, window_seconds=600, threshold=1000)
    out.append(("D8 高阈值告警为 0", al2["alert_count"] == 0))

    # ---------------- [E] HTTP /v1/governance/* 路由 ----------------
    from http_api import route, TenantPool
    pool = TenantPool()
    plat = pool.get("gov-http")
    plat.register_identity("agent://h/root", org="h", agent_type="issuance",
                           owner="a", tags=["root"])
    plat.register_identity("agent://h/worker", org="h", agent_type="worker",
                           owner="b", tags=["worker"])
    rc = plat.issue_credential("agent://h/root", "agent://h/worker",
                               "svc://h", ["h:read"], ttl=3600)

    status, res = route(pool, "GET", "/v1/governance/inventory", {},
                        None, "gov-http")
    out.append(("E1 HTTP inventory 200", status == 200))
    out.append(("E2 HTTP inventory total=2",
                res.get("total") == 2))

    status, res = route(pool, "GET", "/v1/governance/topology", {},
                        None, "gov-http")
    out.append(("E3 HTTP topology 200", status == 200))
    out.append(("E4 HTTP topology edge=1",
                res.get("edge_count") == 1))

    status, res = route(pool, "GET", "/v1/governance/permissions",
                        {"idn": ["agent://h/worker"]}, None, "gov-http")
    out.append(("E5 HTTP permissions 200", status == 200))
    out.append(("E6 HTTP permissions audience=svc://h",
                any(a["audience"] == "svc://h" for a in res["audiences"])))

    # 缺 idn 应 400
    status, res = route(pool, "GET", "/v1/governance/permissions", {},
                        None, "gov-http")
    out.append(("E7 缺 idn 返回 400", status == 400))

    status, res = route(pool, "GET", "/v1/governance/alerts",
                        {"window": ["3600"], "threshold": ["5"]},
                        None, "gov-http")
    out.append(("E8 HTTP alerts 200", status == 200))
    out.append(("E9 HTTP alerts 含 rules", "rules" in res))

    # ---------------- [F] 边界与向后兼容 ----------------
    # 空平台
    p_empty = Platform(tenant="empty")
    inv_e = governance.agent_inventory(p_empty)
    out.append(("F1 空平台清单 total=0", inv_e["total"] == 0))
    topo_e = governance.delegation_topology(p_empty)
    out.append(("F2 空平台拓扑边=0", topo_e["edge_count"] == 0))
    rtv_e = governance.realtime_permission_view(p_empty, "nobody")
    out.append(("F3 空平台权限视图 ok", rtv_e["ok"]
                and rtv_e["audience_count"] == 0))
    al_e = governance.scan_alerts(p_empty, window_seconds=60,
                                  threshold=1)
    out.append(("F4 空平台告警 scan 返回 ok", al_e["ok"]))

    # 未注册的 idn 查权限视图
    rtv_unknown = governance.realtime_permission_view(p, "agent://nobody")
    out.append(("F5 未注册 idn 权限视图 audience_count=0",
                rtv_unknown["audience_count"] == 0))

    # 子图 root_idn 不存在
    sub_bad = governance.delegation_topology(p, root_idn="agent://nobody")
    out.append(("F6 未知 root 子图边=0", sub_bad["edge_count"] == 0))

    # 持久化后端下的治理接口
    from persistence import SQLiteBackend
    pers = SQLiteBackend(":memory:")
    p2 = Platform(tenant="gov-pers", persistence=pers)
    p2.register_identity("agent://p/root", org="p",
                         agent_type="issuance", owner="x")
    p2.register_identity("agent://p/worker", org="p",
                         agent_type="worker", owner="y")
    rp = p2.issue_credential("agent://p/root", "agent://p/worker",
                             "svc://p", ["p:read"], ttl=3600)
    inv_p = governance.agent_inventory(p2)
    out.append(("F7 持久化后端清单 total=2", inv_p["total"] == 2))
    rtv_p = governance.realtime_permission_view(p2, "agent://p/worker")
    out.append(("F8 持久化后端权限视图命中 svc://p",
                any(a["audience"] == "svc://p"
                    for a in rtv_p["audiences"])))

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
                               "check_v15_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("PASS=%d  FAIL=%d\n" % (n_pass, n_fail))
    print(report_path)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
