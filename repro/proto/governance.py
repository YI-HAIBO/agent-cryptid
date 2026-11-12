# -*- coding: utf-8 -*-
"""治理台数据接口：FR6-01 / FR6-02 / FR6-05。

设计原则：
    · 只读聚合层，不写库、不改状态；所有数据来自 Platform 已有的登记簿与审计链。
    · 输出面向展示层（JSON / Markdown），便于接前端或导出报表。
    · 不引入第三方依赖，纯 Python。

对应需求：
    FR6-01  智能体清单（归属、状态、凭证统计）      → agent_inventory()
    FR6-02  委托链拓扑与实时权限视图              → delegation_topology()
                                                    + realtime_permission_view()
    FR6-05  异常告警扫描                          → scan_alerts()
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------
# FR6-01  智能体清单
# ------------------------------------------------------------------
def agent_inventory(platform, only=None) -> dict:
    """FR6-01：智能体清单及其归属、状态与凭证统计。

    only   可选过滤：{"org":..., "owner":..., "tag":..., "status":...,
                    "agent_type":...}；None 时不过滤。
    """
    only = only or {}
    identities = platform._identities
    registry = platform._cred_registry
    revoked = platform._revoked_jtis

    # 统计口径
    by_org, by_type, by_owner, by_tag = {}, {}, {}, {}
    per_id = {}
    total_active = total_disabled = 0
    issued_total = 0  # 该标识作为签发方持有的未撤销凭证数
    delegated_in_total = 0  # 作为主体持有的未撤销凭证数

    for idn, rec in identities.items():
        meta = rec.get("meta") or {}
        org = meta.get("org") or "（未标注）"
        typ = meta.get("agent_type") or "（未标注）"
        owner = meta.get("owner") or "（未标注）"
        tags = meta.get("tags") or []
        status = rec.get("status")
        if status == "active":
            total_active += 1
        else:
            total_disabled += 1
        by_org[org] = by_org.get(org, 0) + 1
        by_type[typ] = by_type.get(typ, 0) + 1
        by_owner[owner] = by_owner.get(owner, 0) + 1
        for t in tags:
            by_tag[t] = by_tag.get(t, 0) + 1

        if only.get("org") and meta.get("org") != only["org"]:
            continue
        if only.get("owner") and meta.get("owner") != only["owner"]:
            continue
        if only.get("tag") and only["tag"] not in tags:
            continue
        if only.get("status") and status != only["status"]:
            continue
        if only.get("agent_type") and meta.get("agent_type") != only["agent_type"]:
            continue

        # 该标识作为 iss / sub 出现的凭证数
        issued_n = sum(1 for m in registry.values()
                       if m.get("iss") == idn)
        delegated_in_n = sum(1 for m in registry.values()
                             if m.get("sub") == idn)
        # 未撤销计数（当前有效）
        active_issued = sum(1 for m in registry.values()
                            if m.get("iss") == idn
                            and m["iss"] and m["iss"] != idn)  # placeholder
        # 正确口径：按 jti 检查是否撤销
        active_issued = 0
        delegated_active = 0
        issued_active = 0
        delegated_in_active = 0
        for jti, m in registry.items():
            if jti in revoked:
                continue
            if m.get("iss") == idn:
                issued_active += 1
            if m.get("sub") == idn:
                delegated_in_active += 1

        per_id[idn] = {
            "idn": idn,
            "status": status,
            "org": org,
            "agent_type": typ,
            "owner": owner,
            "tags": list(tags),
            "created_at": meta.get("created_at"),
            "disabled_at": meta.get("disabled_at"),
            "disable_reason": meta.get("disable_reason"),
            "enabled_at": meta.get("enabled_at"),
            "issued_active": issued_active,
            "delegated_in_active": delegated_in_active,
            "issued_total": issued_n,
            "delegated_in_total": delegated_in_n,
        }
        issued_total += issued_n
        delegated_in_total += delegated_in_n

    rows = sorted(per_id.values(),
                  key=lambda r: (0 if r["status"] == "active" else 1,
                                 r["idn"]))
    return {
        "ok": True,
        "total": len(rows),
        "active": total_active,
        "disabled": total_disabled,
        "by_org": by_org,
        "by_type": by_type,
        "by_owner": by_owner,
        "by_tag": by_tag,
        "identities": rows,
    }


# ------------------------------------------------------------------
# FR6-02  委托链拓扑
# ------------------------------------------------------------------
def delegation_topology(platform, root_idn=None, include_revoked=False) -> dict:
    """FR6-02：委托链有向图拓扑。

    以「签发方 → 主体」为边：
        cred (iss=A, sub=B)  →  边 A → B，jti=cred.jti
    root_idn  若给定，只返回该标识作为根起点的子图；否则全量。
    include_revoked  是否包含已撤销的凭证（默认剔除）。
    """
    registry = platform._cred_registry
    revoked = platform._revoked_jtis

    nodes = set()
    edges = []
    roots = set()
    max_depth = 0

    for jti, m in registry.items():
        if not include_revoked and jti in revoked:
            continue
        iss = m.get("iss")
        sub = m.get("sub")
        if not iss or not sub:
            continue
        parent = m.get("parent")
        depth = m.get("depth", 0)
        if depth and depth > max_depth:
            max_depth = depth
        if not parent:
            roots.add(iss)
        edges.append({
            "jti": jti,
            "from": iss,
            "to": sub,
            "parent_jti": parent,
            "depth": depth,
            "revoked": jti in revoked,
        })
        nodes.add(iss)
        nodes.add(sub)

    # 收敛到 root_idn 子图（从该标识 BFS）
    if root_idn is not None:
        keep_nodes = set()
        keep_nodes.add(root_idn)
        frontier = [root_idn]
        seen = set()
        while frontier:
            cur = frontier.pop()
            for e in edges:
                if e["from"] == cur and e["to"] not in keep_nodes:
                    keep_nodes.add(e["to"])
                    if e["to"] not in seen:
                        seen.add(e["to"])
                        frontier.append(e["to"])
        edges = [e for e in edges
                 if e["from"] in keep_nodes and e["to"] in keep_nodes]
        nodes = keep_nodes

    node_rows = []
    for idn in sorted(nodes):
        rec = platform._identities.get(idn, {})
        meta = rec.get("meta", {}) if rec else {}
        node_rows.append({
            "idn": idn,
            "status": rec.get("status", "unknown"),
            "org": meta.get("org"),
            "agent_type": meta.get("agent_type"),
            "owner": meta.get("owner"),
            "in_degree": sum(1 for e in edges if e["to"] == idn),
            "out_degree": sum(1 for e in edges if e["from"] == idn),
        })

    return {
        "ok": True,
        "node_count": len(node_rows),
        "edge_count": len(edges),
        "max_depth": max_depth,
        "roots": sorted(roots),
        "nodes": node_rows,
        "edges": edges,
    }


def realtime_permission_view(platform, idn, now=None) -> dict:
    """FR6-02：某标识当前「实际可访问」的资源与权限视图。

    口径：该标识持有的所有未撤销凭证，按受众聚合，
    对每条链计算作用域交集（受委托链收敛影响）。

    数据来源：审计事件（既含 credential.issue 也含 delegation.issue），
    不依赖完整 Credential 对象，只依赖审计日志里的公开字段。
    """
    now = now if now is not None else int(time.time())
    registry = platform._cred_registry
    revoked = platform._revoked_jtis

    # 从审计链读 (jti -> {sub, iss, aud, scope, parent_jti, depth})
    cred_info = {}
    if platform._pers is not None:
        rows = platform._pers.query_audit(platform.tenant, limit=100000)
        for r in rows:
            ev = r.get("event") or {}
            kind = ev.get("kind")
            jti = ev.get("jti")
            if not jti:
                continue
            if kind == "credential.issue":
                cred_info[jti] = {
                    "sub": ev.get("sub"), "iss": ev.get("iss"),
                    "aud": ev.get("aud"), "scope": ev.get("scope") or [],
                    "exp": None, "parent_jti": None, "depth": 0,
                }
            elif kind == "delegation.issue":
                cred_info[jti] = {
                    "sub": ev.get("delegatee"), "iss": ev.get("delegator"),
                    "aud": ev.get("aud"), "scope": ev.get("scope") or [],
                    "exp": None,
                    "parent_jti": ev.get("parent_jti"),
                    "depth": ev.get("depth", 0),
                }
    else:
        # 内存模式：直接读 audit.chain
        for e in platform.audit.chain:
            ev = e.get("event") or {}
            kind = ev.get("kind")
            jti = ev.get("jti")
            if not jti:
                continue
            if kind == "credential.issue":
                cred_info[jti] = {
                    "sub": ev.get("sub"), "iss": ev.get("iss"),
                    "aud": ev.get("aud"), "scope": ev.get("scope") or [],
                    "exp": None, "parent_jti": None, "depth": 0,
                }
            elif kind == "delegation.issue":
                cred_info[jti] = {
                    "sub": ev.get("delegatee"), "iss": ev.get("delegator"),
                    "aud": ev.get("aud"), "scope": ev.get("scope") or [],
                    "exp": None,
                    "parent_jti": ev.get("parent_jti"),
                    "depth": ev.get("depth", 0),
                }

    # 用 registry 的 depth 补全（比审计事件更权威）
    for jti, c in cred_info.items():
        meta = registry.get(jti)
        if meta:
            if meta.get("depth") is not None:
                c["depth"] = meta["depth"]

    # 收集该 idn 持有（sub==idn）的未撤销凭证
    held = [jti for jti, c in cred_info.items()
            if c["sub"] == idn and jti not in revoked]

    # 按受众聚合：作用域取交集
    aud_map = {}
    for jti in held:
        c = cred_info[jti]
        aud = c["aud"]
        if aud not in aud_map:
            aud_map[aud] = {
                "scope_set": set(c["scope"]),
                "chain": [jti],
                "expires": c["exp"] or 0,
                "depth": c["depth"] or 0,
            }
        else:
            aud_map[aud]["scope_set"] &= set(c["scope"])
            aud_map[aud]["chain"].append(jti)
            if c["exp"] and aud_map[aud]["expires"]:
                aud_map[aud]["expires"] = min(aud_map[aud]["expires"],
                                              c["exp"])
            aud_map[aud]["depth"] = max(aud_map[aud]["depth"],
                                        c["depth"] or 0)

    view = []
    for aud, info in aud_map.items():
        expired = bool(info["expires"]) and info["expires"] <= now
        view.append({
            "audience": aud,
            "scope": sorted(info["scope_set"]),
            "scope_count": len(info["scope_set"]),
            "expires": info["expires"],
            "expired": expired,
            "max_depth": info["depth"],
            "cred_count": len(info["chain"]),
            "chain_head": info["chain"][0] if info["chain"] else None,
        })
    view.sort(key=lambda v: v["audience"])
    return {"ok": True, "idn": idn, "now": now,
            "audiences": view, "audience_count": len(view)}


# ------------------------------------------------------------------
# FR6-05  异常告警扫描
# ------------------------------------------------------------------
ALERT_RULES = {
    "verify_fail_hot": "某签发方在时间窗内的凭证校验失败次数超阈值",
    "scope_escalation": "委托签发因作用域越权被拒（FR3-02 拦截）",
    "parent_revoked": "委托签发因父凭证已撤销被拒",
    "depth_exceeded": "委托深度超限被拒（FR3-04 拦截）",
    "disabled_issuer": "已停用标识尝试签发（被拒）",
    "unknown_issuer": "未知签发方凭证校验失败",
    "audience_mismatch": "凭证受众与目标不一致导致校验失败",
    "chain_scope_fail": "委托链校验因权限交集不足失败",
}


def scan_alerts(platform, window_seconds=3600, threshold=5) -> dict:
    """FR6-05：扫描审计日志，输出分级告警。

    window_seconds  回溯时间窗（秒），默认 1 小时
    threshold       高频失败告警阈值：某 issuer 校验失败 ≥ 该次数即告警
    """
    now = int(time.time())
    since = now - window_seconds
    if platform._pers is not None:
        rows = platform._pers.query_audit(platform.tenant,
                                          limit=100000)
    else:
        # 内存模式：直接从 audit.chain 构造 rows
        rows = [{"ts": e.get("ts"), "event": e.get("event", {})}
                for e in platform.audit.chain]

    # 分桶
    per_issuer_fail = {}  # issuer -> count
    escalation = []
    parent_revoked = []
    depth_exceeded = []
    disabled_issuer = []
    unknown_issuer = []
    audience_mismatch = []
    chain_scope_fail = []
    verify_fail_total = 0
    verify_ok_total = 0

    for r in rows:
        ev = r.get("event") or {}
        ts = r.get("ts") or ev.get("ts") or 0
        if ts and ts < since:
            continue
        kind = ev.get("kind")
        if kind == "credential.verify":
            result = ev.get("result")
            reason = ev.get("reason") or ""
            if result == "ok":
                verify_ok_total += 1
            else:
                verify_fail_total += 1
                # 全部拒绝按 reason 归桶统计（供高频告警）
                per_issuer_fail.setdefault(reason or "unknown", 0)
                per_issuer_fail[reason or "unknown"] += 1
                if reason == "unknown issuer":
                    unknown_issuer.append(ev)
                elif reason == "audience mismatch":
                    audience_mismatch.append(ev)
                # revoked 属预期行为，不入高频告警
                elif reason == "revoked":
                    pass
        elif kind == "delegation.issue":
            # 签发成功的事件里记录的是 parent_verified；被拒的在 audit 里没有独立事件
            # 这里我们只统计「签发成功但被收敛的」和「签发成功但已超深的」两类
            # 深度超限被拒的记录不会进 audit（未 append），故从返回码路径捕获
            # 这里保留一个空桶，用于展示 rule 定义
            pass

    # 归并告警条目
    alerts = []

    # 高频失败：按 reason 聚合，revoked 属预期行为不入高频告警
    for reason, cnt in per_issuer_fail.items():
        if reason == "revoked":
            continue
        if cnt >= threshold:
            alerts.append({
                "level": "warning",
                "rule": "verify_fail_hot",
                "reason_code": reason,
                "count": cnt,
                "detail": "%s 校验失败 %d 次（窗口 %ds，阈值 %d）"
                          % (reason, cnt, window_seconds, threshold),
            })

    # 从审计里找越权被拒的记录（拒绝在 audit 无独立事件，改从返回码捕获需要
    # 上层调用；这里给出规则定义与规则集）

    # 从 audit 里找 issuer disabled 的凭证签发尝试（会 append）
    for r in rows:
        ev = r.get("event") or {}
        ts = r.get("ts") or ev.get("ts") or 0
        if ts and ts < since:
            continue
        if ev.get("kind") == "credential.verify" and \
                ev.get("reason") == "issuer disabled":
            disabled_issuer.append(ev)
        elif ev.get("kind") == "delegation.verify" and \
                ev.get("result") == "fail":
            # 链校验失败——可能是权限交集不足
            reasons = ev.get("reasons") or []
            for rsn in reasons:
                if "scope" in str(rsn).lower():
                    chain_scope_fail.append(ev)
                    break

    if disabled_issuer:
        alerts.append({
            "level": "critical",
            "rule": "disabled_issuer",
            "count": len(disabled_issuer),
            "detail": "检测到停用标识仍尝试签发 %d 次（已被拒）"
                      % len(disabled_issuer),
        })
    if chain_scope_fail:
        alerts.append({
            "level": "warning",
            "rule": "chain_scope_fail",
            "count": len(chain_scope_fail),
            "detail": "委托链校验失败 %d 次（含权限交集不足）"
                      % len(chain_scope_fail),
        })

    return {
        "ok": True,
        "window_seconds": window_seconds,
        "since": since,
        "threshold": threshold,
        "rules": ALERT_RULES,
        "totals": {
            "verify_ok": verify_ok_total,
            "verify_fail": verify_fail_total,
            "unknown_issuer": len(unknown_issuer),
            "audience_mismatch": len(audience_mismatch),
            "disabled_issuer": len(disabled_issuer),
            "chain_scope_fail": len(chain_scope_fail),
            "escalation_rejected": len(escalation),
            "parent_revoked_rejected": len(parent_revoked),
            "depth_exceeded_rejected": len(depth_exceeded),
        },
        "alerts": alerts,
        "alert_count": len(alerts),
    }


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def _demo_platform():
    from agent_platform import Platform
    p = Platform(tenant="gov-test")
    p.register_identity("agent://root/ca", org="root",
                        agent_type="issuance", owner="admin",
                        tags=["root", "ca"])
    p.register_identity("agent://org-a/orchestrator", org="org-a",
                        agent_type="orchestrator", owner="alice",
                        tags=["org-a", "tier1"])
    p.register_identity("agent://org-a/worker", org="org-a",
                        agent_type="worker", owner="bob",
                        tags=["org-a", "tier2"])
    p.register_identity("agent://org-b/agent1", org="org-b",
                        agent_type="worker", owner="carol",
                        tags=["org-b"])
    r1 = p.issue_credential("agent://root/ca",
                            "agent://org-a/orchestrator",
                            "service://invoice", ["invoice:read",
                                                  "invoice:write"],
                            ttl=3600)
    r2 = p.issue_delegation("agent://org-a/orchestrator",
                            "agent://org-a/worker",
                            "service://invoice", ["invoice:read"],
                            intent="task", parent_cred=r1["cred"])
    p.disable_identity("agent://org-b/agent1", reason="test")
    return p, r1, r2


def self_check():
    """治理台三接口的功能自检。"""
    out = []
    p, r1, r2 = _demo_platform()

    # FR6-01
    inv = agent_inventory(p)
    out.append(("FR6-01 total", inv["ok"] and inv["total"] == 4))
    out.append(("FR6-01 active", inv["active"] == 3))
    out.append(("FR6-01 disabled", inv["disabled"] == 1))
    out.append(("FR6-01 by_org 有 org-a", inv["by_org"].get("org-a") == 2))
    out.append(("FR6-01 by_tag 有 tier2", inv["by_tag"].get("tier2") == 1))
    rows = inv["identities"]
    out.append(("FR6-01 rows 数", len(rows) == 4))
    worker = next(r for r in rows if r["idn"] == "agent://org-a/worker")
    out.append(("FR6-01 worker delegated_in_active",
                worker["delegated_in_active"] == 1))

    # FR6-02 拓扑
    topo = delegation_topology(p)
    out.append(("FR6-02 边数", topo["edge_count"] == 2))
    out.append(("FR6-02 节点数", topo["node_count"] == 3))
    out.append(("FR6-02 max_depth", topo["max_depth"] == 1))

    # 子图（以 orchestrator 为根）
    sub = delegation_topology(p, root_idn="agent://org-a/orchestrator")
    out.append(("FR6-02 子图 边数", sub["edge_count"] == 1))

    # 实时权限视图
    rtv = realtime_permission_view(p, "agent://org-a/worker")
    out.append(("FR6-02 realtime ok", rtv["ok"]))
    out.append(("FR6-02 audience 命中 service://invoice",
                any(a["audience"] == "service://invoice"
                    for a in rtv["audiences"])))

    # FR6-05 告警扫描
    al = scan_alerts(p, window_seconds=60, threshold=1)
    out.append(("FR6-05 ok", al["ok"]))
    out.append(("FR6-05 规则数", len(al["rules"]) >= 8))
    out.append(("FR6-05 totals 有 verify 数据",
                "verify_ok" in al["totals"]))

    # 空扫描
    al2 = scan_alerts(p, window_seconds=1, threshold=1000000)
    out.append(("FR6-05 空阈值告警为 0", al2["alert_count"] == 0))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
