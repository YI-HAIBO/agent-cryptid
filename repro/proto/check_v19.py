# -*- coding: utf-8 -*-
"""v2.14 集成测试：FR7-03 智能体卡片签名扩展 + FR7-04 编排框架插件。

通过 http_api.route() 走真实路由分发，覆盖：
    · FR7-03 卡片签名 / 验签 / 篡改检测 / 撤销感知 / 发布与拉取
    · FR7-04 工具登记 / 鉴权决策 / 作用域 / 受众 / 委托链 / 跨租户隔离

测试策略：直接调用 http_api.route()，不起真实 socket 服务器。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http_api import route, TenantPool


def _pool():
    return TenantPool(db_path=":memory:", default_tenant="default")


def _r(pool, method, path, body=None, tenant="t1", query=None):
    """走真实路由分发。返回 (status, payload)。"""
    return route(pool, method, path, query or {}, body, tenant, None)


def self_check():
    out = []

    # ==================================================================
    # [A] FR7-03 卡片签名：HTTP 路由
    # ==================================================================
    p = _pool()
    _r(p, "POST", "/v1/identities", {"idn": "agent://acme/ops",
                                     "org": "acme"}, tenant="t1")
    _r(p, "POST", "/v1/identities", {"idn": "agent://acme/ca",
                                     "org": "acme"}, tenant="t1")

    # 签一张凭证，卡片绑它（撤销依据）
    st, r = _r(p, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/ca",
                "subject_idn": "agent://acme/ops",
                "audience": "svc://card", "scope": ["card:publish"],
                "ttl": 3600}, tenant="t1")
    out.append(("A.1 前置凭证签发成功", st == 200 and r.get("ok") is True))
    card_jti = r.get("jti")

    # A2-A4 签名
    st, r = _r(p, "POST", "/v1/agent-cards/sign",
               {"card": {
                   "agent_idn": "agent://acme/ops",
                   "name": "Ops Agent",
                   "url": "https://ops.acme.example",
                   "version": "1.0",
                   "capabilities": ["streaming"],
                   "skills": [{"id": "restart", "name": "重启服务"}],
               },
                   "issuer_idn": "agent://acme/ops",
                   "jti": card_jti},
               tenant="t1")
    out.append(("A.2 卡片签名返回 ok", st == 200 and r.get("ok") is True))
    signed_card = r.get("card")
    out.append(("A.3 含签名扩展",
                "x-cryptid-signature" in (signed_card or {})))
    out.append(("A.4 绑定 jti 正确",
                signed_card.get("x-cryptid-signature", {}).get("jti")
                == card_jti))

    # A5-A6 验签
    st, r = _r(p, "POST", "/v1/agent-cards/verify",
               {"card": signed_card}, tenant="t1")
    out.append(("A.5 验签端点返回 ok", st == 200 and r.get("ok") is True))
    out.append(("A.6 卡片有效", r.get("valid") is True))

    # A7-A8 篡改检测
    tampered = dict(signed_card)
    tampered["name"] = "Evil Agent"
    st, r = _r(p, "POST", "/v1/agent-cards/verify",
               {"card": tampered}, tenant="t1")
    out.append(("A.7 篡改后 valid=False", r.get("valid") is False))
    out.append(("A.8 篡改原因合理",
                r.get("reason") in ("card tampered", "signature invalid")))

    # A9-A10 主体绑定
    st, r = _r(p, "POST", "/v1/agent-cards/verify",
               {"card": signed_card,
                "expected_subject": "agent://acme/ops"}, tenant="t1")
    out.append(("A.9 期望主体一致有效", r.get("valid") is True))
    st, r = _r(p, "POST", "/v1/agent-cards/verify",
               {"card": signed_card,
                "expected_subject": "agent://other/x"}, tenant="t1")
    out.append(("A.10 期望主体不符失效", r.get("valid") is False))

    # A11 缺 agent_idn 被拒
    st, r = _r(p, "POST", "/v1/agent-cards/sign",
               {"card": {"name": "No Idn"}}, tenant="t1")
    out.append(("A.11 缺 agent_idn 被拒",
                st == 400 and r.get("ok") is False))

    # ==================================================================
    # [B] FR7-03 卡片发布与拉取
    # ==================================================================
    st, r = _r(p, "POST", "/v1/agent-cards",
               {"card": {
                   "agent_idn": "agent://acme/ops",
                   "name": "Ops Agent",
                   "url": "https://ops.acme.example",
                   "skills": [{"id": "restart"}],
               },
                   "issuer_idn": "agent://acme/ops",
                   "jti": card_jti},
               tenant="t1")
    out.append(("B.1 发布卡片成功", st == 200 and r.get("ok") is True))

    st, r = _r(p, "GET", "/v1/agent-cards", tenant="t1")
    out.append(("B.2 列出卡片返回 ok", st == 200 and r.get("ok") is True))
    out.append(("B.3 卡片库含 1 张", r.get("total") == 1))

    st, r = _r(p, "GET", "/v1/agent-cards/detail",
               tenant="t1", query={"agent_idn": ["agent://acme/ops"]})
    out.append(("B.4 按 idn 查到卡片", st == 200 and r.get("ok") is True))
    out.append(("B.5 返回含签名",
                "x-cryptid-signature" in (r.get("card") or {})))

    st, r = _r(p, "GET", "/v1/agent-cards/detail", tenant="t1")
    out.append(("B.6 缺 agent_idn 被拒",
                st == 400 and r.get("ok") is False))

    st, r = _r(p, "GET", "/v1/agent-cards/well-known", tenant="t1")
    out.append(("B.7 well-known 返回卡片",
                st == 200 and r.get("agent_idn") == "agent://acme/ops"))

    # 跨租户：t2 无卡片
    st, r = _r(p, "GET", "/v1/agent-cards", tenant="t2")
    out.append(("B.8 跨租户卡片库为空", st == 200 and r.get("total") == 0))

    # ==================================================================
    # [C] FR7-03 撤销感知（卡片随凭证撤销而失效）
    # ==================================================================
    st, r = _r(p, "POST", "/v1/revocations",
               {"jti": card_jti, "reason": "key compromise"},
               tenant="t1")
    out.append(("C.1 撤销凭证成功", st == 200 and r.get("ok") is True))

    st, r = _r(p, "POST", "/v1/agent-cards/verify",
               {"card": signed_card}, tenant="t1")
    out.append(("C.2 凭证撤销后卡片失效", r.get("valid") is False))
    out.append(("C.3 失效原因是 revoked", r.get("reason") == "revoked"))

    # ==================================================================
    # [D] FR7-04 编排插件：工具登记
    # ==================================================================
    p2 = _pool()
    _r(p2, "POST", "/v1/identities", {"idn": "agent://acme/orch",
                                      "org": "acme"}, tenant="d1")
    _r(p2, "POST", "/v1/identities", {"idn": "agent://acme/worker",
                                      "org": "acme"}, tenant="d1")

    st, r = _r(p2, "POST", "/v1/orchestrator/tools",
               {"audience": "orch://bot", "name": "restart_service",
                "scopes": ["ops:restart"], "description": "重启服务"},
               tenant="d1")
    out.append(("D.1 登记工具成功", st == 200 and r.get("ok") is True))
    out.append(("D.2 返回所需作用域",
                r.get("required_scope") == ["ops:restart"]))

    st, r = _r(p2, "POST", "/v1/orchestrator/tools",
               {"name": "no_audience"}, tenant="d1")
    out.append(("D.3 缺 audience 被拒",
                st == 400 and r.get("ok") is False))

    st, r = _r(p2, "GET", "/v1/orchestrator/tools",
               tenant="d1", query={"audience": ["orch://bot"]})
    out.append(("D.4 列出工具返回 ok", st == 200 and r.get("ok") is True))
    out.append(("D.5 含 restart_service",
                "restart_service" in (r.get("tools") or {})))
    out.append(("D.6 工具带作用域元数据",
                (r.get("tools", {}).get("restart_service") or {})
                .get("required_scope") == ["ops:restart"]))

    st, r = _r(p2, "GET", "/v1/orchestrator/tools", tenant="d1")
    out.append(("D.7 缺 audience 被拒",
                st == 400 and r.get("ok") is False))

    # ==================================================================
    # [E] FR7-04 鉴权决策
    # ==================================================================
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://bot", "scope": ["ops:restart"],
                "ttl": 3600}, tenant="d1")
    out.append(("E.1 前置凭证签发成功", st == 200 and r.get("ok") is True))
    cred = r.get("cred")

    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "restart_service",
                "arguments": {"name": "nginx"}, "credential": cred},
               tenant="d1")
    out.append(("E.2 作用域足够放行", r.get("allow") is True))
    out.append(("E.3 sub 为执行者", r.get("sub") == "agent://acme/worker"))
    out.append(("E.4 act 有值（防混淆代理人）", r.get("act") is not None))

    # E5 无凭证
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "restart_service",
                "arguments": {"name": "x"}}, tenant="d1")
    out.append(("E.5 无凭证被拒",
                r.get("allow") is False
                and r.get("reason") == "missing credential"))

    # E6 缺 audience
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"tool": "restart_service", "credential": cred}, tenant="d1")
    out.append(("E.6 缺 audience 被拒",
                st == 400 and r.get("ok") is False))

    # E7 作用域不足
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://bot", "scope": ["ops:read"],
                "ttl": 3600}, tenant="d1")
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "restart_service",
                "arguments": {"name": "y"}, "credential": r.get("cred")},
               tenant="d1")
    out.append(("E.7 作用域不足被拒", r.get("allow") is False))
    out.append(("E.8 原因含 insufficient scope",
                "insufficient scope" in (r.get("reason") or "")))

    # E9 受众不符（跨服务挪用）
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://other", "scope": ["ops:restart"],
                "ttl": 3600}, tenant="d1")
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "restart_service",
                "arguments": {"name": "z"}, "credential": r.get("cred")},
               tenant="d1")
    out.append(("E.9 受众不符被拒", r.get("allow") is False))

    # E10-E11 防重放
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://bot", "scope": ["ops:restart"],
                "ttl": 3600}, tenant="d1")
    c_rep = r.get("cred")
    st, r1 = _r(p2, "POST", "/v1/orchestrator/guard",
                {"audience": "orch://bot", "tool": "restart_service",
                 "arguments": {"name": "dup"}, "credential": c_rep},
                tenant="d1")
    st, r2 = _r(p2, "POST", "/v1/orchestrator/guard",
                {"audience": "orch://bot", "tool": "restart_service",
                 "arguments": {"name": "dup"}, "credential": c_rep},
                tenant="d1")
    out.append(("E.10 首次放行", r1.get("allow") is True))
    out.append(("E.11 同参数重放被拒",
                r2.get("allow") is False
                and r2.get("reason") == "replay detected"))

    # E12 未登记工具且无 required_scope
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "ghost_tool",
                "credential": cred}, tenant="d1")
    out.append(("E.12 未登记且无 scope 被拒",
                st == 400 and r.get("ok") is False))

    # E13-E14 未登记工具但显式给 scope（按需登记）
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://bot", "scope": ["ops:deploy"],
                "ttl": 3600}, tenant="d1")
    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "deploy",
                "arguments": {"v": "1.0"},
                "required_scope": ["ops:deploy"],
                "credential": r.get("cred")}, tenant="d1")
    out.append(("E.13 显式 scope 放行", r.get("allow") is True))
    st, r = _r(p2, "GET", "/v1/orchestrator/tools",
               tenant="d1", query={"audience": ["orch://bot"]})
    out.append(("E.14 按需登记后可见", "deploy" in (r.get("tools") or {})))

    # ==================================================================
    # [F] FR7-04 委托链与跨租户
    # ==================================================================
    _r(p2, "POST", "/v1/identities", {"idn": "agent://acme/sub",
                                      "org": "acme"}, tenant="d1")
    st, r = _r(p2, "POST", "/v1/credentials",
               {"issuer_idn": "agent://acme/orch",
                "subject_idn": "agent://acme/worker",
                "audience": "orch://bot",
                "scope": ["ops:restart", "ops:delete"], "ttl": 7200},
               tenant="d1")
    root = r.get("cred")
    st, r = _r(p2, "POST", "/v1/delegations",
               {"delegator_idn": "agent://acme/worker",
                "delegatee_idn": "agent://acme/sub",
                "audience": "orch://bot", "scope": ["ops:restart"],
                "parent_cred": root, "ttl": 3600}, tenant="d1")
    out.append(("F.1 委托签发成功", st == 200 and r.get("ok") is True))
    chain = [root, r.get("cred")]
    _r(p2, "POST", "/v1/orchestrator/tools",
       {"audience": "orch://bot", "name": "delete_all",
        "scopes": ["ops:delete"]}, tenant="d1")

    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "restart_service",
                "arguments": {"name": "chain"}, "chain": chain},
               tenant="d1")
    out.append(("F.2 持链调用放行", r.get("allow") is True))
    out.append(("F.3 sub 为末端执行者", r.get("sub") == "agent://acme/sub"))
    out.append(("F.4 act 为发起方", r.get("act") == "agent://acme/worker"))

    st, r = _r(p2, "POST", "/v1/orchestrator/guard",
               {"audience": "orch://bot", "tool": "delete_all",
                "arguments": {}, "chain": chain}, tenant="d1")
    out.append(("F.5 链上无删除权限被拒", r.get("allow") is False))

    # F6 跨租户工具隔离
    st, r = _r(p2, "GET", "/v1/orchestrator/tools",
               tenant="d2", query={"audience": ["orch://bot"]})
    out.append(("F.6 跨租户工具为空",
                st == 200 and r.get("total") == 0))

    # ==================================================================
    # [G] 模块自测汇总（直调模块 self_check）
    # ==================================================================
    from agent_card import self_check as card_check
    from orchestrator_plugin import self_check as plug_check
    cc = card_check()
    out.append(("G.1 卡片模块自测全通过",
                all(ok for _, ok in cc)))
    pc = plug_check()
    out.append(("G.2 插件模块自测全通过",
                all(ok for _, ok in pc)))
    out.append(("G.3 卡片模块用例数 >= 20", len(cc) >= 20))
    out.append(("G.4 插件模块用例数 >= 30", len(pc) >= 30))

    # ==================================================================
    # 汇总
    # ==================================================================
    pass_count = sum(1 for _, ok in out if ok)
    fail_count = sum(1 for _, ok in out if not ok)
    print("\n" + "=" * 60)
    print("v2.14 集成测试：FR7-03 智能体卡片签名 + FR7-04 编排框架插件")
    print("=" * 60)
    for name, ok in out:
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
    print("-" * 60)
    print("RESULT  PASS=%d  FAIL=%d" % (pass_count, fail_count))
    print("=" * 60)

    report_path = os.path.join(
        os.path.dirname(__file__), "check_v19_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        for name, ok in out:
            f.write("%-8s %s\n" % ("PASS" if ok else "FAIL", name))
        f.write("\nRESULT  PASS=%d  FAIL=%d\n" % (pass_count, fail_count))

    return out


if __name__ == "__main__":
    self_check()
