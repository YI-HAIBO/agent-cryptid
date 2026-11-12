# -*- coding: utf-8 -*-
"""端到端 demo：从注册标识 → 签发凭证 → 委托 → 服务调用 → 撤销 → 审计。

场景（对齐《技术方案》6 类角色场景之一：企业内多智能体协作）：

    1. Admin 在 Platform 上注册 CA 与三个业务智能体。
    2. CA 给"编排智能体 A"签发根凭证（可读取发票服务）。
    3. A 把权限委托给"工作智能体 B"，B 把权限再委托给"外部智能体 C"。
    4. C 携带完整委托链调用发票服务，服务校验链并返回数据。
    5. Admin 发现 A 疑似泄露，撤销 A 的根凭证。
    6. C 再用同一链调用失败；Admin 从审计日志查到完整链路。
    7. 客户端按版本号拉取增量撤销快照，本地缓存同步。

运行：
    python demo.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform  # noqa: E402
from runtime import Agent, Service  # noqa: E402


AUD = "service://invoice"
SCOPE = ["invoice:read", "invoice:list"]


def _step(title):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main():
    plat = Platform(tenant="demo-tenant")
    invoice = Service(AUD, allowed_scopes=["invoice:read",
                                            "invoice:list",
                                            "invoice:write"],
                      description="发票服务（Mock）")

    _step("步骤 1｜Admin 在 Platform 注册标识")
    r = plat.register_identity("agent://root/ca", org="root",
                               agent_type="issuance-authority",
                               owner="admin")
    print("  CA 注册：%s（pub_x=%s…）" % ("OK" if r["ok"] else "FAIL",
                                        r["pub_x"][:12]))
    for idn in ["agent://org-a/orchestrator",
                "agent://org-a/worker",
                "agent://org-c/external"]:
        r = plat.register_identity(idn, org=idn.split("/")[1],
                                   agent_type="worker", owner="admin")
        print("  %-30s 注册：%s" % (idn, "OK" if r["ok"] else "FAIL"))

    _step("步骤 2｜CA 给编排智能体 A 签发根凭证")
    ca = Agent("agent://root/ca")
    a = Agent("agent://org-a/orchestrator", name="A-编排")
    b = Agent("agent://org-a/worker", name="B-工作")
    c = Agent("agent://org-c/external", name="C-外部")

    r = plat.issue_credential("agent://root/ca", "agent://org-a/orchestrator",
                              AUD, SCOPE, ttl=3600)
    print("  签发根凭证：%s（jti=%s）" % ("OK" if r["ok"] else "FAIL",
                                        r["jti"][:12]))
    root_cred = r["cred"]
    a.receive(root_cred)
    print("  A 现有凭证数：%d" % len(a.creds))

    _step("步骤 3｜A 委托给 B；B 再委托给 C（三跳链）")
    r = plat.issue_delegation("agent://org-a/orchestrator",
                              "agent://org-a/worker",
                              AUD, SCOPE, intent="处理发票")
    cred_ab = r["cred"]
    b.receive(cred_ab)
    print("  A→B 委托：%s（jti=%s）" % ("OK" if r["ok"] else "FAIL",
                                       r["jti"][:12]))

    r = plat.issue_delegation("agent://org-a/worker",
                              "agent://org-c/external",
                              AUD, SCOPE, intent="外包处理")
    cred_bc = r["cred"]
    c.receive(cred_bc)
    print("  B→C 委托：%s（jti=%s）" % ("OK" if r["ok"] else "FAIL",
                                       r["jti"][:12]))

    chain = [root_cred, cred_ab, cred_bc]

    _step("步骤 4｜C 携带完整链调用发票服务")
    res = c.call_service(invoice, SCOPE, plat, chain_wires=chain)
    print("  调用结果：%s" % ("成功" if res["ok"] else "失败"))
    print("  服务返回：%s" % res.get("data"))

    _step("步骤 5｜Admin 撤销 A 的根凭证（怀疑泄露）")
    r = plat.revoke(root_cred["jti"], reason="suspected leak")
    print("  撤销结果：%s（版本 v%d）" % ("OK" if r["ok"] else "FAIL",
                                        r["version"]))

    _step("步骤 6｜C 再用同一链调用 —— 应被拒绝")
    res = c.call_service(invoice, SCOPE, plat, chain_wires=chain)
    print("  调用结果：%s" % ("成功" if res["ok"] else "失败（已撤销）"))
    print("  原因：%s" % res.get("reason"))

    _step("步骤 7｜客户端按版本号拉取增量撤销快照")
    snap = plat.revocation_snapshot(since_version=0)
    print("  当前版本：v%d，累计撤销：%d" % (snap["current_version"],
                                            snap["total_revoked"]))
    for e in snap["entries"]:
        print("  - v%d jti=%s 原因=%s" % (e["version"], e["jti"][:12],
                                          e["reason"]))

    _step("步骤 8｜Admin 从审计日志检索全链路")
    q = plat.audit_query(limit=20)
    print("  审计链长度：%d，完整性：%s" % (q["chain_length"],
                                          "OK" if q["chain_valid"] else "BROKEN"))
    print("  根哈希：%s" % (q["chain_root_hash"][:24] + "…"))
    kinds = {}
    for r in q["records"]:
        k = r["event"].get("kind", "?")
        kinds[k] = kinds.get(k, 0) + 1
    for k, v in kinds.items():
        print("  - %-25s × %d" % (k, v))

    _step("步骤 9｜权限越权尝试：C 试图获取 invoice:write")
    res = c.call_service(invoice, ["invoice:write"], plat, chain_wires=chain)
    print("  调用结果：%s（越权被拒）" % ("成功" if res["ok"] else "失败"))

    _step("步骤 10｜配置策略：把 max_ttl 缩短到 1 小时")
    r = plat.configure_policy({"max_ttl_seconds": 3600})
    print("  策略：%s（max_ttl=%d 秒）" % ("OK" if r["ok"] else "FAIL",
                                          r["policy"]["max_ttl_seconds"]))

    _step("完整演示结束")
    total = len(invoice.calls)
    ok_count = sum(1 for c in invoice.calls if c["action"] == "executed")
    rej_count = total - ok_count
    print("  注册标识数：%d" % (len(plat._identities)))
    print("  服务调用数：%d（%d 成功，%d 被拒）" % (total, ok_count, rej_count))
    print("  审计记录数：%d，链完整：%s" % (
        plat.audit.count(), plat.audit.verify()[0]))


if __name__ == "__main__":
    main()
