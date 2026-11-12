# -*- coding: utf-8 -*-
"""生成一份示例合规报表（FR5-05 / NFR-11）。

跑一段完整业务（注册 → 签发 → 校验 → 委托 → 工具鉴权 → 撤销 → 锚定），
再导出对齐 GB/T 39786 的合规报表三件套（Markdown / JSON / CSV）。

用法：
    python compliance_demo.py [输出目录]
缺省输出到 ../合规报表示例/
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from credential import ALG_SM2, ALG_SM9
from mcp_adapter import MCPAuthzAdapter
from compliance_report import ComplianceReport

TENANT = "demo"
AUD = "service://invoice"
MCP_AUD = "mcp://fileserver"


def build_business():
    """构造一段完整业务，产生可被密评采信的证据。"""
    p = Platform(tenant=TENANT)
    ids = ["agent://acme/root-ca", "agent://acme/orchestrator",
           "agent://acme/worker"]
    for idn in ids:
        p.register_identity(idn, org="acme", agent_type="worker",
                            owner="ops@acme")
    p.configure_policy({"allowed_algs": [ALG_SM2, ALG_SM9],
                        "max_ttl_seconds": 3600})

    # 1) 根凭证（SM2）→ 校验
    r0 = p.issue_credential(ids[0], ids[1], AUD,
                            ["invoice:read", "invoice:list"], ttl=3600)
    p.verify_credential(r0["cred"], audience=AUD)

    # 2) 委托（出示父凭证，作用域收敛）→ 链验证
    r1 = p.issue_delegation(ids[1], ids[2], AUD, ["invoice:read"],
                            ttl=3600, intent="月度对账子任务",
                            parent_cred=r0["cred"])
    p.verify_delegation_chain([r0["cred"], r1["cred"]], AUD,
                              ["invoice:read"])

    # 3) 无证书标识身份（SM9）走一遍
    r2 = p.issue_credential(ids[0], ids[1], AUD, ["invoice:read"],
                            ttl=3600, alg_tier=ALG_SM9)
    p.verify_credential(r2["cred"], audience=AUD)

    # 4) MCP 工具调用鉴权
    authz = MCPAuthzAdapter(p, audience=MCP_AUD,
                            tool_scopes={"read_file": ["invoice:read"],
                                         "export_report": ["invoice:list"]})
    r3 = p.issue_credential(ids[0], ids[1], MCP_AUD,
                            ["invoice:read", "invoice:list"], ttl=3600)
    authz.authorize_tool_call(r3["cred"], "read_file",
                              arguments={"path": "/data/invoice.csv"})
    authz.authorize_tool_call(r3["cred"], "export_report",
                              arguments={"month": "2026-09"})
    # 一次越权尝试（应被拒绝，留痕）
    r4 = p.issue_credential(ids[0], ids[2], MCP_AUD, ["invoice:read"],
                            ttl=3600)
    authz.authorize_tool_call(r4["cred"], "export_report")

    # 5) 异常处置：撤销某标识及其下游委托
    p.revoke_by_identity(ids[1], reason="行为异常，按预案废止")

    # 6) 审计锚定（不可否认性证据）
    p.anchor_audit(ids[0], reason="月度锚定")
    return p


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "合规报表示例")
    p = build_business()
    rep = ComplianceReport(p, system_name="某智能体平台（示例）",
                           assessor="（待填：测评机构）")
    rep.collect()
    paths = rep.save(out_dir)
    print("示例合规报表已生成：")
    for x in paths:
        print("  %s" % x)
    c = rep.data["conclusion"]
    print("\n结论：符合率 %s（符合 %s / 部分符合 %s / 不适用 %s）" %
          (c["conformity_rate"], "、".join(c["conforming"]) or "无",
           "、".join(c["partial"]) or "无",
           "、".join(c["not_applicable"]) or "无"))
    if c["gaps"]:
        print("待改进项：")
        for g in c["gaps"]:
            print("  - %s" % g)
    return 0


if __name__ == "__main__":
    sys.exit(main())
