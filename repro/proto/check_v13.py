# -*- coding: utf-8 -*-
"""v2.10 测试：FR5-05 合规报表导出 + NFR-11 密评材料输出。

对齐 GB/T 39786 商用密码应用安全性评估（密评）的材料要求。

覆盖：
  [A] 报表结构与元信息
  [B] 密码算法合规性证据
  [C] 密钥管理证据
  [D] 运行统计准确性
  [E] 三项密评指标（身份鉴别/访问控制/不可否认性）
  [F] 完整性证明可独立复核
  [G] 导出文件（Markdown/JSON/CSV）
  [H] 失败诚实性：证据不足时不得写「符合」
  [I] 边界：空平台
"""
import csv
import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from compliance_report import ComplianceReport, STANDARD, INDICATORS
from credential import ALG_SM2, ALG_SM9
from mcp_adapter import MCPAuthzAdapter

PASS = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("PASS     %s" % name)
    else:
        FAIL.append(name)
        print("FAIL     %s  %s" % (name, detail))


def build_platform(tenant="cr", algs=None, with_mcp=False):
    """构造一个跑过完整业务的平台。"""
    p = Platform(tenant=tenant)
    ids = ["agent://%s/root" % tenant, "agent://%s/a1" % tenant,
           "agent://%s/a2" % tenant]
    for idn in ids:
        p.register_identity(idn, org=tenant)
    p.configure_policy({"allowed_algs": algs or [ALG_SM2],
                        "max_ttl_seconds": 3600})

    aud = "service://%s" % tenant
    r0 = p.issue_credential(ids[0], ids[1], aud, ["c:read"], ttl=3600)
    p.verify_credential(r0["cred"], audience=aud)
    r1 = p.issue_delegation(ids[1], ids[2], aud, ["c:read"], ttl=3600,
                            parent_cred=r0["cred"])
    p.verify_delegation_chain([r0["cred"], r1["cred"]], aud, ["c:read"])
    if with_mcp:
        authz = MCPAuthzAdapter(p, audience="mcp://%s" % tenant,
                                tool_scopes={"read_file": ["c:read"]})
        r2 = p.issue_credential(ids[0], ids[1], "mcp://%s" % tenant,
                                ["c:read"], ttl=3600)
        authz.authorize_tool_call(r2["cred"], "read_file")
    p.revoke(r1["cred"]["jti"], reason="compliance test")
    p.anchor_audit(ids[0], reason="compliance test")
    return p, ids, r0, r1


# ---------------------------------------------------------------------------
# [A] 结构与元信息
# ---------------------------------------------------------------------------

def test_structure():
    print("\n=== [A] 报表结构与元信息 ===")
    p, ids, r0, r1 = build_platform("crA")
    rep = ComplianceReport(p, system_name="某智能体平台",
                           assessor="某测评中心")
    d = rep.collect()

    check("A1 含报告编号", bool(d["meta"]["report_id"]))
    check("A2 测评依据为 GB/T 39786",
          STANDARD in d["meta"]["standard"], detail=d["meta"]["standard"])
    check("A3 系统名称透传", d["meta"]["system_name"] == "某智能体平台")
    check("A4 测评机构透传", d["meta"]["assessor"] == "某测评中心")
    check("A5 租户记录", d["meta"]["tenant"] == "crA")
    check("A6 含报告期间", "~" in d["meta"]["period_str"])
    check("A7 六大字段齐备",
          all(k in d for k in ["meta", "cryptography", "key_management",
                               "statistics", "integrity_proofs",
                               "indicators", "conclusion"]))


# ---------------------------------------------------------------------------
# [B] 密码算法合规性
# ---------------------------------------------------------------------------

def test_crypto():
    print("\n=== [B] 密码算法合规性证据 ===")
    p, _, _, _ = build_platform("crB")
    d = ComplianceReport(p).collect()
    names = [a["name"] for a in d["cryptography"]["algorithms"]]
    check("B1 含 SM2", "SM2" in names)
    check("B2 含 SM3", "SM3" in names)
    check("B3 不因未启用而列 SM9", "SM9" not in names,
          detail=str(names))
    for a in d["cryptography"]["algorithms"]:
        check("B4 %s 标注国标号" % a["name"],
              a["standard"].startswith("GB/T"),
              detail=a["standard"])
    check("B5 无国际算法", not d["cryptography"]["international_algorithm_present"])

    # 启用 SM9 后应出现
    p2, _, _, _ = build_platform("crB9", algs=[ALG_SM2, ALG_SM9])
    d2 = ComplianceReport(p2).collect()
    names2 = [a["name"] for a in d2["cryptography"]["algorithms"]]
    check("B6 启用后含 SM9", "SM9" in names2, detail=str(names2))


# ---------------------------------------------------------------------------
# [C] 密钥管理
# ---------------------------------------------------------------------------

def test_key_management():
    print("\n=== [C] 密钥管理证据 ===")
    p, _, _, _ = build_platform("crC")
    d = ComplianceReport(p).collect()
    km = d["key_management"]
    for k in ["generation", "storage", "distribution", "update",
              "destruction", "backup_recovery"]:
        check("C1 密钥管理含 %s" % k, bool(km.get(k)))
    check("C2 声明私钥不落盘",
          "不留存" in km["storage"] or "内存" in km["storage"])
    # v2.16：FR1-05 密钥轮换已完成（v2.13），不得再写成「待建/尚未实现」；
    # 真实缺口已变为 FR1-06（芯片/TEE 承载，PRD 排入二点零版），必须仍如实披露。
    check("C3 如实反映密钥轮换已具备",
          "轮换" in km["update"] and "待建" not in km["update"])
    check("C4 仍诚实标注私钥承载缺口（FR1-06）",
          any("芯片" in g or "可信执行" in g for g in km.get("gaps") if g))
    check("C5 不得再声称 FR1-05 未实现",
          not any("FR1-05" in g for g in km.get("gaps") if g))


# ---------------------------------------------------------------------------
# [D] 统计准确性
# ---------------------------------------------------------------------------

def test_statistics():
    print("\n=== [D] 运行统计准确性 ===")
    p, ids, r0, r1 = build_platform("crD", with_mcp=True)
    d = ComplianceReport(p).collect()
    st = d["statistics"]

    check("D1 标识总数正确", st["identity_total"] == 3,
          detail=str(st["identity_total"]))
    check("D2 凭证签发计数正确", st["credential_issued"] >= 1)
    check("D3 凭证校验计数正确", st["credential_verified"] >= 1)
    check("D4 委托签发计数正确", st["delegation_issued"] >= 1)
    check("D5 委托链验证计数正确", st["delegation_verified"] >= 1)
    check("D6 撤销记录计数正确", st["revocations"] >= 1)
    check("D7 审计链条目数非空", st["audit_entries"] > 0)
    check("D8 锚点计数正确", st["audit_anchors"] >= 1)
    check("D9 MCP 鉴权计数正确", st["mcp_authorizations"] >= 1,
          detail=str(st["mcp_authorizations"]))
    check("D10 审计事件分类齐全",
          "credential.issue" in st["audit_kinds"])

    # 停用标识计数
    p.disable_identity(ids[2], reason="test")
    d2 = ComplianceReport(p).collect()
    check("D11 停用标识计入统计",
          d2["statistics"]["identity_disabled"] == 1,
          detail=str(d2["statistics"]["identity_disabled"]))


# ---------------------------------------------------------------------------
# [E] 三项密评指标
# ---------------------------------------------------------------------------

def test_indicators():
    print("\n=== [E] 三项密评指标 ===")
    p, _, _, _ = build_platform("crE", with_mcp=True)
    d = ComplianceReport(p).collect()
    inds = d["indicators"]
    names = [i["name"] for i in inds]

    check("E1 覆盖身份鉴别", "身份鉴别" in names)
    check("E2 覆盖访问控制", "访问控制" in names)
    check("E3 覆盖不可否认性", "不可否认性" in names)
    check("E4 三项指标与声称一致", tuple(names) == INDICATORS,
          detail=str(names))

    for i in inds:
        check("E5 %s 含标准要求" % i["name"], bool(i["requirement"]))
        check("E6 %s 含实现措施" % i["name"], bool(i["implementation"]))
        check("E7 %s 含测评方法" % i["name"], bool(i["method"]))
        check("E8 %s 含证据" % i["name"], bool(i["evidence"]))
        check("E9 %s 含测评结果" % i["name"],
              i["result"] in ("符合", "部分符合") or
              i["result"].startswith("不适用"))

    # 完整证据链下三项均应为「符合」
    check("E10 完整证据下身份鉴别符合",
          inds[0]["result"] == "符合", detail=str(inds[0]["gaps"]))
    check("E11 完整证据下访问控制符合",
          inds[1]["result"] == "符合", detail=str(inds[1]["gaps"]))
    check("E12 完整证据下不可否认性符合",
          inds[2]["result"] == "符合", detail=str(inds[2]["gaps"]))


# ---------------------------------------------------------------------------
# [F] 完整性证明可独立复核
# ---------------------------------------------------------------------------

def test_integrity_proofs():
    print("\n=== [F] 完整性证明可独立复核 ===")
    p, _, _, _ = build_platform("crF")
    d = ComplianceReport(p).collect()
    ip = d["integrity_proofs"]

    ac = ip["audit_chain"]
    check("F1 审计链自洽", ac["self_consistent"] is True)
    check("F2 审计链根哈希非空", bool(ac["root_hash"]))
    check("F3 审计链只可追加", ac["append_only"] is True)
    check("F4 链长与平台一致",
          ac["length"] == p.audit.count(),
          detail="%s vs %s" % (ac["length"], p.audit.count()))

    an = ip["audit_anchor"]
    check("F5 锚点已采集", an["count"] >= 1)
    check("F6 最新锚点验签通过", an["latest_verified"] is True,
          detail=str(an["verify_reason"]))
    check("F7 锚点承诺链根非空", bool(an["latest_root_hash"]))

    ra = ip["revocation_accumulator"]
    check("F8 撤销累加器根非空", bool(ra["current_root"]))
    check("F9 撤销证明抽样验证通过",
          ra["sample_proof_verified"] is True)
    check("F10 抽样 jti 非空", bool(ra["sample_jti"]))

    # 根哈希与平台快照一致（防止报表瞎编）
    snap = p.revocation_snapshot(since_version=0)
    check("F11 累加器根与平台快照一致",
          ra["current_root"] == snap.get("acc_current_root"))


# ---------------------------------------------------------------------------
# [G] 导出文件
# ---------------------------------------------------------------------------

def test_export():
    print("\n=== [G] 导出文件 ===")
    p, _, _, _ = build_platform("crG", with_mcp=True)
    rep = ComplianceReport(p, system_name="导出测试")
    rep.collect()
    tmp = tempfile.mkdtemp()
    try:
        paths = rep.save(tmp)
        check("G1 导出三份文件", len(paths) == 3, detail=str(paths))
        for pth in paths:
            check("G2 文件存在且非空 %s" % os.path.basename(pth),
                  os.path.exists(pth) and os.path.getsize(pth) > 0)

        # Markdown
        md_path = [x for x in paths if x.endswith(".md")][0]
        md = open(md_path, encoding="utf-8").read()
        check("G3 Markdown 含标题", md.startswith("# "))
        check("G4 Markdown 含算法表", "| 算法 |" in md)
        check("G5 Markdown 含指标表", "| 测评项 |" in md)
        check("G6 Markdown 含结论", "## 六、结论" in md)

        # JSON
        js_path = [x for x in paths if x.endswith(".json")][0]
        js = json.load(open(js_path, encoding="utf-8"))
        check("G7 JSON 含 indicators", len(js["indicators"]) == 3)
        check("G8 JSON 可回读为 UTF-8",
              js["meta"]["system_name"] == "导出测试")

        # CSV
        csv_path = [x for x in paths if x.endswith(".csv")][0]
        rows = list(csv.reader(io.StringIO(
            open(csv_path, encoding="utf-8").read())))
        check("G9 CSV 表头正确",
              rows[0] == ["测评项", "标准要求", "实现措施", "测评方法",
                          "测评结果", "缺口"])
        check("G10 CSV 三行指标", len(rows) == 4,
              detail=str(len(rows)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# [H] 失败诚实性
# ---------------------------------------------------------------------------

def test_honesty():
    print("\n=== [H] 证据不足时不得写符合 ===")
    # 空平台：无任何业务记录
    p = Platform(tenant="crH")
    d = ComplianceReport(p).collect()
    inds = {i["name"]: i for i in d["indicators"]}

    check("H1 空平台身份鉴别判不适用",
          inds["身份鉴别"]["result"].startswith("不适用"),
          detail=inds["身份鉴别"]["result"])
    check("H2 空平台列出缺口", len(inds["身份鉴别"]["gaps"]) > 0)
    check("H3 空平台不可否认性不为符合",
          inds["不可否认性"]["result"] != "符合",
          detail=inds["不可否认性"]["result"])
    check("H4 符合率不为 100%",
          d["conclusion"]["conformity_rate"] != "100%",
          detail=d["conclusion"]["conformity_rate"])

    # 有委托但无 MCP 鉴权 → 访问控制应为部分符合
    p2, _, _, _ = build_platform("crH2", with_mcp=False)
    d2 = ComplianceReport(p2).collect()
    ac = [i for i in d2["indicators"] if i["name"] == "访问控制"][0]
    check("H5 缺 MCP 证据时访问控制部分符合",
          ac["result"] == "部分符合", detail=str(ac["gaps"]))
    check("H6 缺口点名 MCP", any("MCP" in g for g in ac["gaps"]),
          detail=str(ac["gaps"]))

    # 篡改审计链 → 不可否认性不得为符合
    p3, _, _, _ = build_platform("crH3")
    p3.audit.chain[0]["hash"] = "0" * 64
    d3 = ComplianceReport(p3).collect()
    nr = [i for i in d3["indicators"] if i["name"] == "不可否认性"][0]
    check("H7 审计链被篡改时不可否认性不为符合",
          nr["result"] != "符合", detail=str(nr["gaps"]))
    check("H8 缺口点名自洽性",
          any("自洽" in g for g in nr["gaps"]), detail=str(nr["gaps"]))


# ---------------------------------------------------------------------------
# [I] 边界
# ---------------------------------------------------------------------------

def test_edge():
    print("\n=== [I] 边界 ===")
    p = Platform(tenant="crI")
    rep = ComplianceReport(p)
    d = rep.collect()
    check("I1 空平台可生成报表（不崩）", bool(d["meta"]["report_id"]))
    check("I2 空平台时间为占位符",
          d["meta"]["period_start"] is None
          or isinstance(d["meta"]["period_start"], int))
    check("I3 空平台三种格式均可产出",
          bool(rep.to_markdown()) and bool(rep.to_json())
          and bool(rep.to_csv()))
    check("I4 空平台统计为零", d["statistics"]["identity_total"] == 0)

    # 显式指定期间
    p2, _, _, _ = build_platform("crI2")
    d2 = ComplianceReport(p2, period=(1700000000, 1800000000)).collect()
    check("I5 指定期间被采用",
          d2["meta"]["period_start"] == 1700000000
          and d2["meta"]["period_end"] == 1800000000)

    # 重复 collect 结果稳定（结论不应抖动）
    rep3 = ComplianceReport(p2)
    a = rep3.collect()
    b = rep3.collect()
    check("I6 重复采集结论一致",
          a["conclusion"]["conformity_rate"] ==
          b["conclusion"]["conformity_rate"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_structure()
    test_crypto()
    test_key_management()
    test_statistics()
    test_indicators()
    test_integrity_proofs()
    test_export()
    test_honesty()
    test_edge()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v13_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v13 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
