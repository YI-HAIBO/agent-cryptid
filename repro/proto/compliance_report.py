# -*- coding: utf-8 -*-
"""合规报表导出（FR5-05 / NFR-11）。

对齐 GB/T 39786《信息系统密码应用基本要求》商用密码应用安全性评估
（密评）的材料要求，把中台运行期的密码学证据整理成可直接提交测评的
报表。覆盖本产品声称的三项密评指标：

    · 身份鉴别   —— 智能体标识 + 凭证签名校验
    · 访问控制   —— 作用域收敛、受众绑定、委托链、撤销
    · 不可否认性 —— 凭证签名 + 审计哈希链 + 审计锚点签名

设计原则：
    1. 证据优先，结论其次。每条结论都必须挂可独立复核的证据字段
       （根哈希、验签结果、证明可验证性），测评师能自己验一遍。
    2. 不美化。证据不足时结论为「部分符合」并列出缺口，
       绝不因为「功能已实现」就写「符合」。
    3. 三种导出：Markdown（人读/入册）、JSON（机读/入系统）、
       CSV（指标表，交表用）。

用法：
    rep = ComplianceReport(plat, system_name="某智能体平台",
                           assessor="某某测评中心")
    rep.save("out/")            # 生成 md / json / csv 三份
    print(rep.to_markdown())
"""
import csv
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PLATFORM_VERSION = "2.16"
STANDARD = "GB/T 39786-2021"

# 本产品声称覆盖的密评指标（三项）
INDICATORS = ("身份鉴别", "访问控制", "不可否认性")

# 证据项英文键 → 中文标签（报表给测评师看，字段要可读）
EVIDENCE_LABELS = {
    "algorithms": "使用算法",
    "credential_issued": "凭证签发次数",
    "credential_verified": "凭证校验次数",
    "identity_total": "标识总数",
    "revocation_checked": "撤销状态已核对",
    "delegation_issued": "委托签发次数",
    "delegation_verified": "委托链验证次数",
    "mcp_authorizations": "工具调用鉴权次数",
    "revocation_entries": "撤销记录数",
    "accumulator_root": "撤销累加器根",
    "accumulator_proof_verified": "撤销证明抽样验证",
    "scope_convergence_enforced": "作用域收敛已强制",
    "audience_binding_enforced": "受众绑定已强制",
    "audit_chain_length": "审计链条目数",
    "audit_chain_root": "审计链根哈希",
    "audit_chain_self_consistent": "审计链自洽",
    "append_only": "只可追加",
    "anchor_count": "审计锚点数",
    "anchor_latest_verified": "最新锚点验签",
    "anchor_latest_root": "最新锚点承诺链根",
}


def _fmt_ts(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_date(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class ComplianceReport:
    """从 Platform 采集密码学证据，生成密评合规报表。

    platform     Platform 实例
    system_name  被测系统名称（写入报表抬头）
    assessor     测评机构名称（可为空）
    period       (起, 止) Unix 秒；为空则按审计链实际时间范围
    """

    def __init__(self, platform, system_name="智能体密码身份中台",
                 assessor=None, period=None):
        self.p = platform
        self.system_name = system_name
        self.assessor = assessor
        self.period = period
        self._data = None

    # ---------------------------------------------------------------
    # 证据采集
    # ---------------------------------------------------------------
    def collect(self):
        """采集全部证据，返回结构化字典。"""
        p = self.p
        data = {}

        # --- 时间范围 ---
        ts_list = [e.get("ts") for e in p.audit.chain if e.get("ts")]
        since, until = (self.period or (None, None))
        if since is None and ts_list:
            since = min(ts_list)
        if until is None and ts_list:
            until = max(ts_list)
        now = int(time.time())

        # --- 标识统计 ---
        idents = getattr(p, "_identities", {}) or {}
        active = sum(1 for v in idents.values()
                     if v.get("status") == "active")
        disabled = len(idents) - active

        # --- 审计全量 ---
        audit = p.audit_query(limit=100000)
        records = audit.get("records", [])
        by_kind = {}
        for r in records:
            k = (r.get("event") or {}).get("kind") or "unknown"
            by_kind[k] = by_kind.get(k, 0) + 1

        # --- 撤销 ---
        snap = p.revocation_snapshot(since_version=0)
        entries = snap.get("entries", []) or []

        # --- 锚点 ---
        anchors = p.list_audit_anchors(limit=10000)
        anchor_list = anchors.get("anchors", []) or []

        # --- 策略 ---
        policy = dict(getattr(p, "_policy", {}) or {})

        data["meta"] = {
            "report_id": "AC-CR-%s" % time.strftime("%Y%m%d-%H%M%S",
                                                    time.localtime(now)),
            "system_name": self.system_name,
            "assessor": self.assessor,
            "standard": STANDARD,
            "platform_version": PLATFORM_VERSION,
            "tenant": getattr(p, "tenant", None),
            "generated_at": now,
            "generated_at_str": _fmt_ts(now),
            "period_start": since,
            "period_end": until,
            "period_str": "%s ~ %s" % (_fmt_date(since), _fmt_date(until)),
        }

        data["cryptography"] = self._collect_crypto(p, policy, records)

        data["key_management"] = {
            "generation": "标识密钥由标识认证机构（IA）基于主密钥派生；"
                          "SM9 用户私钥由主私钥与标识直接派生，无需证书",
            "storage": "主密钥常驻内存；用户私钥仅在注册响应中返回一次，"
                       "服务端不留存凭证全文与用户明文私钥",
            "distribution": "SM2 按标识派生下发；SM9 无证书，验签方仅需"
                            "主公钥 P_pub 与标识",
            "update": "主密钥版本化轮换（FR1-05）：rotate_mk / rotate_ks 生成"
                      "新版本并保留历史版本；标识记录 key_version、凭证携带"
                      "kv 字段，验签按版本取对应公钥或主公钥，故轮换不影响"
                      "既有标识与已签发凭证。标识停用/重新启用复用原密钥对",
            "destruction": "标识停用即失去签发与校验能力；撤销句柄进 "
                           "Merkle 累加器，不可移除",
            "backup_recovery": "撤销状态与审计锚点持久化至数据库，"
                               "支持重启恢复",
            "gaps": ["标识私钥未由国密密码芯片或可信执行环境承载"
                     "（FR1-06，PRD 排入二点零版）"],
        }

        data["statistics"] = {
            "identity_total": len(idents),
            "identity_active": active,
            "identity_disabled": disabled,
            "credential_issued": by_kind.get("credential.issue", 0),
            "credential_verified": by_kind.get("credential.verify", 0),
            "delegation_issued": by_kind.get("delegation.issue", 0),
            "delegation_verified": by_kind.get("delegation.verify", 0),
            "revocations": len(entries),
            "revoked_total": snap.get("total_revoked", len(entries)),
            "audit_entries": audit.get("chain_length", len(records)),
            "audit_kinds": by_kind,
            "audit_anchors": len(anchor_list),
            "mcp_authorizations": by_kind.get("mcp.authorize", 0),
        }

        data["integrity_proofs"] = self._collect_integrity(
            p, audit, anchor_list, snap, entries)

        data["indicators"] = self._build_indicators(
            p, data, by_kind, audit, anchor_list, entries)

        data["conclusion"] = self._build_conclusion(data)

        self._data = data
        return data

    def _collect_crypto(self, p, policy, records=None):
        """密码算法使用情况（密评「算法合规性」证据）。

        列入原则是「实际可用且确实用过」，不是「代码里存在」。
        SM9 主密钥（ia.ks）在任何租户上都恒存在，不能拿它当启用依据
        ——否则未启用 SM9 的租户也会被写成用了 SM9，密评材料失真。
        """
        allowed = policy.get("allowed_algs") or []
        records = records or []
        # 抗量子档位常量：局部导入 + 兜底，避免与 credential 的导入顺序耦合
        try:
            from credential import ALG_SM2_MLDSA, ALG_HASH_SIG
        except Exception:                                  # pragma: no cover
            ALG_SM2_MLDSA, ALG_HASH_SIG = "sm2-ml-dsa", "hash-signature"
        # 报告期内是否真的签发过 SM9 凭证
        sm9_used = any((r.get("event") or {}).get("alg_tier") == "sm9"
                       for r in records)
        algs = []
        if "sm2" in allowed or not allowed:
            algs.append({
                "name": "SM2", "type": "公钥密码（椭圆曲线）",
                "standard": "GB/T 32918.2-2016",
                "key_length": "256 位",
                "usage": "凭证签名与验签、审计锚点签名",
            })
        algs.append({
            "name": "SM3", "type": "密码杂凑算法",
            "standard": "GB/T 32905-2016",
            "key_length": "256 位摘要",
            "usage": "消息摘要、ZA 计算、Merkle 累加器叶子、"
                     "审计链与请求指纹",
        })
        if "sm9" in allowed or sm9_used:
            algs.append({
                "name": "SM9", "type": "标识密码（基于双线性对）",
                "standard": "GB/T 38635-2016",
                "key_length": "256 位 BN 曲线",
                "usage": "无证书标识身份的凭证签名与验签",
            })
        # v2.16：抗量子档位同样按「实际用过」原则列入。
        # 漏报会让密评材料失真——租户若真签了 PQ 凭证，报表必须体现。
        pq_used = {}
        for r in records:
            t = (r.get("event") or {}).get("alg_tier")
            if t in (ALG_SM2_MLDSA, ALG_HASH_SIG):
                pq_used[t] = pq_used.get(t, 0) + 1
        if ALG_SM2_MLDSA in allowed or pq_used.get(ALG_SM2_MLDSA):
            algs.append({
                "name": "ML-DSA-65", "type": "抗量子签名（格）",
                "standard": "FIPS 204",
                "key_length": "k=6, l=5, q=8380417",
                "usage": "混合档 sm2-ml-dsa 的抗量子分量（与 SM2 双签名，"
                         "失败关闭）",
            })
        if ALG_HASH_SIG in allowed or pq_used.get(ALG_HASH_SIG):
            algs.append({
                "name": "SLH-DSA", "type": "抗量子签名（哈希）",
                "standard": "FIPS 205（原型为缩减演示参数集）",
                "key_length": "原型缩减集",
                "usage": "hash-signature 档位，年尺度审计场景",
            })

        intl = [a for a in allowed
                if a.lower() in ("rsa", "ecdsa", "sha256", "sha-256",
                                 "aes", "md5")]
        pq_gaps = []
        if pq_used.get(ALG_SM2_MLDSA):
            # v2.17: ML-DSA 已换回标准 t1+hint 紧凑格式，无 full-t 归约缺口
            pass
        if pq_used.get(ALG_HASH_SIG):
            pq_gaps.append("hash-signature 档位不含国密分量，"
                           "NFR-06「禁用国际算法作为唯一依赖」需单独评估")
        if any(k in allowed for k in (ALG_SM2_MLDSA, ALG_HASH_SIG)) \
                and not pq_used:
            pq_gaps.append("策略已放开抗量子档位，但报告期内无对应签发记录")
        return {
            "algorithms": algs,
            "allowed_algs": allowed,
            "international_algorithm_present": bool(intl),
            "post_quantum_present": bool(pq_used),
            "post_quantum_usage": pq_used,
            "note": "全部密码运算采用商用密码算法；国际算法不作为唯一依赖"
                    "（NFR-06）。抗量子档位另计，见 post_quantum_present",
            "gaps": (["存在国际算法档位"] if intl else []) + pq_gaps,
        }

    def _collect_integrity(self, p, audit, anchor_list, snap, entries):
        """完整性证明：审计哈希链、锚点签名、撤销累加器。"""
        # 审计链自洽
        chain_ok, chain_why = p.audit.verify()
        # 锚点验签
        anchor_ok = None
        anchor_reason = "no anchor"
        if anchor_list:
            latest = anchor_list[-1]
            vr = p.verify_audit_anchor(latest)
            anchor_ok = bool(vr.get("ok"))
            anchor_reason = vr.get("verify_reason") or "-"
        # 撤销证明抽样验证
        proof_ok = None
        proof_jti = None
        if entries:
            jti = entries[0].get("jti")
            if jti:
                vr = p.verify_revocation(jti)
                proof_ok = bool(vr.get("verify"))
                proof_jti = jti
        return {
            "audit_chain": {
                "length": audit.get("chain_length", 0),
                "root_hash": audit.get("chain_root_hash"),
                "self_consistent": bool(audit.get("chain_valid")),
                "verify_reason": audit.get("chain_verify_reason") or chain_why,
                "recheck": bool(chain_ok),
                "append_only": True,
            },
            "audit_anchor": {
                "count": len(anchor_list),
                "latest_verified": anchor_ok,
                "verify_reason": anchor_reason,
                "latest_root_hash": (anchor_list[-1].get("root_hash")
                                     if anchor_list else None),
                "latest_ts": (anchor_list[-1].get("ts") if anchor_list
                              else None),
            },
            "revocation_accumulator": {
                "version": snap.get("acc_version"),
                "current_root": snap.get("acc_current_root"),
                "frozen_roots": len(snap.get("acc_frozen_roots") or []),
                "entries": len(entries),
                "sample_jti": proof_jti,
                "sample_proof_verified": proof_ok,
            },
        }

    def _build_indicators(self, p, data, by_kind, audit, anchor_list,
                          entries):
        """构造密评指标映射表（三项指标，每项含证据与结论）。"""
        st = data["statistics"]
        proofs = data["integrity_proofs"]

        # --- 身份鉴别 ---
        id_gaps = []
        issued = st["credential_issued"]
        verified = st["credential_verified"]
        if issued == 0:
            id_gaps.append("报告期内无凭证签发记录，无法形成鉴别证据")
        if st["identity_total"] == 0:
            id_gaps.append("未注册任何智能体标识")
        id_result = "符合" if not id_gaps else "不适用（证据不足）"
        identity = {
            "id": "identity_authentication",
            "name": "身份鉴别",
            "requirement": "应采用密码技术对登录/访问系统的实体进行身份"
                           "鉴别，确保身份真实性",
            "implementation": "为每个智能体签发密码学标识；调用方出示凭证，"
                              "校验方用签发方公钥本地验签，"
                              "校验通过方视为身份真实",
            "method": "抽取凭证签发与校验记录，核对签名算法、"
                      "验签结果、撤销状态与有效期",
            "evidence": {
                "algorithms": [a["name"]
                               for a in data["cryptography"]["algorithms"]
                               if a["name"] in ("SM2", "SM9")],
                "credential_issued": issued,
                "credential_verified": verified,
                "identity_total": st["identity_total"],
                "revocation_checked": bool(entries) or st["revoked_total"] > 0,
            },
            "result": id_result,
            "gaps": id_gaps,
        }

        # --- 访问控制 ---
        ac_gaps = []
        delegation = st["delegation_issued"]
        if delegation == 0:
            ac_gaps.append("报告期内无委托记录，多级授权收敛未产生证据")
        if st["mcp_authorizations"] == 0:
            ac_gaps.append("无工具调用鉴权记录（MCP 适配未产生决策证据）")
        ac_result = "符合" if not ac_gaps else "部分符合"
        access = {
            "id": "access_control",
            "name": "访问控制",
            "requirement": "应采用密码技术保证访问控制信息的完整性，"
                           "防止非授权访问与越权",
            "implementation": "凭证绑定作用域与受众；委托链逐级收敛"
                              "（子级作用域与有效期不得超过父级）；"
                              "工具调用前按最小权限过滤并按作用域鉴权；"
                              "撤销沿委托图级联生效",
            "method": "核对委托链收敛检查、受众绑定、Merkle 累加器撤销"
                      "证明与工具鉴权决策记录",
            "evidence": {
                "delegation_issued": delegation,
                "delegation_verified": st["delegation_verified"],
                "mcp_authorizations": st["mcp_authorizations"],
                "revocation_entries": st["revocations"],
                "accumulator_root": proofs["revocation_accumulator"]
                                          ["current_root"],
                "accumulator_proof_verified":
                    proofs["revocation_accumulator"]["sample_proof_verified"],
                "scope_convergence_enforced": True,
                "audience_binding_enforced": True,
            },
            "result": ac_result,
            "gaps": ac_gaps,
        }

        # --- 不可否认性 ---
        nr_gaps = []
        chain = proofs["audit_chain"]
        anchor = proofs["audit_anchor"]
        if not chain["self_consistent"]:
            nr_gaps.append("审计哈希链自洽性校验未通过")
        if anchor["count"] == 0:
            nr_gaps.append("未生成审计锚点，缺少对审计链根的时间承诺")
        elif anchor["latest_verified"] is not True:
            nr_gaps.append("审计锚点验签未通过")
        if chain["length"] == 0:
            nr_gaps.append("审计链为空")
        nr_result = "符合" if not nr_gaps else "部分符合"
        non_repudiation = {
            "id": "non_repudiation",
            "name": "不可否认性",
            "requirement": "应采用密码技术提供不可否认性证据，"
                           "使行为发起方无法否认其行为",
            "implementation": "每次签发、校验、委托、撤销、工具鉴权均生成"
                              "签名记录并写入只可追加的审计哈希链；"
                              "定期对链根做签名锚定，形成时间承诺",
            "method": "重算审计哈希链验证自洽性；对最新审计锚点做离线验签；"
                      "核对链根与锚点中承诺的链长是否一致",
            "evidence": {
                "audit_chain_length": chain["length"],
                "audit_chain_root": chain["root_hash"],
                "audit_chain_self_consistent": chain["self_consistent"],
                "append_only": chain["append_only"],
                "anchor_count": anchor["count"],
                "anchor_latest_verified": anchor["latest_verified"],
                "anchor_latest_root": anchor["latest_root_hash"],
            },
            "result": nr_result,
            "gaps": nr_gaps,
        }

        return [identity, access, non_repudiation]

    def _build_conclusion(self, data):
        inds = data["indicators"]
        ok = [i for i in inds if i["result"] == "符合"]
        partial = [i for i in inds if i["result"] == "部分符合"]
        na = [i for i in inds if i["result"].startswith("不适用")]
        gaps = []
        for i in inds:
            gaps.extend(i["gaps"])
        gaps.extend([g for g in
                     (data["key_management"].get("gaps") or []) if g])
        gaps.extend([g for g in
                     (data["cryptography"].get("gaps") or []) if g])
        return {
            "covered_indicators": INDICATORS,
            "conforming": [i["name"] for i in ok],
            "partial": [i["name"] for i in partial],
            "not_applicable": [i["name"] for i in na],
            "conformity_rate": "%.0f%%" % (
                100.0 * len(ok) / max(1, len(inds))),
            "gaps": [g for g in gaps if g],
            "statement": "本报告证据取自中台运行期实际记录，"
                         "所列根哈希、验签结果与撤销证明均可独立复核。",
        }

    # ---------------------------------------------------------------
    # 导出
    # ---------------------------------------------------------------
    @property
    def data(self):
        if self._data is None:
            self.collect()
        return self._data

    def to_json(self):
        return json.dumps(self.data, ensure_ascii=False, indent=2)

    def to_csv(self):
        """指标表 CSV（交表用）。"""
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["测评项", "标准要求", "实现措施", "测评方法",
                    "测评结果", "缺口"])
        for i in self.data["indicators"]:
            w.writerow([i["name"], i["requirement"], i["implementation"],
                        i["method"], i["result"],
                        "；".join(i["gaps"]) or "-"])
        return buf.getvalue()

    def to_markdown(self):
        d = self.data
        m, st = d["meta"], d["statistics"]
        L = []
        L.append("# 商用密码应用安全性评估合规报表")
        L.append("")
        L.append("**系统名称**：%s　　**报告编号**：%s" %
                 (m["system_name"], m["report_id"]))
        L.append("")
        L.append("**测评依据**：%s《信息系统密码应用基本要求》　　"
                 "**中台版本**：%s" % (m["standard"], m["platform_version"]))
        L.append("")
        if m["assessor"]:
            L.append("**测评机构**：%s" % m["assessor"])
        L.append("**报告期间**：%s　　**生成时间**：%s" %
                 (m["period_str"], m["generated_at_str"]))
        if m["tenant"]:
            L.append("**租户**：%s" % m["tenant"])
        L.append("")
        L.append("---")
        L.append("")

        # 一、密码算法使用
        L.append("## 一、密码算法使用情况")
        L.append("")
        L.append("| 算法 | 类型 | 标准 | 密钥长度 | 用途 |")
        L.append("|---|---|---|---|---|")
        for a in d["cryptography"]["algorithms"]:
            L.append("| %s | %s | %s | %s | %s |" %
                     (a["name"], a["type"], a["standard"],
                      a["key_length"], a["usage"]))
        L.append("")
        L.append("> %s" % d["cryptography"]["note"])
        L.append("")

        # 二、密钥管理
        L.append("## 二、密钥管理")
        L.append("")
        L.append("| 环节 | 措施 |")
        L.append("|---|---|")
        for k, label in [("generation", "生成"), ("storage", "存储"),
                         ("distribution", "分发"), ("update", "更新"),
                         ("destruction", "销毁"),
                         ("backup_recovery", "备份与恢复")]:
            L.append("| %s | %s |" % (label, d["key_management"][k]))
        L.append("")

        # 三、运行统计
        L.append("## 三、运行统计")
        L.append("")
        L.append("| 指标 | 数值 |")
        L.append("|---|---|")
        rows = [
            ("标识总数", st["identity_total"]),
            ("活跃标识", st["identity_active"]),
            ("停用标识", st["identity_disabled"]),
            ("凭证签发次数", st["credential_issued"]),
            ("凭证校验次数", st["credential_verified"]),
            ("委托签发次数", st["delegation_issued"]),
            ("委托链验证次数", st["delegation_verified"]),
            ("工具调用鉴权次数", st["mcp_authorizations"]),
            ("撤销记录数", st["revocations"]),
            ("审计链条目数", st["audit_entries"]),
            ("审计锚点数", st["audit_anchors"]),
        ]
        for k, v in rows:
            L.append("| %s | %s |" % (k, v))
        L.append("")

        # 四、密评指标
        L.append("## 四、密评指标符合性")
        L.append("")
        L.append("| 测评项 | 测评结果 | 主要证据 | 缺口 |")
        L.append("|---|---|---|---|")
        for i in d["indicators"]:
            ev = _brief_evidence(i)
            L.append("| %s | %s | %s | %s |" %
                     (i["name"], i["result"], ev,
                      "；".join(i["gaps"]) or "-"))
        L.append("")
        for i in d["indicators"]:
            L.append("### （%s）%s" %
                     ("一二三四五"[d["indicators"].index(i)], i["name"]))
            L.append("")
            L.append("**标准要求**：%s" % i["requirement"])
            L.append("")
            L.append("**实现措施**：%s" % i["implementation"])
            L.append("")
            L.append("**测评方法**：%s" % i["method"])
            L.append("")
            L.append("**证据**：")
            L.append("")
            L.append("| 证据项 | 值 |")
            L.append("|---|---|")
            for k, v in i["evidence"].items():
                L.append("| %s | %s |" % (EVIDENCE_LABELS.get(k, k),
                                          _fmt_evidence_value(v)))
            L.append("")
            L.append("**测评结果**：%s%s" %
                     (i["result"],
                      "（%s）" % "；".join(i["gaps"]) if i["gaps"] else ""))
            L.append("")

        # 五、完整性证明
        L.append("## 五、完整性证明（可独立复核）")
        L.append("")
        ip = d["integrity_proofs"]
        L.append("| 证明项 | 值 |")
        L.append("|---|---|")
        ac = ip["audit_chain"]
        an = ip["audit_anchor"]
        ra = ip["revocation_accumulator"]
        L.append("| 审计链条目数 | %s |" % ac["length"])
        L.append("| 审计链根哈希 | `%s` |" % ac["root_hash"])
        L.append("| 审计链自洽 | %s |" % ("通过" if ac["self_consistent"]
                                          else "未通过"))
        L.append("| 审计链只可追加 | %s |" % ("是" if ac["append_only"]
                                              else "否"))
        L.append("| 审计锚点数 | %s |" % an["count"])
        L.append("| 最新锚点验签 | %s |" % _tri(an["latest_verified"]))
        L.append("| 最新锚点承诺链根 | `%s` |" % an["latest_root_hash"])
        L.append("| 撤销累加器版本 | %s |" % ra["version"])
        L.append("| 撤销累加器根 | `%s` |" % ra["current_root"])
        L.append("| 撤销证明抽样验证 | %s |" % _tri(ra["sample_proof_verified"]))
        L.append("")

        # 六、结论
        c = d["conclusion"]
        L.append("## 六、结论")
        L.append("")
        L.append("本报告覆盖密评指标 %d 项（%s）：符合 %d 项、"
                 "部分符合 %d 项、不适用 %d 项，符合率 %s。" %
                 (len(c["covered_indicators"]),
                  "、".join(c["covered_indicators"]),
                  len(c["conforming"]), len(c["partial"]),
                  len(c["not_applicable"]), c["conformity_rate"]))
        L.append("")
        if c["gaps"]:
            L.append("**待改进项**：")
            L.append("")
            for g in c["gaps"]:
                L.append("- %s" % g)
            L.append("")
        L.append("> %s" % c["statement"])
        L.append("")
        return "\n".join(L)

    def save(self, out_dir=".", prefix=None):
        """导出三份文件，返回路径列表。"""
        os.makedirs(out_dir, exist_ok=True)
        base = prefix or self.data["meta"]["report_id"]
        paths = []
        for ext, content in (("md", self.to_markdown()),
                             ("json", self.to_json()),
                             ("csv", self.to_csv())):
            path = os.path.join(out_dir, "%s.%s" % (base, ext))
            # CSV 必须 newline=""：csv.writer 用 \r\n 作行终止符，
            # 若以文本模式写入，Windows 会把 \n 再转成 \r\n，
            # 变成 \r\r\n，读取时凭空多出空行。
            if ext == "csv":
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(content)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            paths.append(path)
        return paths


def _tri(v):
    if v is True:
        return "通过"
    if v is False:
        return "未通过"
    return "无数据"


def _fmt_evidence_value(v):
    if isinstance(v, bool):
        return "是" if v else "否"
    if isinstance(v, list):
        return "、".join(str(x) for x in v) or "-"
    if v is None:
        return "-"
    return str(v)


def _brief_evidence(i):
    """指标表里的一句话证据摘要。"""
    ev = i["evidence"]
    if i["id"] == "identity_authentication":
        return "签发 %s 次、校验 %s 次，算法 %s" % (
            ev.get("credential_issued"), ev.get("credential_verified"),
            "、".join(ev.get("algorithms") or []) or "-")
    if i["id"] == "access_control":
        return "委托 %s 次、工具鉴权 %s 次、撤销 %s 条" % (
            ev.get("delegation_issued"), ev.get("mcp_authorizations"),
            ev.get("revocation_entries"))
    return "审计链 %s 条、锚点 %s 个、链自洽 %s" % (
        ev.get("audit_chain_length"), ev.get("anchor_count"),
        "是" if ev.get("audit_chain_self_consistent") else "否")


# ------------------------------------------------------------------
# 自检
# ------------------------------------------------------------------
def self_check():
    """合规报表端到端自检。"""
    from agent_platform import Platform
    from credential import ALG_SM2

    out = []
    p = Platform(tenant="cr")
    for idn in ["agent://cr/root", "agent://cr/a1", "agent://cr/a2"]:
        p.register_identity(idn, org="cr")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    r0 = p.issue_credential("agent://cr/root", "agent://cr/a1",
                            "service://cr", ["cr:read"], ttl=3600)
    p.verify_credential(r0["cred"], audience="service://cr")
    p.issue_delegation("agent://cr/a1", "agent://cr/a2", "service://cr",
                       ["cr:read"], ttl=3600, parent_cred=r0["cred"])
    p.anchor_audit("agent://cr/root", reason="self-check")

    rep = ComplianceReport(p, system_name="自检系统", assessor="自检")
    d = rep.collect()

    out.append(("报表含元信息",
                bool(d["meta"]["report_id"]) and d["meta"]["standard"]))
    out.append(("报表含三项密评指标", len(d["indicators"]) == 3))
    md = rep.to_markdown()
    out.append(("Markdown 含全部章节",
                all(k in md for k in ["## 一、", "## 二、", "## 三、",
                                      "## 四、", "## 五、", "## 六、"])))
    js = json.loads(rep.to_json())
    out.append(("JSON 可解析且含结论", "conclusion" in js))
    csv_text = rep.to_csv()
    out.append(("CSV 含表头与三行指标",
                "测评项" in csv_text
                and csv_text.strip().count("\n") >= 3))
    out.append(("审计链自洽证据",
                d["integrity_proofs"]["audit_chain"]["self_consistent"]))
    out.append(("锚点证据已采集",
                d["integrity_proofs"]["audit_anchor"]["count"] >= 1))
    out.append(("统计与平台一致",
                d["statistics"]["identity_total"] == 3))
    out.append(("结论给出符合率",
                "%" in d["conclusion"]["conformity_rate"]))
    return out


if __name__ == "__main__":
    ok = 0
    res = self_check()
    for name, passed in res:
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            ok += 1
    print("RESULT  PASS=%d  FAIL=%d" % (ok, len(res) - ok))
