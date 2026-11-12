# -*- coding: utf-8 -*-
"""FR2-07 凭证模板：按智能体类型预置作用域。

模板定义某类智能体的「允许签发范围」：
    · 默认作用域（default_scope）
    · 作用域白名单（allowed_scopes）
    · 最大有效期（max_ttl）
    · 允许算法档位（allowed_algs）
    · 关联受众（allowed_audiences）

基于模板签发时强制校验：
    · scope ⊆ allowed_scopes
    · ttl ≤ max_ttl
    · alg_tier ∈ allowed_algs
    · audience ∈ allowed_audiences

设计要点：
    · 模板与 Platform 解耦：TemplateRegistry 独立持有模板，
      通过 issue_from_template() 委托 Platform 签发。
    · 模板可持久化（JSON 格式，入 SQLite 或内存）。
    · 模板本身入审计链，变更可追溯。
"""
import sys
import os
import time
import json
from typing import Optional, List, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class CredentialTemplate:
    """单个凭证模板。"""

    def __init__(self, template_id, name, agent_type,
                 default_scope=None,
                 allowed_scopes=None,
                 max_ttl=3600,
                 allowed_algs=None,
                 allowed_audiences=None,
                 description=None,
                 created_at=None,
                 updated_at=None):
        self.template_id = template_id
        self.name = name
        self.agent_type = agent_type
        self.default_scope = tuple(default_scope or [])
        self.allowed_scopes = tuple(allowed_scopes or self.default_scope)
        self.max_ttl = max_ttl
        self.allowed_algs = tuple(allowed_algs or ["sm2"])
        self.allowed_audiences = tuple(allowed_audiences or [])
        self.description = description or ""
        self.created_at = created_at or int(time.time())
        self.updated_at = updated_at or self.created_at

    def validate(self, scope, ttl, alg_tier, audience) -> List[str]:
        """校验请求参数是否在模板允许范围内。返回违规列表（空=通过）。"""
        violations = []
        # scope 检查
        for s in scope:
            if self.allowed_scopes and s not in self.allowed_scopes:
                violations.append(
                    "scope '%s' not in allowed_scopes" % s)
        # ttl 检查
        if self.max_ttl is not None and ttl > self.max_ttl:
            violations.append(
                "ttl %d exceeds max_ttl %d" % (ttl, self.max_ttl))
        # alg 检查
        if self.allowed_algs and alg_tier not in self.allowed_algs:
            violations.append(
                "alg_tier '%s' not in allowed_algs" % alg_tier)
        # audience 检查
        if self.allowed_audiences and audience not in self.allowed_audiences:
            violations.append(
                "audience '%s' not in allowed_audiences" % audience)
        return violations

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "agent_type": self.agent_type,
            "default_scope": list(self.default_scope),
            "allowed_scopes": list(self.allowed_scopes),
            "max_ttl": self.max_ttl,
            "allowed_algs": list(self.allowed_algs),
            "allowed_audiences": list(self.allowed_audiences),
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CredentialTemplate":
        return cls(
            template_id=d["template_id"],
            name=d["name"],
            agent_type=d["agent_type"],
            default_scope=d.get("default_scope"),
            allowed_scopes=d.get("allowed_scopes"),
            max_ttl=d.get("max_ttl", 3600),
            allowed_algs=d.get("allowed_algs"),
            allowed_audiences=d.get("allowed_audiences"),
            description=d.get("description"),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        )


class TemplateRegistry:
    """凭证模板注册表。"""

    def __init__(self):
        self._templates: Dict[str, CredentialTemplate] = {}

    def create(self, name, agent_type, default_scope=None,
               allowed_scopes=None, max_ttl=3600,
               allowed_algs=None, allowed_audiences=None,
               description=None,
               template_id=None) -> dict:
        """创建模板。返回结果 dict。"""
        if not name:
            return {"ok": False, "reason": "empty name"}
        if not agent_type:
            return {"ok": False, "reason": "empty agent_type"}
        if template_id is None:
            # 用时间戳 + 随机后缀避免同毫秒碰撞
            import uuid
            template_id = "tpl_%s_%d_%s" % (
                agent_type.replace("/", "_"),
                int(time.time() * 1000),
                uuid.uuid4().hex[:8],
            )
        if template_id in self._templates:
            return {"ok": False, "reason": "template_id already exists"}
        tpl = CredentialTemplate(
            template_id=template_id,
            name=name,
            agent_type=agent_type,
            default_scope=default_scope,
            allowed_scopes=allowed_scopes,
            max_ttl=max_ttl,
            allowed_algs=allowed_algs,
            allowed_audiences=allowed_audiences,
            description=description,
        )
        self._templates[template_id] = tpl
        return {"ok": True, "template": tpl.to_dict()}

    def update(self, template_id, **kwargs) -> dict:
        """更新模板。"""
        tpl = self._templates.get(template_id)
        if tpl is None:
            return {"ok": False, "reason": "unknown template"}
        if "name" in kwargs:
            tpl.name = kwargs["name"]
        if "description" in kwargs:
            tpl.description = kwargs["description"]
        if "default_scope" in kwargs:
            tpl.default_scope = tuple(kwargs["default_scope"] or [])
        if "allowed_scopes" in kwargs:
            tpl.allowed_scopes = tuple(kwargs["allowed_scopes"] or [])
        if "max_ttl" in kwargs:
            tpl.max_ttl = kwargs["max_ttl"]
        if "allowed_algs" in kwargs:
            tpl.allowed_algs = tuple(kwargs["allowed_algs"] or [])
        if "allowed_audiences" in kwargs:
            tpl.allowed_audiences = tuple(kwargs["allowed_audiences"] or [])
        tpl.updated_at = int(time.time())
        return {"ok": True, "template": tpl.to_dict()}

    def delete(self, template_id) -> dict:
        """删除模板。"""
        if template_id not in self._templates:
            return {"ok": False, "reason": "unknown template"}
        del self._templates[template_id]
        return {"ok": True}

    def get(self, template_id) -> Optional[CredentialTemplate]:
        return self._templates.get(template_id)

    def list(self, agent_type=None) -> List[dict]:
        """列出模板，可按 agent_type 过滤。"""
        out = []
        for tpl in self._templates.values():
            if agent_type and tpl.agent_type != agent_type:
                continue
            out.append(tpl.to_dict())
        out.sort(key=lambda t: t["template_id"])
        return out

    def state_dict(self) -> dict:
        return {
            tid: tpl.to_dict() for tid, tpl in self._templates.items()
        }

    def load_state(self, state: dict):
        self._templates.clear()
        for tid, d in state.items():
            self._templates[tid] = CredentialTemplate.from_dict(d)


class TemplateCredentialIssuer:
    """基于模板签发凭证。

    职责边界：
        · 只做「模板校验 + 参数归一化」
        · 实际签发委托给 Platform.issue_credential()
        · 不绕过 Platform 的任何安全检查（策略、撤销等）

    续期（FR2-04）也通过本类，确保续期凭证也受模板约束。
    """

    def __init__(self, platform, registry: TemplateRegistry):
        self.platform = platform
        self.registry = registry

    def issue_from_template(self, template_id, issuer_idn, subject_idn,
                            audience=None, scope=None,
                            ttl=None, alg_tier="sm2") -> dict:
        """基于模板签发普通凭证。

        参数：
            template_id    模板 ID
            issuer_idn     签发方标识
            subject_idn    主体标识
            audience       受众（未提供则用模板 allowed_audiences[0]）
            scope          作用域（未提供则用模板 default_scope）
            ttl            有效期（未提供则用模板 max_ttl）
            alg_tier       算法档位

        返回 Platform.issue_credential 的结果 dict，
        失败时加 violations 字段。

        说明：模板签发只用于普通凭证，不支持委托链（parent_cred 由
        Platform.issue_delegation 承担）。模板的作用域/受众/算法校验
        在此函数内完成，签发仍走 Platform.issue_credential 保留所有
        策略与撤销检查。
        """
        tpl = self.registry.get(template_id)
        if tpl is None:
            return {"ok": False, "reason": "unknown template"}

        # 参数归一化
        if scope is None:
            scope = list(tpl.default_scope)
        if ttl is None:
            ttl = tpl.max_ttl
        if audience is None and tpl.allowed_audiences:
            audience = tpl.allowed_audiences[0]
        if not audience:
            return {"ok": False, "reason": "audience required (no default in template)"}

        # 模板校验
        violations = tpl.validate(scope, ttl, alg_tier, audience)
        if violations:
            return {
                "ok": False,
                "reason": "template validation failed",
                "violations": violations,
            }

        # 委托 Platform 签发（保留所有安全语义）
        result = self.platform.issue_credential(
            issuer_idn=issuer_idn,
            subject_idn=subject_idn,
            audience=audience,
            scope=scope,
            ttl=ttl,
            alg_tier=alg_tier,
        )
        if result.get("ok"):
            result["template_id"] = template_id
        return result

    def renew_from_template(self, template_id, old_cred_wire,
                            issuer_idn=None, ttl=None,
                            alg_tier=None) -> dict:
        """基于模板续期凭证（FR2-04 入口）。

        从旧凭证提取 sub/aud/scope/alg_tier，
        用模板校验后重新签发，旧凭证由调用方撤销。
        """
        from agent_platform import _cred_from_wire
        old = _cred_from_wire(old_cred_wire)
        if old is None:
            return {"ok": False, "reason": "invalid credential format"}

        tpl = self.registry.get(template_id)
        if tpl is None:
            return {"ok": False, "reason": "unknown template"}

        # 从旧凭证提取参数
        scope = list(old.scope)
        audience = old.aud
        new_ttl = ttl if ttl is not None else tpl.max_ttl
        new_alg = alg_tier if alg_tier is not None else old.alg_tier
        new_issuer = issuer_idn if issuer_idn is not None else old.iss

        # 模板校验
        violations = tpl.validate(scope, new_ttl, new_alg, audience)
        if violations:
            return {
                "ok": False,
                "reason": "template validation failed",
                "violations": violations,
            }

        result = self.issue_from_template(
            template_id=template_id,
            issuer_idn=new_issuer,
            subject_idn=old.sub,
            audience=audience,
            scope=scope,
            ttl=new_ttl,
            alg_tier=new_alg,
        )
        if result.get("ok"):
            result["renewed_from"] = old.jti
        return result


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def self_check():
    out = []

    # [A] 模板 CRUD
    reg = TemplateRegistry()
    r = reg.create("worker-tpl", "worker",
                   default_scope=["read", "write"],
                   allowed_scopes=["read", "write", "delete"],
                   max_ttl=7200,
                   allowed_algs=["sm2", "sm9"])
    out.append(("A1 创建成功", r["ok"]))
    tid = r["template"]["template_id"]
    out.append(("A2 含 template_id", bool(tid)))
    out.append(("A3 agent_type 正确", r["template"]["agent_type"] == "worker"))

    # 重复创建
    r = reg.create("worker-tpl-2", "worker", template_id=tid)
    out.append(("A4 重复 id 被拒", not r["ok"]))

    # 更新
    r = reg.update(tid, max_ttl=3600, name="worker-tpl-v2")
    out.append(("A5 更新成功", r["ok"]))
    out.append(("A6 max_ttl 已更新", r["template"]["max_ttl"] == 3600))

    # 查询
    out.append(("A7 get 返回模板", reg.get(tid) is not None))
    out.append(("A8 list 含 1 条", len(reg.list()) == 1))
    out.append(("A9 list 按 agent_type 过滤",
                len(reg.list("worker")) == 1))
    out.append(("A10 list 未知 agent_type 为空",
                len(reg.list("orchestrator")) == 0))

    # 删除
    r = reg.delete(tid)
    out.append(("A11 删除成功", r["ok"]))
    out.append(("A12 删除后为空", len(reg.list()) == 0))

    # 未知操作
    out.append(("A13 更新未知被拒", not reg.update("x", name="x")["ok"]))
    out.append(("A14 删除未知被拒", not reg.delete("x")["ok"]))

    # [B] 模板校验
    tpl = CredentialTemplate("tpl_test", "test", "worker",
                             default_scope=["read"],
                             allowed_scopes=["read", "write"],
                             max_ttl=3600,
                             allowed_algs=["sm2"],
                             allowed_audiences=["service://a"])

    # 全部合规
    v = tpl.validate(["read"], 1800, "sm2", "service://a")
    out.append(("B1 合规通过", len(v) == 0))

    # scope 越权
    v = tpl.validate(["delete"], 1800, "sm2", "service://a")
    out.append(("B2 scope 越权被拒", len(v) == 1))
    out.append(("B3 违规原因含 scope", "scope" in v[0]))

    # ttl 超限
    v = tpl.validate(["read"], 7200, "sm2", "service://a")
    out.append(("B4 ttl 超限被拒", len(v) == 1))
    out.append(("B5 违规原因含 ttl", "ttl" in v[0]))

    # alg 不允许
    v = tpl.validate(["read"], 1800, "sm9", "service://a")
    out.append(("B6 alg 不允许被拒", len(v) == 1))
    out.append(("B7 违规原因含 alg", "alg" in v[0]))

    # audience 不允许
    v = tpl.validate(["read"], 1800, "sm2", "service://b")
    out.append(("B8 audience 不允许被拒", len(v) == 1))
    out.append(("B9 违规原因含 audience", "audience" in v[0]))

    # 多重违规
    v = tpl.validate(["delete", "read"], 7200, "sm9", "service://b")
    out.append(("B10 多重违规全部报出", len(v) == 4))

    # [C] 状态持久化
    reg2 = TemplateRegistry()
    reg2.create("svc-tpl", "service", default_scope=["serve"],
                allowed_scopes=["serve"], max_ttl=600,
                allowed_algs=["sm2"])
    st = reg2.state_dict()
    reg3 = TemplateRegistry()
    reg3.load_state(st)
    out.append(("C1 恢复后模板数=1", len(reg3.list()) == 1))
    out.append(("C2 恢复后内容一致",
                reg3.list()[0]["name"] == "svc-tpl"))

    # [D] 基于模板签发（用真实 Platform）
    from agent_platform import Platform
    p = Platform(tenant="tpl-test")
    p.register_identity("agent://tpl/root", org="root",
                        agent_type="issuance")
    p.register_identity("agent://tpl/worker", org="org",
                        agent_type="worker")
    reg4 = TemplateRegistry()
    r = reg4.create("w-tpl", "worker",
                    default_scope=["read"],
                    allowed_scopes=["read", "write"],
                    max_ttl=3600,
                    allowed_algs=["sm2"],
                    allowed_audiences=["service://x"])
    tid4 = r["template"]["template_id"]

    issuer = TemplateCredentialIssuer(p, reg4)

    # 合规签发
    res = issuer.issue_from_template(tid4, "agent://tpl/root",
                                      "agent://tpl/worker")
    out.append(("D1 基于模板签发成功", res["ok"]))
    out.append(("D2 返回含 template_id", res.get("template_id") == tid4))

    # scope 越权
    res = issuer.issue_from_template(tid4, "agent://tpl/root",
                                      "agent://tpl/worker",
                                      scope=["delete"])
    out.append(("D3 scope 越权被拒", not res["ok"]))
    out.append(("D4 返回 violations",
                "violations" in res))

    # ttl 超限
    res = issuer.issue_from_template(tid4, "agent://tpl/root",
                                      "agent://tpl/worker",
                                      ttl=7200)
    out.append(("D5 ttl 超限被拒", not res["ok"]))

    # 未知模板
    res = issuer.issue_from_template("unknown", "agent://tpl/root",
                                      "agent://tpl/worker")
    out.append(("D6 未知模板被拒", not res["ok"]))

    # [E] 基于模板续期（FR2-04 入口）
    # 先签发一张凭证
    r = issuer.issue_from_template(tid4, "agent://tpl/root",
                                    "agent://tpl/worker")
    old_cred = r["cred"]
    # 续期
    res = issuer.renew_from_template(tid4, old_cred)
    out.append(("E1 续期成功", res["ok"]))
    out.append(("E2 返回 renewed_from",
                res.get("renewed_from") == old_cred["jti"]))
    out.append(("E3 续期凭证不同 jti",
                res["cred"]["jti"] != old_cred["jti"]))

    # 续期时 scope 被模板拒绝
    from agent_platform import _cred_from_wire
    # 构造一个 scope=delete 的旧凭证（绕过模板）
    c = p.issue_credential("agent://tpl/root", "agent://tpl/worker",
                           "service://x", ["delete"], ttl=3600)
    res = issuer.renew_from_template(tid4, c["cred"])
    out.append(("E4 续期 scope 越权被拒", not res["ok"]))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
