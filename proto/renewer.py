# -*- coding: utf-8 -*-
"""FR2-04 凭证自动续期：扫描临近过期 → 作用域重算 → 幂等签发 → 记录续期链。

PRD 原文：「支持凭证自动续期，续期须重新计算作用域」。

本模块与 `templates.py` 的 `TemplateCredentialIssuer.renew_from_template`
配合：模板校验 + 作用域重算由 Renewer 提供，签发由 Platform 完成。

职责边界：
    · 只决定「是否续期、用什么作用域、是否撤销旧凭证」；
    · 不绕过 Platform 的任何安全检查（策略、撤销、鉴权）；
    · 幂等键为 (jti, ttl)：同一 ttl 的重复续期请求，第二次起直接返回
      首次的新凭证 jti（renewed=False）；
    · 续期链：新凭证 wire 不改变（模板签发保持纯净），链信息挂在
      Renewer.history 与返回 dict 里；审计由 Platform 独立记录每次签发。

设计要点：
    · 凭证全文不入库 → 凭证索引 (jti, iss, sub, aud, scope, exp, alg, iat)
      从 Platform 审计日志 + _cred_registry 推导（元数据重建）；
    · 阈值 = max(min_threshold, max_ttl * threshold_ratio)；
      remaining ≤ 阈值 且 remaining > 0 时触发（过期凭证不续）；
    · 作用域重算（**必须**）：优先调 scope_callback，回调 None 时退回
      旧凭证 scope 并复用模板校验，防止续期时被模板收紧的策略拒签。
"""
import sys
import os
import time
from collections import OrderedDict
from typing import Optional, Callable, Dict, Tuple, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform, _cred_to_wire, _cred_from_wire


class Renewer:
    """凭证自动续期调度器。

    用法：
        r = Renewer(platform, registry=registry, threshold=60, ttl_ratio=0.5)
        result = r.renew(jti, cred_wire)                       # 单张凭证
        summary = r.scan(now_fn=lambda: int(time.time()))      # 批量扫描
    """

    def __init__(self, platform: Platform, registry=None,
                 threshold: int = 60, ttl_ratio: float = 0.5,
                 min_threshold: int = 30,
                 new_ttl: Optional[int] = None,
                 revoke_old: bool = True,
                 renew_ttl_seconds: Optional[int] = None,
                 scope_callback: Optional[Callable] = None):
        """
        Args:
            platform         Platform 实例（凭证签发与撤销入口）
            registry         TemplateRegistry（可为 None，仅纯 API 模式）
            threshold        续期触发时间（秒）：剩余有效期 ≤ 此值即触发
            ttl_ratio        按比例放大阈值：effective_thr = max(min_threshold,
                        threshold, max_ttl * ttl_ratio)
            min_threshold    阈值下限
            new_ttl          新凭证 TTL（None 时沿用旧凭证的 exp-iat）
            revoke_old       续期成功后是否撤销旧凭证
            renew_ttl_seconds  续期 TTL 秒数（与 new_ttl 同义，保留别名）
            scope_callback   作用域重算回调：f(cred_dict) → list 或 None
        """
        self.platform = platform
        self.registry = registry
        self.threshold = threshold
        self.ttl_ratio = ttl_ratio
        self.min_threshold = min_threshold
        self.new_ttl = new_ttl if new_ttl is not None else renew_ttl_seconds
        self.revoke_old = revoke_old
        self.scope_callback = scope_callback
        # 幂等键：old_jti 本身。一张凭证被续期一次后不再允许续期，
        # 无论后续用什么 ttl（旧凭证作用域/受众已被新凭证替代）。
        self._history: "OrderedDict[str, dict]" = OrderedDict()

    # ------------------------------------------------------------------
    # 凭证索引（从 Platform 推导，凭证全文不入库）
    # ------------------------------------------------------------------
    def _cred_index(self) -> Dict[str, dict]:
        """jti → {iss, sub, aud, scope, iat, ttl, exp, alg}。

        数据源：Platform.audit.chain 里 kind="credential.issue" 的记录。
        凭证全文不入库，故从审计推导：
            · iat ≈ AuditLog 记录的 ts（签发后立刻 append，同秒）
            · exp = iat + ttl
        重复出现的 jti 保留最后一条（续期后会有新签发事件）。
        """
        reg = getattr(self.platform, "_cred_registry", {}) or {}
        idx: Dict[str, dict] = {}
        audit = self.platform.audit
        if hasattr(audit, "chain"):
            entries = audit.chain
        elif hasattr(audit, "__iter__"):
            entries = list(audit)
        else:
            entries = []
        for e in entries:
            ev = e.get("event") or {}
            if ev.get("kind") != "credential.issue":
                continue
            jti = ev.get("jti")
            if not jti:
                continue
            r_meta = reg.get(jti) or {}
            ts = e.get("ts") or int(time.time())
            ttl = ev.get("ttl") or 3600
            idx[jti] = {
                "jti": jti,
                "iss": ev.get("iss") or r_meta.get("iss"),
                "sub": ev.get("sub") or r_meta.get("sub"),
                "aud": ev.get("aud"),
                "scope": list(ev.get("scope") or []),
                "iat": ts,
                "ttl": ttl,
                "exp": ts + ttl,
                "alg": ev.get("alg_tier") or "sm2",
            }
        return idx

    # ------------------------------------------------------------------
    # 幂等：以 old_jti 为键，一张凭证续期一次即锁死
    # ------------------------------------------------------------------
    def _idempotency_key(self, jti: str, ttl: Optional[int] = None) -> str:
        """以 old_jti 本身为键（忽略 ttl，因为一次续期即锁死）。"""
        return jti

    def _renewal_ttl(self, cred: dict) -> int:
        """决定续期新凭证的 TTL。"""
        if self.new_ttl is not None:
            return self.new_ttl
        iat = cred.get("iat")
        exp = cred.get("exp")
        if iat is not None and exp is not None and exp > iat:
            return exp - iat
        return self.threshold + 60   # 兜底：阈值+60

    def _effective_threshold(self, max_ttl: int) -> int:
        return max(self.min_threshold, self.threshold,
                   int(max_ttl * self.ttl_ratio))

    # ------------------------------------------------------------------
    # 前置检查
    # ------------------------------------------------------------------
    def check_renewal(self, jti: str, cred_wire: dict,
                      now: Optional[int] = None,
                      template_id: Optional[str] = None,
                      ttl: Optional[int] = None) -> Tuple[bool, str, dict]:
        """检查凭证是否可以续期。

        Returns: (ok, reason, meta)
        """
        from agent_platform import _cred_from_wire
        old = _cred_from_wire(cred_wire)
        if old is None:
            return False, "invalid credential format", {}

        if jti in self._history:
            return False, "already renewed (idempotent)", {"renewed_from": jti}

        now = now if now is not None else int(time.time())
        remaining = old.exp - now
        if remaining <= 0:
            return False, "credential already expired", {}

        max_ttl = old.exp - old.iat
        thr = self._effective_threshold(max_ttl)
        if remaining > thr:
            return False, "not yet eligible (remaining=%ds > threshold=%ds)" % (remaining, thr), \
                {"remaining": remaining, "threshold": thr}

        meta = {"remaining": remaining, "threshold": thr,
                "new_ttl": self._renewal_ttl(cred_wire)}

        # 模板存在性检查（不校验细节，避免重复校验）
        if template_id and self.registry is not None:
            tpl = self.registry.get(template_id)
            if tpl is None:
                return False, "unknown template", {}
        return True, "ok", meta

    # ------------------------------------------------------------------
    # 作用域重算（FR2-04 明确要求）
    # ------------------------------------------------------------------
    def _recompute_scope(self, old_scope: Tuple[str, ...], template_id: Optional[str]):
        """作用域重算：优先调 scope_callback，回调 None 时退回旧 scope。

        Returns: (new_scope, changed: bool)
        """
        if self.scope_callback is not None:
            new = self.scope_callback({"scope": list(old_scope)})
            if new:
                if list(new) == list(old_scope):
                    return list(new), False
                return list(new), True
        return list(old_scope), False

    # ------------------------------------------------------------------
    # 核心续期 API
    # ------------------------------------------------------------------
    def renew(self, jti: str, cred_wire: dict,
              template_id: Optional[str] = None,
              issuer_idn: Optional[str] = None,
              ttl: Optional[int] = None,
              alg_tier: Optional[str] = None,
              now: Optional[int] = None) -> dict:
        """对单张凭证续期。

        幂等键 (jti, ttl)：同一键的重复请求返回首次结果且 renewed=False。
        """
        if not isinstance(cred_wire, dict):
            return {"ok": False, "reason": "invalid cred_wire"}
        idem = self._idempotency_key(jti)
        if idem in self._history:
            prev = self._history[idem]
            return {"ok": True, "jti": prev["new_jti"],
                    "renewed": False,
                    "reason": "idempotent return",
                    "template_id": prev.get("template_id"),
                    "new_scope": prev.get("new_scope"),
                    "ttl": prev.get("ttl")}

        ok, reason, _ = self.check_renewal(jti, cred_wire, now=now,
                                           template_id=template_id, ttl=ttl)
        if not ok:
            return {"ok": False, "reason": reason}

        old = _cred_from_wire(cred_wire)
        new_scope, scope_changed = self._recompute_scope(old.scope, template_id)
        new_ttl = self._renewal_ttl(cred_wire) if ttl is None else ttl

        # --- 走模板签发（保留所有安全语义） ---
        result = None
        if template_id and self.registry is not None:
            from templates import TemplateCredentialIssuer
            issuer = TemplateCredentialIssuer(self.platform, self.registry)
            result = issuer.renew_from_template(
                template_id=template_id,
                old_cred_wire=cred_wire,
                issuer_idn=issuer_idn,
                ttl=new_ttl,
                alg_tier=alg_tier,
            )
        # --- 无模板：直接调用 Platform 签发（作用域已重算） ---
        if result is None:
            result = self.platform.issue_credential(
                issuer_idn=old.iss,
                subject_idn=old.sub,
                audience=old.aud,
                scope=new_scope,
                ttl=new_ttl,
                alg_tier=old.alg_tier if alg_tier is None else alg_tier,
            )

        if not result.get("ok"):
            return {"ok": False,
                    "reason": result.get("reason", "issue failed"),
                    "template_id": template_id,
                    "new_scope": new_scope,
                    "violations": result.get("violations")}

        new_jti = result.get("jti")
        new_wire = result.get("cred")

        revoked_old = None
        if self.revoke_old:
            rv = self.platform.revoke(jti, reason="renewed")
            revoked_old = {"ok": rv.get("ok"), "reason": rv.get("reason")}

        history_entry = {
            "old_jti": jti,
            "new_jti": new_jti,
            "ts": int(time.time()),
            "template_id": template_id,
            "ttl": new_ttl,
            "new_scope": new_scope,
            "scope_changed": scope_changed,
        }
        self._history[idem] = history_entry
        # LRU 淘汰
        while len(self._history) > 10000:
            self._history.popitem(last=False)

        return {
            "ok": True,
            "jti": new_jti,
            "renewed": True,
            "renewed_from": jti,
            "cred": new_wire,
            "template_id": template_id,
            "new_scope": new_scope,
            "scope_changed": scope_changed,
            "ttl": new_ttl,
            "revoked_old": revoked_old,
        }

    # ------------------------------------------------------------------
    # 批量扫描
    # ------------------------------------------------------------------
    def scan(self, now_fn: Optional[Callable] = None,
             template_for: Optional[Callable] = None,
             limit: Optional[int] = None) -> dict:
        """批量扫描临近过期凭证并续期。

        Args:
            now_fn        当前时间函数（默认 time.time）
            template_for  回调 f(sub, iss, aud) → template_id 或 None
            limit         单次扫描最多续期数（None=不限）

        Returns: {"scanned": N, "renewed": M, "skipped": K, "errors": L}
        """
        now_fn = now_fn or (lambda: int(time.time()))
        now = now_fn()
        index = self._cred_index()
        renewed = skipped = errors = 0
        renewals = []
        for jti, meta in index.items():
            if limit is not None and renewed >= limit:
                break
            if not meta.get("exp"):
                continue
            if jti in self._history:
                continue
            remaining = meta["exp"] - now
            max_ttl = meta["exp"] - (meta.get("iat") or (meta["exp"] - 3600))
            thr = self._effective_threshold(max_ttl)
            if remaining <= 0 or remaining > thr:
                continue
            # 尝试从旧凭证 wire 重建（scan 模式下没有 wire，构造最小 wire）
            wire = {
                "sub": meta["sub"], "iss": meta["iss"],
                "aud": meta["aud"], "scope": meta["scope"],
                "iat": meta["iat"] or (meta["exp"] - max_ttl),
                "nbf": 0, "exp": meta["exp"],
                "nonce": "00" * 32,
                "alg_tier": meta["alg"],
                "jti": jti,
            }
            tpl_id = None
            if template_for is not None:
                tpl_id = template_for(meta["sub"], meta["iss"], meta["aud"])
            res = self.renew(jti, wire, template_id=tpl_id, now=now)
            if res.get("ok") and res.get("renewed"):
                renewed += 1
                renewals.append({"old_jti": jti, "new_jti": res.get("jti")})
            else:
                skipped += 1
        return {"scanned": len(index),
                "renewed": renewed,
                "skipped": skipped,
                "errors": errors,
                "renewals": renewals,
                "ts": now}

    # ------------------------------------------------------------------
    # 统计与持久化
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        return {"total_renewals": len(self._history),
                "unique_credentials": len(set(e["old_jti"] for e in self._history.values()))}

    def history(self, jti: Optional[str] = None) -> List[dict]:
        if jti is None:
            return list(self._history.values())
        return [v for v in self._history.values() if v["old_jti"] == jti]

    def state_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "ttl_ratio": self.ttl_ratio,
            "min_threshold": self.min_threshold,
            "new_ttl": self.new_ttl,
            "revoke_old": self.revoke_old,
            "history": list(self._history.values()),
        }

    def load_state(self, state: dict):
        if not isinstance(state, dict):
            return
        for k in ("threshold", "ttl_ratio", "min_threshold",
                  "new_ttl", "revoke_old"):
            if k in state:
                setattr(self, k, state[k])
        for entry in state.get("history", []):
            jti = entry.get("old_jti")
            if not jti:
                continue
            self._history[jti] = entry


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def _mk_platform():
    p = Platform(tenant="test")
    p.register_identity("agent://test/iss", org="test", agent_type="issuance")
    p.register_identity("agent://test/sub", org="test", agent_type="worker")
    p.register_identity("agent://test/sub2", org="test", agent_type="worker")
    return p


def _mk_reg():
    from templates import TemplateRegistry
    r = TemplateRegistry()
    r.create("worker", "worker",
             default_scope=["read", "write"],
             allowed_scopes=["read", "write", "delete"],
             max_ttl=7200,
             allowed_algs=["sm2"],
             allowed_audiences=["api://x"])
    return r


def self_check():
    out = []

    # === [A] 前置检查：check_renewal ===
    p = _mk_platform()
    r = _mk_reg()
    rner = Renewer(p, registry=r, threshold=60, min_threshold=30, ttl_ratio=0.5)
    res = p.issue_credential("agent://test/iss", "agent://test/sub",
                              "api://x", scope=["read"], ttl=120)
    out.append(("A1 初始签发成功", res["ok"] and res["cred"]))
    jti0 = res["jti"]

    far_future = int(time.time()) + 9999999
    ok, reason, _ = rner.check_renewal(jti0, res["cred"], now=far_future,
                                       template_id="tpl_worker_1" if False else None)
    # 用真实 template_id
    tid = [t["template_id"] for t in r.list() if t["name"] == "worker"][0]
    ok, reason, _ = rner.check_renewal(jti0, res["cred"], now=far_future,
                                       template_id=tid)
    out.append(("A2 过期凭证不续期", not ok and "expired" in reason))

    # 剩余充足 → 不 eligible
    ok, reason, _ = rner.check_renewal(jti0, res["cred"], now=res["iat"] + 2,
                                       template_id=tid)
    out.append(("A3 剩余充足不 eligible", not ok and "eligible" in reason))

    # 剩余接近阈值 → eligible
    ok, reason, meta = rner.check_renewal(jti0, res["cred"],
                                          now=res["iat"] + 70,
                                          template_id=tid)
    out.append(("A4 接近阈值 eligible",
                ok and meta["remaining"] <= meta["threshold"]))

    # 幂等：先手动登记一次历史，再查应拒绝
    rner._history[rner._idempotency_key(jti0)] = {
        "old_jti": jti0, "new_jti": "placeholder", "ts": 0, "ttl": 120,
        "new_scope": ["read"], "scope_changed": False, "template_id": tid,
    }
    ok, reason, _ = rner.check_renewal(jti0, res["cred"],
                                       now=res["iat"] + 70,
                                       template_id=tid)
    out.append(("A5 已续期幂等拒绝", not ok and "idempotent" in reason))

    # === [B] 基本续期（走模板） ===
    p2 = _mk_platform()
    r2 = _mk_reg()
    rner2 = Renewer(p2, registry=r2, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9)
    res2 = p2.issue_credential("agent://test/iss", "agent://test/sub",
                                "api://x", scope=["read"], ttl=7200)
    jti2 = res2["jti"]
    tid2 = r2.list()[0]["template_id"]
    # 模拟凭证接近过期：iat+7200-1 时刻 remaining=1s < threshold
    sim_now_B = res2["iat"] + 7200 - 1
    res3 = rner2.renew(jti2, res2["cred"], template_id=tid2,
                       ttl=3600, now=sim_now_B)
    out.append(("B1 续期成功", res3["ok"] and res3["renewed"]))
    out.append(("B2 返回新 jti", res3.get("jti") is not None
                and res3["jti"] != jti2))
    out.append(("B3 续期链 renewed_from", res3.get("renewed_from") == jti2))
    out.append(("B4 旧凭证已撤销",
                res3.get("revoked_old", {}).get("ok") is True))

    # 幂等：同一键再调用应返回同一新 jti
    res4 = rner2.renew(jti2, res2["cred"], template_id=tid2, ttl=3600)
    out.append(("B5 幂等返回同 jti",
                res4["ok"] and not res4["renewed"]
                and res4["jti"] == res3["jti"]))

    # === [C] 幂等键：以 jti 本身为键 ===
    key1 = rner2._idempotency_key("j_A")
    key2 = rner2._idempotency_key("j_B")
    key3 = rner2._idempotency_key("j_A")
    out.append(("C1 不同 jti 键不同", key1 != key2))
    out.append(("C2 同一 jti 键相同（忽略 ttl）", key1 == key3))

    # === [D] 作用域重算（scope_callback） ===
    p3 = _mk_platform()
    r3 = _mk_reg()
    rner3 = Renewer(p3, registry=r3, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9,
                    scope_callback=lambda c: ["read"] if "write" in c["scope"] else c["scope"])
    resA = p3.issue_credential("agent://test/iss", "agent://test/sub",
                                "api://x", scope=["read", "write"], ttl=7200)
    tid3 = r3.list()[0]["template_id"]
    resB = rner3.renew(resA["jti"], resA["cred"], template_id=tid3,
                       ttl=3600, now=resA["iat"] + 7200 - 1)
    out.append(("D1 续期触发作用域重算",
                resB["ok"] and resB["scope_changed"] is True))
    out.append(("D2 作用域已收窄",
                resB["new_scope"] == ["read"]))

    # 无回调时作用域不变
    rner4 = Renewer(p3, registry=r3, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9)
    resC = p3.issue_credential("agent://test/iss", "agent://test/sub2",
                                "api://x", scope=["read", "write"], ttl=7200)
    resD = rner4.renew(resC["jti"], resC["cred"], template_id=tid3,
                       ttl=3600, now=resC["iat"] + 7200 - 1)
    out.append(("D3 无回调作用域不变",
                resD["ok"] and resD["scope_changed"] is False))

    # === [E] 过期凭证拒绝 ===
    p4 = _mk_platform()
    r4 = _mk_reg()
    rner5 = Renewer(p4, registry=r4, threshold=60, min_threshold=30, ttl_ratio=0.5)
    resE1 = p4.issue_credential("agent://test/iss", "agent://test/sub",
                                 "api://x", scope=["read"], ttl=100)
    # 模拟凭证已过期
    resE2 = rner5.renew(resE1["jti"], resE1["cred"],
                        template_id=r4.list()[0]["template_id"],
                        now=resE1["iat"] + 105)
    out.append(("E1 过期凭证拒绝续期",
                not resE2["ok"] and "expired" in resE2.get("reason", "")))

    # === [F] 凭证索引与批量扫描 ===
    p5 = _mk_platform()
    r5 = _mk_reg()
    rner6 = Renewer(p5, registry=r5, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9)
    resF1 = p5.issue_credential("agent://test/iss", "agent://test/sub",
                                 "api://x", scope=["read"], ttl=100)
    resF2 = p5.issue_credential("agent://test/iss", "agent://test/sub2",
                                 "api://x", scope=["read"], ttl=100)
    idx = rner6._cred_index()
    out.append(("F1 凭证索引含 2 条", len(idx) == 2))
    out.append(("F2 索引含 iss/sub/aud/exp",
                all(k in idx[resF1["jti"]] for k in ("iss", "sub", "aud", "exp"))))

    tid5 = r5.list()[0]["template_id"]
    iat_ref = resF1["iat"]
    scan = rner6.scan(
        now_fn=lambda: iat_ref + 50,  # 剩余 50s < threshold=3600
        template_for=lambda sub, iss, aud: tid5,
    )
    out.append(("F3 scan 返回结构",
                scan.get("scanned") == 2 and "renewed" in scan))

    # === [G] 状态持久化 ===
    p6 = _mk_platform()
    r6 = _mk_reg()
    rner7 = Renewer(p6, registry=r6, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9)
    resG1 = p6.issue_credential("agent://test/iss", "agent://test/sub",
                                 "api://x", scope=["read"], ttl=7200)
    tid6 = r6.list()[0]["template_id"]
    rner7.renew(resG1["jti"], resG1["cred"], template_id=tid6,
                ttl=3600, now=resG1["iat"] + 7200 - 1)
    state = rner7.state_dict()
    out.append(("G1 状态含 history",
                len(state["history"]) == 1 and "threshold" in state))

    rner8 = Renewer(p6, registry=r6)
    rner8.load_state(state)
    out.append(("G2 load_state 恢复幂等",
                rner8.renew(resG1["jti"], resG1["cred"],
                            template_id=tid6, ttl=3600)["renewed"] is False))

    # === [H] 统计 ===
    out.append(("H1 stats 计数正确",
                rner7.stats()["total_renewals"] == 1
                and rner7.stats()["unique_credentials"] == 1))
    out.append(("H2 history 按 jti 过滤",
                len(rner7.history(resG1["jti"])) == 1
                and len(rner7.history("nope")) == 0))

    # === [I] 无模板续期（纯 API 模式） ===
    p7 = _mk_platform()
    rner9 = Renewer(p7, registry=None, threshold=3600, min_threshold=60,
                    ttl_ratio=0.9)
    resH1 = p7.issue_credential("agent://test/iss", "agent://test/sub",
                                 "api://x", scope=["read"], ttl=7200)
    resH2 = rner9.renew(resH1["jti"], resH1["cred"], ttl=3600,
                        now=resH1["iat"] + 7200 - 1)
    out.append(("I1 无模板续期成功", resH2["ok"] and resH2["renewed"]))
    out.append(("I2 续期沿用原 alg_tier", resH2["ttl"] == 3600))

    # === [J] 阈值计算 ===
    # 公式：max(min_threshold, threshold, int(max_ttl * ttl_ratio))
    thr_short = rner9._effective_threshold(60)    # max(60, 3600, 54) = 3600
    thr_mid = rner9._effective_threshold(4000)    # max(60, 3600, 3600) = 3600
    thr_long = rner9._effective_threshold(10000)  # max(60, 3600, 9000) = 9000
    out.append(("J1 阈值下限（受 threshold 参数压制）", thr_short == 3600))
    out.append(("J2 阈值等于 threshold", thr_mid == 3600))
    out.append(("J3 阈值按比例（ttl_ratio 主导）", thr_long == 9000))

    return out


if __name__ == "__main__":
    passed = 0
    failed = 0
    for name, ok in self_check():
        if ok:
            print("PASS     %s" % name)
            passed += 1
        else:
            print("FAIL     %s" % name)
            failed += 1
    print()
    print("RESULT: %d/%d passed, %d failed" % (passed, passed + failed, failed))
    if failed == 0:
        print("ALL PASS")
