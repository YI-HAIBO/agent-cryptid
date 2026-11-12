# -*- coding: utf-8 -*-
"""Platform：智能体密码身份中台的进程内核心 API 层。

对齐《技术方案》10 个核心 API：
    API-01 标识注册        register_identity
    API-02 标识停用        disable_identity
    API-03 凭证签发        issue_credential
    API-04 凭证校验        verify_credential
    API-05 委托签发        issue_delegation
    API-06 委托链验证      verify_delegation_chain
    API-07 撤销            revoke
    API-08 撤销快照        revocation_snapshot
    API-09 审计检索        audit_query
    API-10 策略配置        configure_policy

设计：
    - 单进程内运行，接口以方法形式暴露；后续可包一层 HTTP（Flask/FastAPI）。
    - 控制面与数据面分离：签发与撤销写库；校验与链验证只读本地缓存。
    - 撤销快照支持版本化：每次 revoke 后版本号 +1，客户端按版本号拉增量。
    - 审计查询返回事件列表并附上哈希链验证结果。
"""
import hashlib
import json
import os
import sys
import time
from typing import List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from identity import IdentityAuthority  # noqa: E402
from credential import (  # noqa: E402
    Credential, ALG_SM2, ALG_SM9, ALG_SM2_MLDSA, ALG_HASH_SIG,
    _SM9_AVAILABLE, _MLD_AVAILABLE, _SLH_AVAILABLE,
)
from delegation import build_chain, verify_chain, AuditLog  # noqa: E402
from revocation import RevokeAccumulator  # noqa: E402
from audit_anchor import AuditAnchor, AuditAnchorStore  # noqa: E402
import sm2  # noqa: E402

# v2.16 抗量子档位（纯 Python 零依赖）：ML-DSA / SLH-DSA
if _MLD_AVAILABLE:
    import mldsa  # noqa: E402
else:
    mldsa = None
if _SLH_AVAILABLE:
    import slhdsa  # noqa: E402
else:
    slhdsa = None


def _ts():
    return int(time.time())


class Platform:
    """智能体密码身份中台核心。

    tenant       租户 ID，物理隔离的边界
    persistence  可选 SQLiteBackend；None 时用内存存储
    policy       策略配置
    acc_capacity 撤销累加器叶子容量（2 的幂，默认 1024）；
                 改小可让测试快速触发表满冻结。持久化状态里也带 capacity，
                 恢复时若与当前配置不一致会拒绝恢复并退化为 replay 重建。
    """

    def __init__(self, tenant="default", policy=None, persistence=None,
                 nonce_store=None, nonce_ttl=86400, acc_capacity=1024):
        self.tenant = tenant
        self.ia = IdentityAuthority()
        self.audit = AuditLog()
        self._pers = persistence
        # v2.9：凭证签发登记簿（jti -> issuer_idn），支撑 FR4-02 按标识批量撤销
        self._issued_creds = {}  # jti -> issuer_idn
        # v2.10：凭证血缘登记簿，支撑 FR4-02 的「及其下游委托」级联
        #   jti -> {"iss": 签发方, "sub": 主体, "parent": 父凭证 jti 或 None}
        self._cred_registry = {}
        # v2.10：委托图反向索引（父 jti -> [子 jti]），级联时做传递闭包
        self._cred_children = {}

        # 存储（内存缓存，有 persistence 时同步写入）
        self._identities = {}       # idn -> {"pub": pub, "status", "meta": {...}}
        self._revoked_jtis = set()
        self._revocation_log = []
        # v2.1：Merkle 累加器撤销——控制面下发根、数据面离线验证证明
        self._acc = RevokeAccumulator(capacity=acc_capacity)
        # v2.1：Nonce 存储——默认 MemoryNonceStore；可注入 SQLite/Redis 实现
        from nonce_store import MemoryNonceStore
        self._nonce_store = nonce_store if nonce_store is not None \
            else MemoryNonceStore()
        self._nonce_ttl = nonce_ttl
        # 兼容别名：老代码/测试直接引用 _seen_nonces 依然可用
        self._seen_nonces = self._nonce_store
        # v2.2：审计锚点存储——定期签名审计链根，形成防篡改时间承诺
        # 若 pers 非空，锚点自动持久化到 SQLite 的 audit_anchors 表
        self._anchor_store = AuditAnchorStore(self._pers)
        # v2.16：抗量子密钥缓存——按 (idn, key_version, 算法) 惰性派生并缓存。
        # SLH-DSA 公钥树构造较慢，绝不在注册路径上同步生成，只在真正按 PQ
        # 档位签发/校验时才派生一次；私钥由 mk 确定性派生，重启后无需持久化。
        self._pq_cache = {}
        self._policy = policy or {
            "default_scope": [],
            "max_ttl_seconds": 86400,
            # v2.16：放开抗量子档位（sm2-ml-dsa 混合 / hash-signature）
            "allowed_algs": [ALG_SM2, ALG_SM9, ALG_SM2_MLDSA, ALG_HASH_SIG],
            # v2.11 FR3-04：委托深度上限，None=不限制。
            # 生产建议设 8~16；测试与压测需高深度时显式调高或设 None。
            "max_delegation_depth": None,
            "tenant": tenant,
        }

        if self._pers is not None:
            self._hydrate()
            self._install_audit_hook()

    # ---------------------------------------------------------------
    # 持久化钩子
    # ---------------------------------------------------------------
    def _hydrate(self):
        """从持久化后端载入已有状态。"""
        # 标识
        for rec in self._pers.list_identities(self.tenant, limit=10000):
            idn = rec["idn"]
            try:
                pub = (int(rec["pub_x"], 16), int(rec["pub_y"], 16))
            except Exception:
                continue
            self._identities[idn] = {
                "pub": pub,
                "status": rec["status"],
                "meta": rec["meta"],
            }
            # 同步到 IdentityAuthority 的登记簿
            try:
                self.ia._registry[idn.encode("utf-8")] = {"pub": pub, "key_version": 0}
            except Exception:
                pass
        # 撤销
        snap = self._pers.revocation_snapshot(self.tenant, since_version=0)
        self._revocation_log = list(snap["entries"])
        self._revoked_jtis = {e["jti"] for e in snap["entries"]}
        # v2.4：优先从 revocation_state 表直接恢复累加器（含 leaves 与
        # jti 索引），O(1) 加载；失败或首次启动才退化为 O(n) replay。
        restored = self._try_restore_accumulator()
        if not restored:
            # v2.1 兜底：按持久化顺序 replay 撤销记录，重建 Merkle 累加器
            # 累加器只增不减、revoke 幂等，因此 replay 后根与原撤销过程一致。
            for entry in snap["entries"]:
                jti = entry.get("jti")
                if not jti:
                    continue
                try:
                    self._acc.revoke(jti)
                except ValueError:
                    pass  # 幂等：重复 jti 忽略
            self._save_accumulator_state()
        # 策略
        stored = self._pers.get_policy(self.tenant)
        if stored:
            self._policy.update(stored)
        # v2.2：审计锚点从持久化后端恢复
        try:
            rows = self._pers.list_audit_anchors(self.tenant, limit=10000)
            self._anchor_store.hydrate(rows, self.tenant)
        except Exception:
            pass
        # v2.10：从审计日志重建凭证血缘，使重启后仍能级联撤销
        self._rebuild_cred_registry()

    def _save_accumulator_state(self):
        """把当前累加器状态快照写入持久化后端（幂等覆盖）。"""
        if self._pers is None:
            return False
        if not hasattr(self._pers, "save_revocation_state"):
            return False  # 老后端无该表，静默降级为 replay
        try:
            self._pers.save_revocation_state(
                self.tenant, self._acc.state_dict())
            return True
        except Exception:
            return False

    def _try_restore_accumulator(self):
        """从持久化后端直接恢复累加器状态。成功返回 True。"""
        if self._pers is None:
            return False
        if not hasattr(self._pers, "get_revocation_state"):
            return False
        try:
            st = self._pers.get_revocation_state(self.tenant)
        except Exception:
            return False
        if not st:
            return False
        return self._acc.load_state(st)

    def _install_audit_hook(self):
        """给 self.audit.append 装上持久化钩子。"""
        pers = self._pers
        tenant = self.tenant
        orig = self.audit.append

        def _hooked(event):
            r = orig(event)
            try:
                seq = len(self.audit.chain) - 1
                e = self.audit.chain[-1]
                pers.append_audit(tenant, seq, _ts(),
                                  event.get("kind", ""),
                                  e["hash"], e["prev"], event)
            except Exception:
                pass  # 持久化失败不阻塞主流程
            return r

        self.audit.append = _hooked

    # ---------------------------------------------------------------
    # API-01 标识注册
    # ---------------------------------------------------------------
    def register_identity(self, idn, org=None, agent_type=None,
                          owner=None, initial_scope=None,
                          tags=None) -> dict:
        """创建标识；返回标识与密钥凭据（私钥仅在注册响应中返回一次）。

        v2.11 FR1-04：tags 为自由标签列表，供按标签检索标识。
        """
        if not idn:
            return {"ok": False, "reason": "empty idn"}
        if idn in self._identities:
            return {"ok": False, "reason": "already registered"}

        d_id, pub_id, key_ver = self.ia.issue(idn.encode("utf-8"))
        self._identities[idn] = {
            "pub": pub_id,
            "status": "active",
            "key_version": key_ver,
            "meta": {
                "org": org,
                "agent_type": agent_type,
                "owner": owner,
                "tags": list(tags) if tags else [],
                "initial_scope": initial_scope or [],
                "created_at": _ts(),
                "key_version": key_ver,
            },
        }
        self.audit.append({
            "kind": "identity.register",
            "tenant": self.tenant,
            "idn": idn,
            "pub_x": "%064x" % pub_id[0],
            "org": org,
            "agent_type": agent_type,
            "tags": list(tags) if tags else [],
            "key_version": key_ver,
        })
        if self._pers is not None:
            self._pers.put_identity(
                self.tenant, idn, "%064x" % pub_id[0], "%064x" % pub_id[1],
                "active", self._identities[idn]["meta"])
        return {
            "ok": True,
            "idn": idn,
            "pub_x": "%064x" % pub_id[0],
            "pub_y": "%064x" % pub_id[1],
            "priv_d": "%064x" % d_id,   # 客户端一次性接收后安全存储
            "key_version": key_ver,
            "meta": {"org": org, "agent_type": agent_type, "owner": owner,
                     "tags": list(tags) if tags else []},
        }

    def list_identities(self, org=None, owner=None, tag=None,
                        status=None, agent_type=None,
                        limit=1000) -> dict:
        """FR1-04：按组织 / 责任人 / 标签 / 状态 / 类型检索标识。

        所有过滤条件为 AND 关系；任一为 None 时不参与过滤。
        tag 参数支持单个字符串（精确匹配单个标签）——
        标识的标签是集合，只要包含该 tag 即命中。
        """
        out = []
        for idn, rec in self._identities.items():
            meta = rec.get("meta") or {}
            if org is not None and meta.get("org") != org:
                continue
            if owner is not None and meta.get("owner") != owner:
                continue
            if agent_type is not None and meta.get("agent_type") != agent_type:
                continue
            if status is not None and rec.get("status") != status:
                continue
            if tag is not None:
                tags = meta.get("tags") or []
                if tag not in tags:
                    continue
            out.append({
                "idn": idn,
                "status": rec.get("status"),
                "pub_x": "%064x" % rec["pub"][0],
                "pub_y": "%064x" % rec["pub"][1],
                "meta": {
                    "org": meta.get("org"),
                    "agent_type": meta.get("agent_type"),
                    "owner": meta.get("owner"),
                    "tags": list(meta.get("tags") or []),
                    "initial_scope": meta.get("initial_scope") or [],
                    "created_at": meta.get("created_at"),
                    "disabled_at": meta.get("disabled_at"),
                    "disable_reason": meta.get("disable_reason"),
                    "enabled_at": meta.get("enabled_at"),
                },
            })
            if len(out) >= limit:
                break
        # 稳定排序：先 active 后 disabled，再按 idn
        out.sort(key=lambda r: (0 if r["status"] == "active" else 1, r["idn"]))
        return {"ok": True, "total": len(out), "identities": out}

    def update_identity_tags(self, idn, tags=None, add=None,
                             remove=None) -> dict:
        """FR1-04 配套：事后为已注册标识增删标签，不改身份本身。"""
        if idn not in self._identities:
            return {"ok": False, "reason": "unknown identity"}
        meta = self._identities[idn].setdefault("meta", {})
        cur = set(meta.get("tags") or [])
        if tags is not None:
            cur = set(tags)
        if add:
            cur |= set(add)
        if remove:
            cur -= set(remove)
        meta["tags"] = sorted(cur)
        self.audit.append({
            "kind": "identity.update_tags",
            "tenant": self.tenant,
            "idn": idn,
            "tags": meta["tags"],
        })
        if self._pers is not None:
            pub = self._identities[idn]["pub"]
            self._pers.put_identity(
                self.tenant, idn, "%064x" % pub[0], "%064x" % pub[1],
                self._identities[idn]["status"], meta)
        return {"ok": True, "idn": idn, "tags": meta["tags"]}

    def _derive_priv(self, idn):
        """按标识记录中的 key_version 选对应 mk 派生私钥。"""
        from identity import _kdf
        rec = self._identities.get(idn)
        kv = rec.get("key_version", 0) if rec else 0
        mk = self.ia._get_mk(kv)
        return int.from_bytes(
            _kdf(mk, idn.encode("utf-8")), "big"
        ) % (sm2.N - 1) + 1

    # ---------------------------------------------------------------
    # v2.16 抗量子密钥派生（惰性 + 缓存）
    # ---------------------------------------------------------------
    def _pq_seed(self, idn, kv, domain):
        """由 mk[kv] + 标识 + 域分隔符派生 PQ 密钥种子（确定性、可复现）。

        域分隔保证同一标识的 ML-DSA 与 SLH-DSA 种子互不相关，
        且与 SM2 派生密钥（无域分隔）互不相关。
        """
        from identity import _kdf
        mk = self.ia._get_mk(kv)
        return _kdf(mk, idn.encode("utf-8") + b"\x00pq\x00" + domain)

    def _pq_keys(self, idn, kv, kind):
        """惰性派生 PQ 密钥对并缓存。kind ∈ {"mldsa", "slhdsa"}。

        SLH-DSA 的公钥树构造较慢（纯 Python 下约 20 秒），因此绝不在
        注册路径上同步生成；仅在真正按 PQ 档位签发或校验时派生一次，
        之后命中缓存。私钥由 mk 确定性派生，无需落盘即可重建。
        """
        key = (idn, kv, kind)
        cached = self._pq_cache.get(key)
        if cached is not None:
            return cached
        seed = self._pq_seed(idn, kv, kind.encode("ascii"))
        if kind == "mldsa":
            if not _MLD_AVAILABLE:
                raise RuntimeError("ML-DSA 未编译，无法使用抗量子档位")
            cached = mldsa.keygen(seed)
        else:
            if not _SLH_AVAILABLE:
                raise RuntimeError("SLH-DSA 未编译，无法使用抗量子档位")
            cached = slhdsa.keygen(seed)
        self._pq_cache[key] = cached
        return cached

    def _pq_sk(self, idn, kv, kind):
        return self._pq_keys(idn, kv, kind)[1]

    def _pq_pk(self, idn, kv, kind):
        return self._pq_keys(idn, kv, kind)[0]

    # ---------------------------------------------------------------
    # API-02 标识停用
    # ---------------------------------------------------------------
    def disable_identity(self, idn, reason="user request") -> dict:
        if idn not in self._identities:
            return {"ok": False, "reason": "unknown identity"}
        self._identities[idn]["status"] = "disabled"
        self._identities[idn]["meta"]["disabled_at"] = _ts()
        self._identities[idn]["meta"]["disable_reason"] = reason
        self.audit.append({
            "kind": "identity.disable",
            "tenant": self.tenant,
            "idn": idn,
            "reason": reason,
        })
        if self._pers is not None:
            pub = self._identities[idn]["pub"]
            self._pers.put_identity(
                self.tenant, idn, "%064x" % pub[0], "%064x" % pub[1],
                "disabled", self._identities[idn]["meta"])
        return {"ok": True, "idn": idn, "status": "disabled", "ts": _ts()}

    # ---------------------------------------------------------------
    # API-02b 标识重新启用（v2.10 FR1-03）
    # ---------------------------------------------------------------
    def enable_identity(self, idn, reason="user request") -> dict:
        """恢复已停用的标识。FR1-03 必备项的 enable 侧。

        与「重新注册」的区别（关键语义）：
            - enable 复用原密钥对与元数据，标识身份不变；
            - 重新注册会生成新密钥对，等于换了一个身份，
              且当前 register_identity 对已存在标识直接拒绝。
        因此"重新启用"必须走本方法，不能用 register 代替。

        历史痕迹：disabled_at 保留（表明曾于何时停用），
        但 disable_reason 清空——当前状态已回到 active，
        不应再挂着一个停用原因误导治理台。
        """
        if idn not in self._identities:
            return {"ok": False, "reason": "unknown identity"}
        rec = self._identities[idn]
        if rec["status"] == "active":
            return {"ok": False, "reason": "already active"}
        rec["status"] = "active"
        rec["meta"]["enabled_at"] = _ts()
        rec["meta"]["enable_reason"] = reason
        rec["meta"]["disable_reason"] = None
        self.audit.append({
            "kind": "identity.enable",
            "tenant": self.tenant,
            "idn": idn,
            "reason": reason,
        })
        if self._pers is not None:
            pub = rec["pub"]
            self._pers.put_identity(
                self.tenant, idn, "%064x" % pub[0], "%064x" % pub[1],
                "active", rec["meta"])
        return {"ok": True, "idn": idn, "status": "active", "ts": _ts()}

    # ---------------------------------------------------------------
    # API-03 凭证签发
    # ---------------------------------------------------------------
    def issue_credential(self, issuer_idn, subject_idn, audience,
                         scope, ttl=None, alg_tier=ALG_SM2,
                         task_context=None) -> dict:
        """签发凭证。issuer 必须是 active 的已注册标识。"""
        if issuer_idn not in self._identities:
            return {"ok": False, "reason": "unknown issuer"}
        if self._identities[issuer_idn]["status"] != "active":
            return {"ok": False, "reason": "issuer disabled"}
        if subject_idn not in self._identities:
            return {"ok": False, "reason": "unknown subject"}
        if self._identities[subject_idn]["status"] != "active":
            return {"ok": False, "reason": "subject disabled"}
        if ttl is None:
            ttl = self._policy["max_ttl_seconds"]
        if ttl > self._policy["max_ttl_seconds"]:
            ttl = self._policy["max_ttl_seconds"]
        if alg_tier not in self._policy["allowed_algs"]:
            return {"ok": False, "reason": "alg_tier not allowed"}

        # v2.6: alg_tier 决定签发密钥
        # - SM2: 用 _derive_priv 派生 d_id（SM2 标量私钥）
        # - SM9: 直接用主签名私钥 ks（无证书，ds_A 由 (ks, ID) 派生）
        # v2.16: 抗量子档位
        # - sm2-ml-dsa: SM2 分量用 d_id，ML-DSA 分量用惰性派生的 pq_sk
        # - hash-signature: 用惰性派生的 SLH-DSA pq_sk
        issuer_kv = self._identities[issuer_idn].get("key_version", 0)
        pq_sk = None
        if alg_tier == ALG_SM9:
            if not getattr(self.ia, "ks", None):
                return {"ok": False, "reason": "sm9 master key unavailable"}
            priv = self.ia._get_ks(issuer_kv)
            issuer_pub = None
        elif alg_tier == ALG_SM2_MLDSA:
            if not _MLD_AVAILABLE:
                return {"ok": False, "reason": "mldsa unavailable"}
            priv = self._derive_priv(issuer_idn)
            issuer_pub = self._identities[issuer_idn].get("pub")
            pq_sk = self._pq_sk(issuer_idn, issuer_kv, "mldsa")
        elif alg_tier == ALG_HASH_SIG:
            if not _SLH_AVAILABLE:
                return {"ok": False, "reason": "slhdsa unavailable"}
            priv = self._derive_priv(issuer_idn)  # 占位：该档位不使用 SM2 分量
            issuer_pub = self._identities[issuer_idn].get("pub")
            pq_sk = self._pq_sk(issuer_idn, issuer_kv, "slhdsa")
        else:
            priv = self._derive_priv(issuer_idn)
            # v2.15：复用注册时已算好的公钥，省掉每次签发的标量乘
            # （缺失时 sign 内部会退回自行计算，不影响正确性）
            issuer_pub = self._identities[issuer_idn].get("pub")

        cred = Credential(sub=subject_idn, iss=issuer_idn, aud=audience,
                          scope=scope, exp=_ts() + ttl, alg_tier=alg_tier,
                          kv=issuer_kv)
        cred.sign(issuer_idn, priv, pub=issuer_pub, pq_sk=pq_sk)
        # v2.9：登记 jti → issuer_idn，支撑按标识批量撤销（FR4-02）
        self._issued_creds[cred.jti] = issuer_idn
        # v2.10：登记凭证血缘（根凭证无父），支撑级联撤销
        # v2.11 FR3-04：根凭证 depth=0
        self._register_cred(cred.jti, issuer_idn, subject_idn, None,
                            depth=0)
        self.audit.append({
            "kind": "credential.issue",
            "tenant": self.tenant,
            "iss": issuer_idn, "sub": subject_idn,
            "aud": audience, "jti": cred.jti,
            "scope": list(scope), "ttl": ttl, "alg_tier": alg_tier,
        })
        return {
            "ok": True, "jti": cred.jti, "cred": _cred_to_wire(cred),
            "iat": cred.iat, "exp": cred.exp, "alg_tier": alg_tier,
        }

    # ---------------------------------------------------------------
    # API-04 凭证校验
    # ---------------------------------------------------------------
    def verify_credential(self, cred_wire, audience=None, now=None,
                          record_nonce=True) -> dict:
        """校验凭证（本地，无网络）。

        v2.11：所有校验路径（含提前拒绝的）都写审计事件，
        供 FR6-05 异常告警扫描使用。
        """
        cred = _cred_from_wire(cred_wire)
        if cred is None:
            self.audit.append({
                "kind": "credential.verify",
                "tenant": self.tenant,
                "result": "fail",
                "reason": "invalid credential format",
                "aud": audience,
            })
            return {"ok": False, "reason": "invalid credential format"}

        # 签发方必须已知
        if cred.iss not in self._identities:
            self.audit.append({
                "kind": "credential.verify",
                "tenant": self.tenant,
                "jti": cred.jti,
                "result": "fail",
                "reason": "unknown issuer",
                "aud": audience,
            })
            return {"ok": False, "reason": "unknown issuer"}
        # v2.6: SM9 无证书——issuer_pub 用主签名公钥 P_pub（G2 点），
        #       而非 SM2 登记簿里的 pub_id
        pq_pub = None
        if cred.alg_tier == ALG_SM9:
            # FR1-05：用凭证记录的 kv 版本取对应 P_pub（而非当前最新）
            cred_kv = getattr(cred, "kv", None) or 0
            issuer_pub = self.ia._get_ppub(cred_kv)
            if issuer_pub is None:
                self.audit.append({
                    "kind": "credential.verify",
                    "tenant": self.tenant,
                    "jti": cred.jti,
                    "result": "fail",
                    "reason": "sm9 ppub unavailable",
                    "aud": audience,
                })
                return {"ok": False, "reason": "sm9 ppub unavailable"}
        else:
            issuer_pub = self._identities[cred.iss]["pub"]
            # v2.16：抗量子档位需要额外的 PQ 公钥（按签发时的 kv 取）
            pq_pub = None
            cred_kv = getattr(cred, "kv", None) or 0
            if cred.alg_tier == ALG_SM2_MLDSA:
                pq_pub = self._pq_pk(cred.iss, cred_kv, "mldsa")
            elif cred.alg_tier == ALG_HASH_SIG:
                pq_pub = self._pq_pk(cred.iss, cred_kv, "slhdsa")

        # 受众一致性
        if audience and cred.aud != audience:
            self.audit.append({
                "kind": "credential.verify",
                "tenant": self.tenant,
                "jti": cred.jti,
                "result": "fail",
                "reason": "audience mismatch",
                "aud": audience,
            })
            return {"ok": False, "reason": "audience mismatch"}

        # 撤销检查
        if cred.jti in self._revoked_jtis:
            self.audit.append({
                "kind": "credential.verify",
                "tenant": self.tenant,
                "jti": cred.jti,
                "result": "fail",
                "reason": "revoked",
                "aud": audience,
            })
            return {"ok": False, "reason": "revoked"}

        # nonce 防重放（v2.1：走 NonceStore，可注入 SQLite/Redis）
        seen = self._nonce_store if record_nonce else None
        ok, why = cred.verify(cred.iss, issuer_pub, now=now,
                              seen_nonces=seen,
                              revoked_jtis=self._revoked_jtis,
                              pq_pub=pq_pub)
        if ok and record_nonce:
            # add 是原子声称（Redis SET NX / SQLite INSERT OR IGNORE）：
            # 返回 False 表示该 nonce 已被并发请求抢先声称 → 判为重放。
            # 即使 __contains__ 先返回 False（未见），这里仍会拒绝，
            # 闭合 check-then-act 竞态。
            if not self._nonce_store.add(cred.nonce, ttl=self._nonce_ttl):
                ok = False
                why = "nonce replay"

        self.audit.append({
            "kind": "credential.verify",
            "tenant": self.tenant,
            "jti": cred.jti,
            "result": "ok" if ok else "fail",
            "reason": why,
            "aud": audience,
        })
        return {"ok": ok, "reason": why, "jti": cred.jti,
                "sub": cred.sub, "iss": cred.iss, "scope": list(cred.scope),
                "exp": cred.exp}

    # ---------------------------------------------------------------
    # API-05 委托签发
    # ---------------------------------------------------------------
    def issue_delegation(self, delegator_idn, delegatee_idn,
                         audience, scope, intent=None, ttl=None,
                         alg_tier=None, parent_cred=None) -> dict:
        """把 delegator 的权限委托给 delegatee。返回委托凭证（链尾）。

        alg_tier 默认 sm2；v2.8 起支持 sm9。

        v2.10 FR3-02 / FR3-05 权限收敛：
            parent_cred  delegator 持有的父凭证（wire 格式）。传入后做三项
                         强制校验——父凭证主体必须是本次委托方、受众须一致、
                         父凭证不得已撤销；并强制两条收敛：
                         · 子级作用域 ⊆ 父级作用域，超出即拒绝
                         · 子级有效期 ≤ 父级有效期，超出自动截断
                         不传 parent_cred 时仍可签发（向后兼容），
                         但收敛只在验链侧兜底，返回 parent_verified=False。
        """
        if delegator_idn not in self._identities or \
           self._identities[delegator_idn]["status"] != "active":
            return {"ok": False, "reason": "delegator invalid"}
        if delegatee_idn not in self._identities or \
           self._identities[delegatee_idn]["status"] != "active":
            return {"ok": False, "reason": "delegatee invalid"}
        if ttl is None:
            ttl = self._policy["max_ttl_seconds"]

        # v2.10：父凭证收敛校验（Sign-side enforcement）
        parent = None
        if parent_cred is not None:
            parent = _cred_from_wire(parent_cred)
            if parent is None:
                return {"ok": False, "reason": "invalid parent credential"}
            # 归属：父凭证主体必须是本次委托方
            if parent.sub != delegator_idn:
                return {"ok": False,
                        "reason": "parent credential not held by delegator"}
            # 受众须一致
            if parent.aud != audience:
                return {"ok": False, "reason": "parent audience mismatch"}
            # 父凭证已撤销 → 不得再派生
            if parent.jti in self._revoked_jtis:
                return {"ok": False, "reason": "parent credential revoked"}
            # FR3-02：子级作用域不得超出父级，超出即拒绝
            if not set(scope).issubset(set(parent.scope)):
                esc = sorted(set(scope) - set(parent.scope))
                return {"ok": False, "reason": "scope escalation",
                        "escalated": esc}

        # v2.8: 委托凭证支持 SM9 档位
        if alg_tier is None:
            alg_tier = ALG_SM2
        if alg_tier not in self._policy["allowed_algs"]:
            return {"ok": False, "reason": "alg_tier not allowed"}

        # FR3-05：子级有效期不得超出父级，超出截断到父级 exp
        exp = _ts() + ttl
        exp_truncated = False
        if parent is not None and exp > parent.exp:
            exp = parent.exp
            exp_truncated = True

        # v2.11 FR3-04：委托深度限制
        #   父凭证在登记簿中 → depth = parent.depth + 1
        #   无父凭证（遗留调用）→ depth = 1（视为第一跳委托）
        #   超出策略上限则拒绝签发，避免委托链无谓扩散
        if parent is not None:
            parent_meta = self._cred_registry.get(parent.jti)
            parent_depth = parent_meta.get("depth", 0) if parent_meta else 0
        else:
            parent_depth = 0
        new_depth = parent_depth + 1
        max_depth = self._policy.get("max_delegation_depth", 8)
        if max_depth is not None and new_depth > max_depth:
            return {
                "ok": False,
                "reason": "delegation depth exceeded",
                "max_depth": max_depth,
                "would_be_depth": new_depth,
                "parent_jti": parent.jti if parent is not None else None,
            }

        cred = Credential(sub=delegatee_idn, iss=delegator_idn, aud=audience,
                          scope=scope, exp=exp, act=delegator_idn,
                          alg_tier=alg_tier,
                          kv=self._identities.get(delegator_idn, {}).get("key_version", 0))
        delegator_kv = self._identities.get(delegator_idn, {}).get("key_version", 0)
        pq_sk = None
        if alg_tier == ALG_SM9:
            if not _SM9_AVAILABLE or self.ia is None or self.ia.ks is None:
                return {"ok": False, "reason": "sm9 not available"}
            priv_ks = self.ia._get_ks(delegator_kv)
            cred.sign(delegator_idn, priv_ks)
        elif alg_tier == ALG_SM2_MLDSA:
            # v2.16：混合档位——SM2 分量 + 惰性派生的 ML-DSA 分量
            if not _MLD_AVAILABLE:
                return {"ok": False, "reason": "mldsa unavailable"}
            d = self._derive_priv(delegator_idn)
            pq_sk = self._pq_sk(delegator_idn, delegator_kv, "mldsa")
            cred.sign(delegator_idn, d,
                      pub=self._identities[delegator_idn].get("pub"),
                      pq_sk=pq_sk)
        elif alg_tier == ALG_HASH_SIG:
            # v2.16：hash-signature——仅用惰性派生的 SLH-DSA 密钥
            if not _SLH_AVAILABLE:
                return {"ok": False, "reason": "slhdsa unavailable"}
            d = self._derive_priv(delegator_idn)
            pq_sk = self._pq_sk(delegator_idn, delegator_kv, "slhdsa")
            cred.sign(delegator_idn, d, pq_sk=pq_sk)
        else:
            d = self._derive_priv(delegator_idn)
            # v2.15：复用已缓存公钥，省掉标量乘
            cred.sign(delegator_idn, d,
                      pub=self._identities[delegator_idn].get("pub"))
        self.audit.append({
            "kind": "delegation.issue",
            "tenant": self.tenant,
            "delegator": delegator_idn, "delegatee": delegatee_idn,
            "aud": audience, "scope": list(scope), "intent": intent,
            "jti": cred.jti,
            # v2.10：收敛元数据入审计，供事后追溯「权限是沿哪条链收敛的」
            "parent_jti": parent.jti if parent is not None else None,
            "parent_verified": parent is not None,
            "exp_truncated": exp_truncated,
            # v2.11 FR3-04：委托深度入审计，供事后追溯链的层次
            "depth": new_depth,
        })
        # v2.10：登记凭证血缘（父 = 委托方出示的凭证）
        self._register_cred(cred.jti, delegator_idn, delegatee_idn,
                            parent.jti if parent is not None else None,
                            depth=new_depth)
        return {"ok": True, "jti": cred.jti, "cred": _cred_to_wire(cred),
                "parent_verified": parent is not None,
                "exp_truncated": exp_truncated,
                "depth": new_depth}

    # ---------------------------------------------------------------
    # API-06 委托链验证
    # ---------------------------------------------------------------
    def verify_delegation_chain(self, chain_wires, target_audience,
                                target_scope, now=None) -> dict:
        """验证委托链并计算有效权限交集。"""
        creds = [_cred_from_wire(c) for c in chain_wires]
        if any(c is None for c in creds):
            return {"ok": False, "reason": "invalid chain format"}

        # 收集链中所有签发方公钥
        issuers = {}
        # v2.16：抗量子档位链路的 PQ 公钥（按签发时 kv 取）
        pq_pubs = {}
        for c in creds:
            if c.iss not in self._identities:
                return {"ok": False, "reason": "unknown issuer: %s" % c.iss}
            cred_kv = getattr(c, "kv", None) or 0
            # v2.6: SM9 无证书，issuer_pub 用主签名公钥 P_pub
            # v2.13 FR1-05：按凭证 kv 取对应版本 P_pub（支持密钥轮换）
            if c.alg_tier == ALG_SM9:
                issuers[c.iss] = self.ia._get_ppub(cred_kv)
            else:
                issuers[c.iss] = self._identities[c.iss]["pub"]
                if c.alg_tier == ALG_SM2_MLDSA:
                    pq_pubs[c.iss] = self._pq_pk(c.iss, cred_kv, "mldsa")
                elif c.alg_tier == ALG_HASH_SIG:
                    pq_pubs[c.iss] = self._pq_pk(c.iss, cred_kv, "slhdsa")

        # 逐跳验链
        ok, reasons = verify_chain(creds, issuers, now=now,
                                  seen_nonces=None,
                                  revoked_jtis=self._revoked_jtis,
                                  pq_pubs=pq_pubs)

        # 计算权限交集（链中 scope 的交）
        scope_intersection = set()
        if creds:
            scope_intersection = set(creds[0].scope)
            for c in creds[1:]:
                scope_intersection &= set(c.scope)

        # 与目标资源要求对比
        req_scope = set(target_scope)
        scope_ok = req_scope.issubset(scope_intersection)

        # 受众一致性
        aud_ok = all(c.aud == target_audience for c in creds)

        result = ok and scope_ok and aud_ok
        self.audit.append({
            "kind": "delegation.verify",
            "tenant": self.tenant,
            "chain_len": len(creds),
            "target_aud": target_audience,
            "target_scope": sorted(target_scope),
            "scope_intersection": sorted(scope_intersection),
            "result": "ok" if result else "fail",
        })
        return {
            "ok": result,
            "reasons": reasons,
            "scope_intersection": sorted(scope_intersection),
            "scope_satisfied": scope_ok,
            "audience_satisfied": aud_ok,
            "chain_length": len(creds),
        }

    # ---------------------------------------------------------------
    # API-07 撤销
    # ---------------------------------------------------------------
    def revoke(self, jti, reason="user request") -> dict:
        if jti in self._revoked_jtis:
            return {"ok": False, "reason": "already revoked"}
        self._revoked_jtis.add(jti)
        version = len(self._revocation_log) + 1
        # v2.1：同步写入 Merkle 累加器，生成认证路径
        acc_rec = self._acc.revoke(jti)
        entry = {"version": version, "jti": jti, "reason": reason,
                 "ts": _ts(),
                 "acc_version": acc_rec["version"],
                 "tree_id": acc_rec["tree_id"],
                 "leaf_index": acc_rec["leaf_index"]}
        self._revocation_log.append(entry)
        acc_root = self._acc.snapshot()["current_root"]
        self.audit.append({
            "kind": "revoke", "tenant": self.tenant,
            "jti": jti, "reason": reason, "version": version,
            "acc_version": acc_rec["version"], "acc_root": acc_root,
        })
        if self._pers is not None:
            self._pers.append_revocation(
                self.tenant, version, jti, reason, entry["ts"])
        # v2.4：每次撤销后同步累加器状态快照，下次启动 O(1) 恢复
        self._save_accumulator_state()
        return {"ok": True, "jti": jti, "version": version,
                "acc_version": acc_rec["version"], "ts": _ts()}

    def _register_cred(self, jti, iss, sub, parent_jti, depth=0):
        """登记凭证血缘，并维护委托图反向索引（父 → 子）与委托深度。

        v2.11 FR3-04：depth 记录该凭证在委托树中的深度
        （根凭证 depth=0，每下一跳 +1），供最大深度限制与治理台拓扑展示。
        """
        self._cred_registry[jti] = {"iss": iss, "sub": sub,
                                    "parent": parent_jti, "depth": depth}
        if parent_jti:
            kids = self._cred_children.setdefault(parent_jti, [])
            if jti not in kids:
                kids.append(jti)

    def _rebuild_cred_registry(self):
        """重启后从审计日志重建凭证血缘，使级联撤销仍然可用。

        凭证全文按设计不入库（只存撤销与统计元数据），但审计事件里
        保留了 iss / sub / parent_jti，足够重建委托图。老数据缺
        parent_jti 时退化为无父节点，级联相应降级——不会报错。
        v2.11：审计里已含 depth，直接还原；缺失时用父节点 depth+1
        重算，保证重启后 FR3-04 深度语义仍成立。
        """
        if self._pers is None:
            return 0
        try:
            rows = self._pers.query_audit(self.tenant, limit=100000)
        except Exception:
            return 0
        n = 0
        for r in rows:
            ev = r.get("event") or {}
            kind = ev.get("kind")
            jti = ev.get("jti")
            if not jti:
                continue
            if kind == "credential.issue":
                self._register_cred(jti, ev.get("iss"), ev.get("sub"),
                                    None, depth=0)
                n += 1
            elif kind == "delegation.issue":
                parent_jti = ev.get("parent_jti")
                depth = ev.get("depth")
                if depth is None and parent_jti:
                    p_meta = self._cred_registry.get(parent_jti)
                    depth = (p_meta.get("depth", 0) + 1) if p_meta else 1
                elif depth is None:
                    depth = 1
                self._register_cred(jti, ev.get("delegator"),
                                    ev.get("delegatee"), parent_jti,
                                    depth=depth)
                n += 1
        return n

    def revoke_by_identity(self, idn, reason="identity disabled",
                           cascade=True) -> dict:
        """FR4-02：按标识废止该智能体全部凭证及其下游委托。

        v2.10 级联语义（此前只撤 iss == idn，下游委托漏网）：
          1) 种子集 = 该标识签发的凭证（iss == idn）
                    ∪ 签发给该标识的凭证（sub == idn）
             —— 废止一个智能体，它持有的权限与它发出去的权限都作废。
          2) 沿委托图（父凭证 → 子凭证）做传递闭包，覆盖全部下游委托。
          3) 逐个撤销，返回实际撤销的 jti 列表与数量。

        cascade=False 时退化为 v2.9 行为（仅种子集，不扩散），
        供对比测试与需要克制爆炸半径的场景使用。
        """
        if idn not in self._identities:
            return {"ok": False, "reason": "unknown identity"}

        seeds = {jti for jti, m in self._cred_registry.items()
                 if m.get("iss") == idn or m.get("sub") == idn}
        # 兜底：registry 缺失时退回 v2.9 的 iss 索引
        for jti, iss in self._issued_creds.items():
            if iss == idn:
                seeds.add(jti)

        affected = set(seeds)
        if cascade:
            frontier = list(seeds)
            while frontier:
                cur = frontier.pop()
                for child in self._cred_children.get(cur, []):
                    if child not in affected:
                        affected.add(child)
                        frontier.append(child)

        revoked = []
        for jti in sorted(affected):
            if self.revoke(jti, reason=reason).get("ok"):
                revoked.append(jti)
        return {"ok": True, "revoked": len(revoked), "jtis": revoked,
                "affected": len(affected), "cascade": cascade,
                "reason": reason}

    # ---------------------------------------------------------------
    # API-08 撤销快照
    # ---------------------------------------------------------------
    def revocation_snapshot(self, since_version=0) -> dict:
        """返回自 since_version 之后的增量撤销记录。

        v2.1 起快照额外带 Merkle 累加器状态：
          - acc_version / acc_current_root / acc_frozen_roots
          - entries 里每条可另调 verify_revocation 拿到认证路径
        """
        if self._pers is not None:
            pers_snap = self._pers.revocation_snapshot(
                self.tenant, since_version=since_version)
            result = {"ok": True, **pers_snap}
        else:
            entries = [e for e in self._revocation_log
                       if e["version"] > since_version]
            result = {
                "ok": True,
                "current_version": len(self._revocation_log),
                "since_version": since_version,
                "entries": entries,
                "total_revoked": len(self._revoked_jtis),
            }
        # v2.1：附加累加器快照（根哈希 O(1) 下发）
        acc_snap = self._acc.snapshot()
        result["acc_version"] = acc_snap["version"]
        result["acc_current_root"] = acc_snap["current_root"]
        result["acc_frozen_roots"] = acc_snap["frozen_roots"]
        return result

    # ---------------------------------------------------------------
    # v2.1 撤销证明（新）
    # ---------------------------------------------------------------
    def verify_revocation(self, jti) -> dict:
        """返回指定 jti 的撤销证明，供离线校验。

        未撤销 -> {"ok": True, "revoked": False, "proof": None}
        已撤销 -> {"ok": True, "revoked": True, "proof": {...}, "verify": True}
        """
        proof = self._acc.proof(jti)
        if proof is None:
            return {"ok": True, "revoked": False, "proof": None}
        return {
            "ok": True,
            "revoked": True,
            "proof": proof,
            "verify": RevokeAccumulator.verify_proof(proof),
        }

    # ---------------------------------------------------------------
    # API-09 审计检索
    # ---------------------------------------------------------------
    def audit_query(self, kind=None, idn=None, since_ts=None,
                    until_ts=None, limit=100) -> dict:
        if self._pers is not None:
            rows = self._pers.query_audit(self.tenant, kind=kind,
                                          idn=idn, limit=limit)
            records = []
            for r in rows:
                ev = r["event"]
                if since_ts and r.get("ts", 0) < since_ts:
                    continue
                if until_ts and r.get("ts", 0) > until_ts:
                    continue
                records.append({
                    "hash": r["hash"], "prev": r["prev_hash"],
                    "event": ev, "ts": r.get("ts"),
                })
        else:
            records = []
            for e in self.audit.chain:
                ev = e["event"]
                if kind and ev.get("kind") != kind:
                    continue
                if idn and idn not in (ev.get("idn"), ev.get("iss"),
                                        ev.get("sub"), ev.get("delegator"),
                                        ev.get("delegatee")):
                    continue
                if since_ts and ev.get("ts", 0) < since_ts:
                    continue
                if until_ts and ev.get("ts", 0) > until_ts:
                    continue
                records.append({
                    "hash": e["hash"], "prev": e["prev"], "event": ev,
                    "ts": e.get("ts"),
                })
                if len(records) >= limit:
                    break
        chain_ok, why = self.audit.verify()
        return {
            "ok": True,
            "chain_valid": chain_ok,
            "chain_root_hash": self.audit.root_hash,
            "chain_length": self.audit.count(),
            "records": records,
            "chain_verify_reason": why,
        }

    # ---------------------------------------------------------------
    # API-10 策略配置
    # ---------------------------------------------------------------
    def configure_policy(self, patch: dict) -> dict:
        new = dict(self._policy)
        new.update(patch)
        self._policy = new
        self.audit.append({
            "kind": "policy.update", "tenant": self.tenant,
            "patch_keys": sorted(patch.keys()),
        })
        if self._pers is not None:
            for k, v in patch.items():
                self._pers.set_policy(self.tenant, k, v)
        return {"ok": True, "policy": dict(self._policy)}

    # ---------------------------------------------------------------
    # FR1-05 密钥轮换
    # ---------------------------------------------------------------
    def rotate_master_key(self, alg="sm2", reason="scheduled rotation"):
        """FR1-05：轮换主密钥。轮换不影响既有标识。

        alg: "sm2" 或 "sm9"
        返回 {"ok": True, "alg", "new_version", "reason"}

        语义：
        - 新标识用新版 mk/ks 派生
        - 既有标识保留旧版 key_version，用旧 mk 继续派生私钥
        - 既有凭证签名不受影响（SM2 pub 不变；SM9 按 kv 查 P_pub）
        """
        if alg == "sm2":
            ver, new_mk, new_mpk = self.ia.rotate_mk()
            self.audit.append({
                "kind": "key.rotate", "tenant": self.tenant,
                "alg": "sm2", "new_version": ver, "reason": reason,
            })
            return {"ok": True, "alg": "sm2", "new_version": ver,
                    "reason": reason, "ts": _ts()}
        elif alg == "sm9":
            if not _SM9_AVAILABLE or self.ia.ks is None:
                return {"ok": False, "reason": "sm9 not available"}
            ver, new_ks, new_ppub = self.ia.rotate_ks()
            self.audit.append({
                "kind": "key.rotate", "tenant": self.tenant,
                "alg": "sm9", "new_version": ver, "reason": reason,
            })
            return {"ok": True, "alg": "sm9", "new_version": ver,
                    "reason": reason, "ts": _ts()}
        else:
            return {"ok": False, "reason": "unknown alg: %s" % alg}

    def key_versions(self):
        """FR1-05：查询当前主密钥版本信息（不含密钥明文）。"""
        return {"ok": True, "versions": self.ia.key_versions(), "ts": _ts()}

    # ---------------------------------------------------------------
    # v2.2 审计锚点（上链存证雏形）
    # ---------------------------------------------------------------
    def anchor_audit(self, issuer_idn, reason="manual") -> dict:
        """对当前审计链根做签名承诺，形成"防篡改时间锚点"。

        用 issuer_idn 对应的标识私钥签名 (ts, chain_len, root_hash) 三元组，
        验证方只需 (issuer_pub, anchor) 即可离线校验，不依赖审计链本体。
        """
        if issuer_idn not in self._identities:
            return {"ok": False, "reason": "unknown issuer"}
        if self._identities[issuer_idn]["status"] != "active":
            return {"ok": False, "reason": "issuer disabled"}

        issuer_pub = self._identities[issuer_idn]["pub"]
        priv = self._derive_priv(issuer_idn)
        root_hash = self.audit.root_hash
        chain_len = self.audit.count()
        anchor = AuditAnchor(
            ts=_ts(), chain_len=chain_len,
            root_hash=root_hash, issuer_idn=issuer_idn,
        )
        anchor.sign(priv)
        self._anchor_store.add(anchor, tenant=self.tenant)
        # 锚点是独立于审计链的元事件（防篡改时间承诺），
        # 不 append 到 audit 链——否则会污染链的根哈希，导致
        # 锚点承诺与实际链状态永远不一致。
        ok, why = anchor.verify(issuer_pub)
        return {
            "ok": ok,
            "anchor": anchor.to_dict(),
            "verify_reason": why,
        }

    def list_audit_anchors(self, since_ts=None, limit=100) -> dict:
        anchors = self._anchor_store.list(since_ts=since_ts, limit=limit,
                                          tenant=self.tenant)
        return {
            "ok": True,
            "total": len(anchors),
            "anchors": [a.to_dict() for a in anchors],
        }

    def latest_audit_anchor(self) -> dict:
        a = self._anchor_store.latest(tenant=self.tenant)
        return {"ok": True, "anchor": a.to_dict() if a else None}

    def verify_audit_anchor(self, anchor_dict, issuer_pub=None) -> dict:
        """验证一个锚点：若未提供 issuer_pub，从当前标识簿查询。"""
        if not anchor_dict:
            return {"ok": False, "reason": "empty anchor"}
        anchor = AuditAnchor.from_dict(anchor_dict)
        if issuer_pub is None:
            if anchor.issuer_idn not in self._identities:
                return {"ok": False, "reason": "unknown issuer"}
            issuer_pub = self._identities[anchor.issuer_idn]["pub"]
        ok, why = anchor.verify(issuer_pub)
        return {"ok": ok, "verify_reason": why}


# ------------------------------------------------------------------
# 序列化辅助
# ------------------------------------------------------------------
def _cred_to_wire(cred: Credential) -> dict:
    """序列化凭证为 wire 格式。

    - SM2: sig = (r, s) → sig_r, sig_s
    - SM9: sig = (h, (Sx, Sy)) → sig_r=h, sig_s_x=Sx, sig_s_y=Sy
    - sm2-ml-dsa (v2.16): sig = ((r, s), mld_sig) → sig_r/sig_s + pq_sig
    - hash-signature (v2.16): sig = slh_sig → pq_sig
    - kv: v2.13 FR1-05 主密钥版本（SM9 验签需匹配 P_pub）
    """
    d = {
        "sub": cred.sub, "iss": cred.iss, "act": cred.act,
        "aud": cred.aud, "scope": list(cred.scope),
        "iat": cred.iat, "nbf": cred.nbf, "exp": cred.exp,
        "nonce": cred.nonce.hex(), "alg_tier": cred.alg_tier,
        "jti": cred.jti,
    }
    if cred.kv is not None:
        d["kv"] = cred.kv
    if cred.sig:
        if cred.alg_tier == ALG_SM2_MLDSA:
            (r, s), mld_sig = cred.sig
            d["sig_r"] = "%064x" % r
            d["sig_s"] = "%064x" % s
            d["pq_sig"] = json.dumps(mld_sig, separators=(",", ":"))
        elif cred.alg_tier == ALG_HASH_SIG:
            # SLH-DSA 签名含 bytes，需转 hex
            slh = cred.sig
            d["pq_sig"] = json.dumps({
                "m": slh["m"].hex(),
                "leaf": slh["leaf"],
                "sig": [x.hex() for x in slh["sig"]],
                "path": [x.hex() for x in slh["path"]],
            }, separators=(",", ":"))
        else:
            d["sig_r"] = "%064x" % cred.sig[0]
            s = cred.sig[1]
            if isinstance(s, tuple):
                # SM9: s = (Sx, Sy)
                d["sig_s_x"] = "%064x" % s[0]
                d["sig_s_y"] = "%064x" % s[1]
            else:
                # SM2: s = integer
                d["sig_s"] = "%064x" % s
    return d


def _cred_from_wire(d: dict) -> Optional[Credential]:
    try:
        c = Credential(
            sub=d["sub"], iss=d["iss"], act=d.get("act"),
            aud=d["aud"], scope=tuple(d["scope"]),
            iat=d["iat"], nbf=d["nbf"], exp=d["exp"],
            nonce=bytes.fromhex(d["nonce"]),
            alg_tier=d.get("alg_tier", ALG_SM2),
            jti=d["jti"],
            kv=d.get("kv"),
        )
        if d.get("pq_sig"):
            # v2.16 抗量子档位
            j = json.loads(d["pq_sig"])
            if d.get("alg_tier") == ALG_SM2_MLDSA:
                c.sig = ((int(d["sig_r"], 16), int(d["sig_s"], 16)), j)
            else:
                c.sig = {
                    "m": bytes.fromhex(j["m"]),
                    "leaf": j["leaf"],
                    "sig": [bytes.fromhex(x) for x in j["sig"]],
                    "path": [bytes.fromhex(x) for x in j["path"]],
                }
        elif d.get("sig_r"):
            h_or_r = int(d["sig_r"], 16)
            if d.get("sig_s_x") and d.get("sig_s_y"):
                # SM9 格式
                s = (int(d["sig_s_x"], 16), int(d["sig_s_y"], 16))
            elif d.get("sig_s"):
                # SM2 格式
                s = int(d["sig_s"], 16)
            else:
                return None
            c.sig = (h_or_r, s)
        return c
    except Exception:
        return None


def self_check() -> List[Tuple[str, bool]]:
    """10 API 全流程烟测。"""
    out = []
    p = Platform(tenant="test")

    # API-01 注册
    r = p.register_identity("agent://root/ca", org="root",
                            agent_type="issuance", owner="admin")
    out.append(("API-01 标识注册", r["ok"] and r["idn"] == "agent://root/ca"))

    for idn in ["agent://org-a/orchestrator",
                "agent://org-a/worker",
                "agent://org-b/subagent"]:
        p.register_identity(idn, org=idn.split("/")[1],
                            agent_type="worker", owner="admin")

    # API-02 停用
    r = p.disable_identity("agent://org-b/subagent", reason="test")
    out.append(("API-02 标识停用", r["ok"] and r["status"] == "disabled"))
    # 再注册恢复
    p.register_identity("agent://org-b/subagent", org="org-b",
                        agent_type="worker", owner="admin")

    # API-03 凭证签发
    r = p.issue_credential("agent://root/ca", "agent://org-a/orchestrator",
                           "service://invoice", ["invoice:read"], ttl=3600)
    out.append(("API-03 凭证签发", r["ok"] and "jti" in r))
    cred_wire = r["cred"]

    # API-04 凭证校验
    r = p.verify_credential(cred_wire, audience="service://invoice",
                            record_nonce=False)
    out.append(("API-04 凭证校验", r["ok"] and r["reason"] == "ok"))

    # API-05 委托签发（出示父凭证，触发 FR3-02/FR3-05 收敛）
    r = p.issue_delegation("agent://org-a/orchestrator",
                            "agent://org-a/worker",
                            "service://invoice",
                            ["invoice:read"], intent="test task",
                            parent_cred=cred_wire)
    out.append(("API-05 委托签发", r["ok"]))
    del_wire = r["cred"]

    # API-06 委托链验证
    r = p.verify_delegation_chain([cred_wire, del_wire],
                                   "service://invoice",
                                   ["invoice:read"])
    out.append(("API-06 委托链验证", r["ok"] and r["scope_satisfied"]))

    # API-07 撤销
    r = p.revoke(cred_wire["jti"], reason="compromise suspected")
    out.append(("API-07 撤销", r["ok"] and r["version"] == 1))

    # API-08 撤销快照
    r = p.revocation_snapshot(since_version=0)
    out.append(("API-08 撤销快照",
                r["ok"] and r["total_revoked"] == 1))

    # API-09 审计检索
    r = p.audit_query(kind="credential.issue")
    out.append(("API-09 审计检索",
                r["ok"] and r["chain_valid"] and len(r["records"]) >= 1))

    # API-10 策略配置
    r = p.configure_policy({"max_ttl_seconds": 7200})
    out.append(("API-10 策略配置",
                r["ok"] and r["policy"]["max_ttl_seconds"] == 7200))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
