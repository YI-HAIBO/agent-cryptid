# -*- coding: utf-8 -*-
"""凭证层：智能体凭证的签发、序列化与本地校验。

凭证字段（对齐《技术方案》凭证三段式）：
    sub       主体标识（当前持凭证方）
    iss       签发方标识
    act       代表方标识（委托链存在时非空；否则与 sub 相同）
    aud       受众（可接受该凭证的服务）
    scope     授权范围（列表）
    iat       签发时间（Unix 秒）
    nbf       生效时间（默认等于 iat）
    exp       过期时间
    nonce     一次性随机数（防重放）
    alg_tier  算法档位："sm2" / "sm2-ml-dsa" / "hash-signature"
    jti       凭证唯一 ID
    sig       签名

设计要点：
    - 规范化序列化为 UTF-8 紧凑 JSON（键名按字典序排序），签名覆盖全文。
    - 校验本地化：签名用本地缓存的公钥验，撤销快照本地缓存，无网络往返。
    - alg_tier 进入签名覆盖：换档位必须换签名，防降级攻击。
"""
import hashlib
import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

# 快速路径：若可用 gmssl，则签名走 gmssl（8ms）；验签走自研正确公式
# 但用 gmssl._kg 加速标量乘（~20ms，比纯自研快 7x）
try:
    from sm2_fast import FastSigner as _FastSigner
    _FAST_AVAILABLE = True
except ImportError:
    _FastSigner = None
    _FAST_AVAILABLE = False

# SM9 真实现（v2.6 加入）
try:
    import sm9 as _SM9
    _SM9_AVAILABLE = True
except ImportError:
    _SM9 = None
    _SM9_AVAILABLE = False

# 抗量子档位（v2.16 加入）：ML-DSA（FIPS 204 / Dilithium）与 SLH-DSA（FIPS 205 / SPHINCS+）
# 均纯 Python 自实现，零第三方依赖。
try:
    import mldsa as _MLD
    _MLD_AVAILABLE = True
except ImportError:
    _MLD = None
    _MLD_AVAILABLE = False

try:
    import slhdsa as _SLH
    _SLH_AVAILABLE = True
except ImportError:
    _SLH = None
    _SLH_AVAILABLE = False


ALG_SM2 = "sm2"
ALG_SM9 = "sm9"
ALG_SM2_MLDSA = "sm2-ml-dsa"
ALG_HASH_SIG = "hash-signature"
ALG_TIERS = (ALG_SM2, ALG_SM9, ALG_SM2_MLDSA, ALG_HASH_SIG)


def _canonical(payload):
    """规范化：紧凑 JSON，键名字典序。"""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class Credential:
    """智能体凭证。可变对象，签发后可冻结。"""

    def __init__(self, sub, iss, aud, scope, exp, iat=None, nbf=None,
                 act=None, nonce=None, alg_tier=ALG_SM2, jti=None,
                 kv=None):
        now = iat if iat is not None else int(time.time())
        self.sub = sub
        self.iss = iss
        self.act = act if act is not None else sub
        self.aud = aud
        self.scope = tuple(scope)
        self.iat = now
        self.nbf = nbf if nbf is not None else now
        self.exp = exp
        self.nonce = nonce if nonce is not None else secrets.token_bytes(16)
        self.alg_tier = alg_tier
        self.kv = kv  # v2.13 FR1-05：签发时主密钥版本（SM9 验签需匹配 P_pub）
        if jti is None:
            # jti 由除自身外的所有字段哈希派生
            base = {
                "sub": self.sub, "iss": self.iss, "act": self.act,
                "aud": self.aud, "scope": list(self.scope),
                "iat": self.iat, "nbf": self.nbf, "exp": self.exp,
                "nonce": self.nonce.hex(), "alg_tier": self.alg_tier,
            }
            if self.kv is not None:
                base["kv"] = self.kv
            jti = hashlib.sha256(_canonical(base)).hexdigest()[:24]
        self.jti = jti
        self.sig = None

    def _unsigned(self):
        """返回待签名的字段字典（不含 sig；jti 由外部预先设定）。"""
        d = {
            "sub": self.sub,
            "iss": self.iss,
            "act": self.act,
            "aud": self.aud,
            "scope": list(self.scope),
            "iat": self.iat,
            "nbf": self.nbf,
            "exp": self.exp,
            "nonce": self.nonce.hex(),
            "alg_tier": self.alg_tier,
            "jti": self.jti,
        }
        if self.kv is not None:
            d["kv"] = self.kv
        return d

    def canonical_bytes(self):
        return _canonical(self._unsigned())

    def sign(self, idn, priv_key, pub=None, pq_sk=None):
        """签发方使用自己的标识密钥签名。返回凭证自身。

        - alg_tier == ALG_SM2：priv_key 是 SM2 标量私钥（整数）；
        - alg_tier == ALG_SM9：priv_key 是 SM9 主签名私钥 ks（整数）。
          SM9 无证书特性：ds_A 由 (ks, idn) 派生，无需下发用户私钥。
        - alg_tier == ALG_SM2_MLDSA（v2.16）：SM2 + ML-DSA 混合签名，
          priv_key 仍是 SM2 标量私钥，pq_sk 是 mldsa.keygen 产出的 sk；
          两分量任一缺失即拒绝签发。
        - alg_tier == ALG_HASH_SIG（v2.16）：SLH-DSA（hash-signature），
          pq_sk 是 slhdsa.keygen 产出的 sk；priv_key/pub 不参与。

        pub  已知的签发方公钥（SM2 点）。传入即可跳过一次标量乘——
             标量乘约 33ms，而签名本身仅约 2.4ms，是签发耗时的主项。
             标识注册时公钥已算过并缓藏在 _identities 中，签发主路径
             必须传入，避免每张凭证重复计算同一个点乘（v2.15 修复）。
        """
        msg_bytes = self.canonical_bytes()
        idn_bytes = idn.encode("utf-8") if isinstance(idn, str) else idn

        # ---- v2.16：抗量子档位 ----
        if self.alg_tier == ALG_SM2_MLDSA:
            if not _MLD_AVAILABLE:
                raise RuntimeError("ML-DSA 未编译，无法签发")
            if pq_sk is None:
                raise RuntimeError("ML-DSA 密钥缺失")
            # 分量 1：SM2
            pub_pt = pub if pub is not None else sm2.scalar_mult(priv_key)
            if _FAST_AVAILABLE:
                r, s = _FastSigner(priv_key, pub_pt).sign(idn_bytes, msg_bytes)
            else:
                r, s = sm2.sign(idn_bytes, priv_key, msg_bytes)
            # 分量 2：ML-DSA
            mld_sig = _MLD.sign(pq_sk, msg_bytes)
            self.sig = ((r, s), mld_sig)
            return self
        if self.alg_tier == ALG_HASH_SIG:
            if not _SLH_AVAILABLE:
                raise RuntimeError("SLH-DSA 未编译，无法签发")
            if pq_sk is None:
                raise RuntimeError("SLH-DSA 密钥缺失")
            self.sig = _SLH.sign(pq_sk, msg_bytes)
            return self

        if self.alg_tier == ALG_SM9:
            if not _SM9_AVAILABLE:
                raise RuntimeError("SM9 未编译，无法签发")
            # 缓存 P_pub = [ks] * P2（G2 点）
            if not hasattr(self, "_sm9_ppub_cache") or self._sm9_ppub_cache is None:
                self._sm9_ppub_cache = _SM9.g2_mul(priv_key, _SM9.P2)
            # 派生用户私钥 ds_A = [t2] * P1
            ds_A, _t1, _t2, _h1 = _SM9.derive_user_key(idn_bytes, priv_key)
            h, S = _SM9.sign(msg_bytes, ds_A, P_pub_g2=self._sm9_ppub_cache)
            self.sig = (h, S)
            return self
        if _FAST_AVAILABLE:
            # 快路径：gmssl 签名，~2.4ms
            # pub 已知时直接复用，省掉 33ms 的标量乘
            pub = pub if pub is not None else sm2.scalar_mult(priv_key)
            fs = _FastSigner(priv_key, pub)
            r, s = fs.sign(idn_bytes, msg_bytes)
        else:
            # 慢路径：纯自研，~70ms
            r, s = sm2.sign(idn_bytes, priv_key, msg_bytes)
        self.sig = (r, s)
        return self

    def verify(self, issuer_idn, issuer_pub, now=None, seen_nonces=None,
               revoked_jtis=None, pq_pub=None):
        """本地校验。

        issuer_idn  签发方标识（用于 ZA 绑定；SM9 场景下直接作为 ID）
        issuer_pub  签发方公钥（SM2: G1 点 (x,y)；SM9: G2 点 P_pub）
        pq_pub      v2.16 抗量子档位公钥（ALG_SM2_MLDSA: mldsa pk；
                    ALG_HASH_SIG: slhdsa pk）
        now         当前时间戳（默认 time.time()）
        seen_nonces 已见 nonce 集合（防重放），可为 None
        revoked_jtis 已撤销 jti 集合，可为 None
        """
        now = now if now is not None else int(time.time())

        if self.sig is None:
            return False, "missing signature"

        idn_bytes = issuer_idn.encode("utf-8") if isinstance(issuer_idn, str) else issuer_idn
        msg_bytes = self.canonical_bytes()

        # 1) 签名结构与档位一致性检查（防降级：篡改 alg_tier 后结构必然不匹配）
        if self.alg_tier == ALG_SM9:
            if not (isinstance(self.sig, tuple) and len(self.sig) == 2
                    and isinstance(self.sig[0], int)
                    and isinstance(self.sig[1], tuple) and len(self.sig[1]) == 2
                    and all(isinstance(v, int) for v in self.sig[1])):
                return False, "signature invalid"
        elif self.alg_tier == ALG_SM2:
            if not (isinstance(self.sig, tuple) and len(self.sig) == 2
                    and isinstance(self.sig[0], int) and isinstance(self.sig[1], int)):
                return False, "signature invalid"
        elif self.alg_tier == ALG_SM2_MLDSA:
            # 混合签名必须是 ((r, s), dict) 结构
            if not (isinstance(self.sig, tuple) and len(self.sig) == 2
                    and isinstance(self.sig[0], tuple) and len(self.sig[0]) == 2
                    and all(isinstance(v, int) for v in self.sig[0])
                    and isinstance(self.sig[1], dict)):
                return False, "signature invalid"
        elif self.alg_tier == ALG_HASH_SIG:
            # hash-signature 签名必须是含 m/leaf/sig/path 的字典
            if not (isinstance(self.sig, dict)
                    and all(k in self.sig for k in ("m", "leaf", "sig", "path"))):
                return False, "signature invalid"
        else:
            return False, "signature invalid"

        # ---- v2.16：抗量子档位 ----
        if self.alg_tier == ALG_SM2_MLDSA:
            if not _MLD_AVAILABLE:
                return False, "mldsa not compiled"
            if pq_pub is None:
                return False, "pq public key unavailable"
            sm2_sig, mld_sig = self.sig
            r, s = sm2_sig
            # 失败关闭：两个分量都必须通过，任一失败即拒绝
            if _FAST_AVAILABLE:
                fs = _FastSigner(1, issuer_pub)
                sm2_ok = fs.verify(idn_bytes, r, s, msg_bytes)
            else:
                sm2_ok = sm2.verify(idn_bytes, issuer_pub, r, s, msg_bytes)
            if not sm2_ok:
                return False, "signature invalid"
            try:
                mld_ok = _MLD.verify(pq_pub, msg_bytes, mld_sig)
            except Exception:
                mld_ok = False
            if not mld_ok:
                return False, "signature invalid"
            return self._verify_tail(now, seen_nonces, revoked_jtis)

        if self.alg_tier == ALG_HASH_SIG:
            if not _SLH_AVAILABLE:
                return False, "slhdsa not compiled"
            if pq_pub is None:
                return False, "pq public key unavailable"
            try:
                slh_ok = _SLH.verify(pq_pub, msg_bytes, self.sig)
            except Exception:
                slh_ok = False
            if not slh_ok:
                return False, "signature invalid"
            return self._verify_tail(now, seen_nonces, revoked_jtis)

        # 2) 签名校验（按 alg_tier 分派）
        if self.alg_tier == ALG_SM9:
            if not _SM9_AVAILABLE:
                return False, "sm9 not compiled"
            h, S = self.sig
            try:
                ok = _SM9.verify(msg_bytes, h, S, idn_bytes, issuer_pub)
            except Exception:
                ok = False
            if not ok:
                return False, "signature invalid"
        else:
            r, s = self.sig
            if _FAST_AVAILABLE:
                # 快路径：gmssl._kg 加速标量乘，~20ms
                # 用 0 作为占位 priv（FastSigner 不需要真 priv 做 verify）
                fs = _FastSigner(1, issuer_pub)
                ok = fs.verify(idn_bytes, r, s, msg_bytes)
            else:
                # 慢路径：纯自研，~150ms
                ok = sm2.verify(idn_bytes, issuer_pub, r, s, msg_bytes)
            if not ok:
                return False, "signature invalid"

        return self._verify_tail(now, seen_nonces, revoked_jtis)

    def _verify_tail(self, now, seen_nonces, revoked_jtis):
        """签名校验通过后的时间窗口 / 防重放 / 撤销检查。"""
        # 3) 时间窗口
        if now < self.nbf:
            return False, "not yet valid"
        if now > self.exp:
            return False, "expired"

        # 4) 防重放（nonce 一次性）
        if seen_nonces is not None and self.nonce in seen_nonces:
            return False, "nonce replay"

        # 5) 撤销检查
        if revoked_jtis is not None and self.jti in revoked_jtis:
            return False, "revoked"

        return True, "ok"


def issue(identity_authority, sub, iss, aud, scope, ttl, **kw):
    """便捷签发：使用身份权威的标识密钥签发凭证。

    - alg_tier == ALG_SM2: 使用 IA 的 SM2 派生密钥 d_id
    - alg_tier == ALG_SM9: 使用 IA 的 SM9 主私钥 ks（无证书，由 ID 派生 ds_A）
    - alg_tier == ALG_SM2_MLDSA（v2.16）: SM2 分量用 d_id，ML-DSA 分量用
      kw["pq_sk"]（mldsa.keygen 产出的 sk）
    - alg_tier == ALG_HASH_SIG（v2.16）: 用 kw["pq_sk"]（slhdsa.keygen 产出的 sk）
    """
    alg_tier = kw.get("alg_tier", ALG_SM2)
    pq_sk = kw.pop("pq_sk", None)
    cred = Credential(sub=sub, iss=iss, aud=aud, scope=scope,
                      exp=int(time.time()) + ttl,
                      alg_tier=alg_tier, **kw)
    if alg_tier == ALG_SM9:
        # SM9：直接用主私钥 ks 签名（无证书）
        cred.sign(iss, identity_authority.ks)
    elif alg_tier in (ALG_SM2_MLDSA, ALG_HASH_SIG):
        d_id = _derive_key(identity_authority, iss)
        cred.sign(iss, d_id, pub=kw.get("pub"), pq_sk=pq_sk)
    else:
        d_id = _derive_key(identity_authority, iss)
        cred.sign(iss, d_id)
    return cred


def _derive_key(identity_authority, idn):
    """从 IdentityAuthority 反查标识密钥（SM2 路径）。"""
    from identity import _kdf  # 延迟导入避免循环
    return int.from_bytes(
        _kdf(identity_authority.mk, idn.encode("utf-8")), "big"
    ) % (sm2.N - 1) + 1


def self_check():
    """内部自检。"""
    from identity import IdentityAuthority
    import time as _t

    out = []
    ia = IdentityAuthority()

    # 签发 → 校验 → 通过
    idn_iss = "agent://demo-org/issuance-authority"
    idn_sub = "agent://demo-org/ops-agent-001"
    d_id, pub_id, _ = ia.issue(idn_iss.encode("utf-8"))

    cred = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                      scope=["invoice:read"], exp=int(_t.time()) + 3600)
    cred.sign(idn_iss, d_id)

    ok, why = cred.verify(idn_iss, pub_id, now=int(_t.time()))
    out.append(("凭证签发校验通过", ok and why == "ok"))

    # 过期后校验失败
    cred2 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"],
                       exp=int(_t.time()) - 60,
                       nbf=int(_t.time()) - 120)
    cred2.sign(idn_iss, d_id)
    ok2, why2 = cred2.verify(idn_iss, pub_id, now=int(_t.time()))
    out.append(("过期凭证校验失败", not ok2 and why2 == "expired"))

    # 篡改 scope 后校验失败
    cred3 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"], exp=int(_t.time()) + 3600)
    cred3.sign(idn_iss, d_id)
    cred3.scope = ("invoice:write",)  # 篡改
    ok3, why3 = cred3.verify(idn_iss, pub_id, now=int(_t.time()))
    out.append(("篡改 scope 后校验失败", not ok3 and why3 == "signature invalid"))

    # 换档位（alg_tier）后校验失败
    cred4 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"], exp=int(_t.time()) + 3600,
                       alg_tier=ALG_SM2)
    cred4.sign(idn_iss, d_id)
    cred4.alg_tier = ALG_HASH_SIG  # 篡改档位
    ok4, why4 = cred4.verify(idn_iss, pub_id, now=int(_t.time()))
    out.append(("篡改 alg_tier 后校验失败", not ok4))

    # 撤销后校验失败
    cred5 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"], exp=int(_t.time()) + 3600)
    cred5.sign(idn_iss, d_id)
    revoked = {cred5.jti}
    ok5, why5 = cred5.verify(idn_iss, pub_id, now=int(_t.time()),
                             revoked_jtis=revoked)
    out.append(("撤销后校验失败", not ok5 and why5 == "revoked"))

    # 防重放（nonce 复用）
    cred6 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"], exp=int(_t.time()) + 3600)
    cred6.sign(idn_iss, d_id)
    seen = {cred6.nonce}
    ok6, why6 = cred6.verify(idn_iss, pub_id, now=int(_t.time()),
                             seen_nonces=seen)
    out.append(("nonce 复用校验失败", not ok6 and why6 == "nonce replay"))

    # 未签发凭证校验失败
    cred7 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                       scope=["invoice:read"], exp=int(_t.time()) + 3600)
    ok7, why7 = cred7.verify(idn_iss, pub_id, now=int(_t.time()))
    out.append(("未签发凭证校验失败", not ok7 and why7 == "missing signature"))

    # ---- v2.16 抗量子档位 ----
    if _MLD_AVAILABLE:
        pk_mld, sk_mld = _MLD.keygen()

        # 混合签名（SM2 + ML-DSA）签发校验通过
        cred_h = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                            scope=["invoice:read"], exp=int(_t.time()) + 3600,
                            alg_tier=ALG_SM2_MLDSA)
        cred_h.sign(idn_iss, d_id, pub=pub_id, pq_sk=sk_mld)
        ok_h, why_h = cred_h.verify(idn_iss, pub_id, pq_pub=pk_mld,
                                    now=int(_t.time()))
        out.append(("混合签名 SM2+ML-DSA 校验通过", ok_h and why_h == "ok"))

        # 混合签名篡改消息后校验失败
        cred_h2 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_SM2_MLDSA)
        cred_h2.sign(idn_iss, d_id, pub=pub_id, pq_sk=sk_mld)
        cred_h2.scope = ("invoice:write",)
        ok_h2, _ = cred_h2.verify(idn_iss, pub_id, pq_pub=pk_mld,
                                  now=int(_t.time()))
        out.append(("混合签名篡改后校验失败", not ok_h2))

        # 混合签名降级到纯 SM2 后校验失败
        cred_h3 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_SM2_MLDSA)
        cred_h3.sign(idn_iss, d_id, pub=pub_id, pq_sk=sk_mld)
        cred_h3.alg_tier = ALG_SM2
        ok_h3, _ = cred_h3.verify(idn_iss, pub_id, pq_pub=pk_mld,
                                  now=int(_t.time()))
        out.append(("混合签名降级后校验失败", not ok_h3))

        # 混合签名篡改 PQ 分量后校验失败
        cred_h4 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_SM2_MLDSA)
        cred_h4.sign(idn_iss, d_id, pub=pub_id, pq_sk=sk_mld)
        sig_h4 = cred_h4.sig
        tampered = dict(sig_h4[1])
        tampered["ct"] = tampered["ct"][:-2] + ("00" if tampered["ct"][-2:] != "00" else "11")
        cred_h4.sig = (sig_h4[0], tampered)
        ok_h4, _ = cred_h4.verify(idn_iss, pub_id, pq_pub=pk_mld,
                                  now=int(_t.time()))
        out.append(("混合签名 PQ 分量篡改后校验失败", not ok_h4))

        # 混合签名缺少 PQ 公钥时失败关闭
        cred_h5 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_SM2_MLDSA)
        cred_h5.sign(idn_iss, d_id, pub=pub_id, pq_sk=sk_mld)
        ok_h5, why_h5 = cred_h5.verify(idn_iss, pub_id, pq_pub=None,
                                       now=int(_t.time()))
        out.append(("混合签名缺 PQ 公钥失败关闭", not ok_h5
                    and why_h5 == "pq public key unavailable"))

    if _SLH_AVAILABLE:
        pk_slh, sk_slh = _SLH.keygen()

        # hash-signature 签发校验通过
        cred_s = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                            scope=["invoice:read"], exp=int(_t.time()) + 3600,
                            alg_tier=ALG_HASH_SIG)
        cred_s.sign(idn_iss, d_id, pq_sk=sk_slh)
        ok_s, why_s = cred_s.verify(idn_iss, pub_id, pq_pub=pk_slh,
                                    now=int(_t.time()))
        out.append(("hash-signature SLH-DSA 校验通过", ok_s and why_s == "ok"))

        # hash-signature 篡改消息后校验失败
        cred_s2 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_HASH_SIG)
        cred_s2.sign(idn_iss, d_id, pq_sk=sk_slh)
        cred_s2.scope = ("invoice:write",)
        ok_s2, _ = cred_s2.verify(idn_iss, pub_id, pq_pub=pk_slh,
                                  now=int(_t.time()))
        out.append(("hash-signature 篡改后校验失败", not ok_s2))

        # hash-signature 篡改签名分量后校验失败
        cred_s3 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                             scope=["invoice:read"], exp=int(_t.time()) + 3600,
                             alg_tier=ALG_HASH_SIG)
        cred_s3.sign(idn_iss, d_id, pq_sk=sk_slh)
        tampered_s3 = {k: v for k, v in cred_s3.sig.items()}
        tampered_s3["sig"] = [bytes([b ^ 0xFF for b in cred_s3.sig["sig"][0]])]
        tampered_s3["sig"].extend(cred_s3.sig["sig"][1:])
        cred_s3.sig = tampered_s3
        ok_s3, _ = cred_s3.verify(idn_iss, pub_id, pq_pub=pk_slh,
                                  now=int(_t.time()))
        out.append(("hash-signature 篡改签名后校验失败", not ok_s3))

    # 跨档位串用：SM2 签名被伪装成抗量子档位必须失败
    if _MLD_AVAILABLE and _SLH_AVAILABLE:
        cred8 = Credential(sub=idn_sub, iss=idn_iss, aud="service://invoice",
                           scope=["invoice:read"], exp=int(_t.time()) + 3600,
                           alg_tier=ALG_SM2)
        cred8.sign(idn_iss, d_id, pub=pub_id)
        cred8.alg_tier = ALG_SM2_MLDSA
        ok8, _ = cred8.verify(idn_iss, pub_id, pq_pub=pk_mld, now=int(_t.time()))
        out.append(("SM2 签名伪装成混合档位失败", not ok8))
        cred8.alg_tier = ALG_HASH_SIG
        ok9, _ = cred8.verify(idn_iss, pub_id, pq_pub=pk_slh, now=int(_t.time()))
        out.append(("SM2 签名伪装成 hash-signature 失败", not ok9))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
