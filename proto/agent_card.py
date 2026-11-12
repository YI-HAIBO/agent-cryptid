# -*- coding: utf-8 -*-
"""智能体互联协议的智能体卡片签名扩展（FR7-03）。

智能体互联协议（如 A2A 一类）用「智能体卡片」描述一个智能体的身份与
能力：名称、端点、版本、能力集、技能列表、认证方式等。卡片通常是公开
可读的 JSON，问题随之而来——**任何人都可以复制一张卡片并声称自己是
那个智能体**。本模块给卡片加上密码学签名扩展，让消费方能验证三件事：

    1. 这张卡片确实由该标识的持有者签发（身份绑定）；
    2. 卡片内容自签发后未被篡改（内容哈希入签名）；
    3. 该卡片当前仍然有效（未过期、底层凭证未被撤销）。

零外部依赖，只依赖本项目的 sm2 / sm9 / Platform。

设计要点（后续别改坏）：
  1. **失败关闭**：任何一步校验不通过即拒绝，绝不降级放行。
  2. **内容哈希入签名**：卡片规范化字节的 SM3 摘要参与签名覆盖，
     改任何一个字段（含 iat/exp）都会导致验签失败。
  3. **算法档位防降级**：alg_tier 与签名结构必须严格匹配——
     SM9 签名是 (h, (Sx,Sy))、SM2 是 (r, s)。篡改 alg_tier 走错
     路径必须被拒绝（与 Credential.verify 同一套语义）。
  4. **撤销感知**：签名绑定底层凭证 jti，凭证被撤销则卡片立即失效。
     这是「卡片能被撤回」的关键能力，纯自签名方案做不到。
  5. **主体绑定**：验证方可要求 agent_idn 等于期望主体，
     防止把别人签发的卡片拿来冒充自己（混淆代理人攻击）。
  6. **签名输入不含卡片签名扩展本身**：先算内容哈希再签名，
     否则会陷入「签名覆盖自身」的循环依赖。

用法：
    plat = Platform(tenant="acme")
    signer = AgentCardSigner(plat)
    card = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent",
                     url="https://ops.acme.example", skills=[...])
    signed = signer.sign(card, issuer_idn="agent://acme/ops", jti=cred_jti)
    ok, why = signer.verify(signed, expected_subject="agent://acme/ops")
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sm2  # noqa: E402

try:
    import sm9 as _SM9
    _SM9_AVAILABLE = True
except ImportError:
    _SM9 = None
    _SM9_AVAILABLE = False

ALG_SM2 = "sm2"
ALG_SM9 = "sm9"


def _canonical(obj) -> bytes:
    """JSON 规范化：sort_keys + 紧凑分隔符 + UTF-8。

    与 Credential 的 _canonical 保持同一约定，保证同样的字段集合
    在任何进程内都得到同样的字节序列。
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str).encode("utf-8")


def _sm3_hex(data: bytes) -> str:
    """SM3 摘要 → hex 字符串（兼容 bytes / str 两种返回）。"""
    d = sm2.sm3(data)
    if isinstance(d, (bytes, bytearray)):
        return d.hex()
    return str(d)


class AgentCard:
    """智能体卡片。

    agent_idn       卡片所属智能体的标识（参与签名覆盖，防挪用）
    name            展示名
    description     能力描述
    url             智能体端点（互联协议用于实际调用）
    version         卡片/协议版本
    capabilities    能力声明（如 streaming / pushNotifications）
    skills          技能列表，元素为 dict（id / name / description ...）
    provider        提供方信息 dict
    authentication  认证方式声明 dict
    iat / exp       生效与失效时间；exp 由 ttl 推导
    """

    def __init__(self, agent_idn, name, description=None, url=None,
                 version="1.0", capabilities=None, skills=None,
                 provider=None, authentication=None,
                 iat=None, exp=None, ttl=86400):
        if not agent_idn:
            raise ValueError("agent_idn is required (卡片必须绑定标识)")
        now = int(time.time())
        self.agent_idn = agent_idn
        self.name = name or agent_idn
        self.description = description
        self.url = url
        self.version = version
        self.capabilities = list(capabilities or [])
        self.skills = list(skills or [])
        self.provider = dict(provider or {})
        self.authentication = dict(authentication or {})
        self.iat = iat if iat is not None else now
        self.exp = exp if exp is not None else self.iat + int(ttl)
        # 签名扩展：独立存放，不进入 canonical_bytes（避免自指）
        self.signature = None

    # ---------------------------------------------------------------
    # 序列化
    # ---------------------------------------------------------------
    def to_dict(self):
        """卡片本体（不含签名扩展）。"""
        return {
            "agent_idn": self.agent_idn,
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "skills": list(self.skills),
            "provider": dict(self.provider),
            "authentication": dict(self.authentication),
            "iat": self.iat,
            "exp": self.exp,
        }

    def canonical_bytes(self) -> bytes:
        """待哈希/签名的规范化字节（不含签名扩展）。"""
        return _canonical(self.to_dict())

    def content_hash(self) -> str:
        """卡片内容摘要（SM3 hex）。"""
        return _sm3_hex(self.canonical_bytes())

    def with_signature(self) -> dict:
        """返回「卡片 + 签名扩展」的完整 dict（对外发布用）。"""
        d = self.to_dict()
        if self.signature is not None:
            d["x-cryptid-signature"] = dict(self.signature)
        return d

    # ---------------------------------------------------------------
    # 反序列化
    # ---------------------------------------------------------------
    @staticmethod
    def from_dict(d):
        """从完整 dict 还原卡片（含签名扩展）。"""
        if not isinstance(d, dict):
            return None
        try:
            card = AgentCard(
                agent_idn=d["agent_idn"],
                name=d.get("name"),
                description=d.get("description"),
                url=d.get("url"),
                version=d.get("version", "1.0"),
                capabilities=d.get("capabilities"),
                skills=d.get("skills"),
                provider=d.get("provider"),
                authentication=d.get("authentication"),
                iat=d.get("iat"),
                exp=d.get("exp"),
                ttl=1,  # exp 已显式给出，ttl 不参与
            )
        except (KeyError, ValueError, TypeError):
            return None
        card.signature = d.get("x-cryptid-signature")
        return card


def _signing_input(card, jti, issuer_idn, alg_tier) -> bytes:
    """构造签名覆盖的输入。

    覆盖内容 = 卡片摘要 + 主体标识 + 凭证 jti + 签发方 + 时间窗 + 档位。
    缺任一都可能被利用：
      - 无 card_hash  → 卡片内容可被整体替换
      - 无 agent_idn  → 卡片可被挪用到别的智能体名下
      - 无 alg_tier   → 可篡改档位触发降级验签
      - 无 iat/exp    → 卡片可被无限期重放
    """
    return _canonical({
        "card_hash": card.content_hash(),
        "agent_idn": card.agent_idn,
        "jti": jti,
        "iss": issuer_idn,
        "iat": card.iat,
        "exp": card.exp,
        "alg_tier": alg_tier,
    })


class AgentCardSigner:
    """卡片签名 / 验签器，绑定 Platform 的密钥与撤销状态。

    platform  Platform 实例，提供标识私钥、公钥与撤销集合
    """

    def __init__(self, platform):
        self.platform = platform

    # ---------------------------------------------------------------
    # 签名
    # ---------------------------------------------------------------
    def sign(self, card, issuer_idn, jti=None, alg_tier=ALG_SM2,
             secret_signer_idn=None):
        """对卡片签名，返回卡片自身（signature 已填充）。

        issuer_idn        签名方标识（通常是卡片所属智能体自身或上级 CA）
        jti               绑定的凭证 jti（撤销依据）；为空时自动生成占位
        alg_tier          算法档位
        secret_signer_idn 实际持私钥的标识；缺省取 issuer_idn。
                          上级 CA 代签场景下两者不同。
        """
        if not isinstance(card, AgentCard):
            return {"ok": False, "reason": "invalid card"}
        if alg_tier not in (ALG_SM2, ALG_SM9):
            return {"ok": False, "reason": "unsupported alg_tier"}
        signer_idn = secret_signer_idn or issuer_idn
        if signer_idn not in self.platform._identities:
            return {"ok": False, "reason": "unknown signer"}
        rec = self.platform._identities[signer_idn]
        if rec.get("status") != "active":
            return {"ok": False, "reason": "signer disabled"}

        bound_jti = jti or ("card:" + card.content_hash()[:24])
        msg = _signing_input(card, bound_jti, issuer_idn, alg_tier)
        idn_bytes = signer_idn.encode("utf-8")

        if alg_tier == ALG_SM9:
            if not _SM9_AVAILABLE or not getattr(self.platform.ia, "ks", None):
                return {"ok": False, "reason": "sm9 unavailable"}
            kv = rec.get("key_version", 0)
            ks = self.platform.ia._get_ks(kv)
            ds_A, _t1, _t2, _h1 = _SM9.derive_user_key(idn_bytes, ks)
            ppub = self.platform.ia._get_ppub(kv)
            h, S = _SM9.sign(msg, ds_A, P_pub_g2=ppub)
            sig = {
                "alg_tier": alg_tier,
                "jti": bound_jti,
                "iss": issuer_idn,
                "signer_idn": signer_idn,
                "key_version": kv,
                "signed_at": int(time.time()),
                "card_hash": card.content_hash(),
                "sig_r": "%064x" % h,
                "sig_s_x": "%064x" % S[0],
                "sig_s_y": "%064x" % S[1],
            }
        else:
            priv = self.platform._derive_priv(signer_idn)
            r, s = sm2.sign(idn_bytes, priv, msg)
            sig = {
                "alg_tier": alg_tier,
                "jti": bound_jti,
                "iss": issuer_idn,
                "signer_idn": signer_idn,
                "key_version": rec.get("key_version", 0),
                "signed_at": int(time.time()),
                "card_hash": card.content_hash(),
                "sig_r": "%064x" % r,
                "sig_s": "%064x" % s,
            }

        card.signature = sig
        self.platform.audit.append({
            "kind": "agentcard.sign",
            "tenant": self.platform.tenant,
            "agent_idn": card.agent_idn,
            "iss": issuer_idn,
            "jti": bound_jti,
            "alg_tier": alg_tier,
        })
        return {"ok": True, "card": card.with_signature(),
                "jti": bound_jti, "alg_tier": alg_tier}

    # ---------------------------------------------------------------
    # 验签
    # ---------------------------------------------------------------
    def verify(self, card, now=None, expected_subject=None,
               revoked_jtis=None):
        """验证卡片签名。返回 (ok: bool, reason: str)。

        expected_subject 期望的主体标识；提供时必须等于 card.agent_idn
        revoked_jtis     已撤销 jti 集合；缺省取平台撤销集合
        """
        if not isinstance(card, AgentCard):
            return False, "invalid card"
        if not card.signature:
            return False, "missing signature"

        now = now if now is not None else int(time.time())
        sig = card.signature
        alg_tier = sig.get("alg_tier", ALG_SM2)
        jti = sig.get("jti")
        iss = sig.get("iss")
        signer_idn = sig.get("signer_idn") or iss

        # 1) 内容哈希一致性（防篡改）
        if sig.get("card_hash") != card.content_hash():
            return False, "card tampered"

        # 2) 主体绑定（防卡片挪用 / 混淆代理人）
        if expected_subject is not None and card.agent_idn != expected_subject:
            return False, "agent idn mismatch"

        # 3) 签名方必须已知且 active
        if signer_idn not in self.platform._identities:
            return False, "unknown signer"
        if self.platform._identities[signer_idn].get("status") != "active":
            return False, "signer disabled"

        # 4) 算法档位与签名结构严格匹配（防降级）
        has_xy = bool(sig.get("sig_s_x")) and bool(sig.get("sig_s_y"))
        has_s = bool(sig.get("sig_s"))
        if has_xy and alg_tier != ALG_SM9:
            return False, "signature invalid"
        if has_s and alg_tier != ALG_SM2:
            return False, "signature invalid"
        if not has_xy and not has_s:
            return False, "signature invalid"

        # 5) 时间窗口
        if now < card.iat:
            return False, "not yet valid"
        if now > card.exp:
            return False, "card expired"

        # 6) 撤销检查（凭证撤销 → 卡片失效）
        revoked = revoked_jtis if revoked_jtis is not None \
            else self.platform._revoked_jtis
        if revoked is not None and jti in revoked:
            return False, "revoked"

        # 7) 验签
        msg = _signing_input(card, jti, iss, alg_tier)
        idn_bytes = signer_idn.encode("utf-8")
        try:
            if alg_tier == ALG_SM9:
                if not _SM9_AVAILABLE:
                    return False, "sm9 unavailable"
                kv = sig.get("key_version", 0)
                ppub = self.platform.ia._get_ppub(kv)
                h = int(sig["sig_r"], 16)
                S = (int(sig["sig_s_x"], 16), int(sig["sig_s_y"], 16))
                ok = _SM9.verify(msg, h, S, idn_bytes, ppub)
            else:
                rec = self.platform._identities[signer_idn]
                pub = rec["pub"]
                r = int(sig["sig_r"], 16)
                s = int(sig["sig_s"], 16)
                ok = sm2.verify(idn_bytes, pub, r, s, msg)
        except Exception:
            return False, "signature invalid"
        if not ok:
            return False, "signature invalid"

        return True, "ok"


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def self_check():
    """内部自检（SM2 路径；SM9 真签名慢，由 check_v8 覆盖）。"""
    out = []
    from agent_platform import Platform

    p = Platform(tenant="cardtest")
    p.register_identity("agent://acme/ops", org="acme")
    p.register_identity("agent://acme/ca", org="acme")
    signer = AgentCardSigner(p)

    # --- A 卡片结构与摘要 ---
    c1 = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent",
                   url="https://ops.acme.example",
                   capabilities=["streaming"],
                   skills=[{"id": "restart", "name": "Restart service"}])
    c2 = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent",
                   url="https://ops.acme.example",
                   capabilities=["streaming"],
                   skills=[{"id": "restart", "name": "Restart service"}],
                   iat=c1.iat, exp=c1.exp)
    out.append(("A1 同内容卡片摘要一致", c1.content_hash() == c2.content_hash()))

    c3 = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent",
                   url="https://ops.acme.example", iat=c1.iat, exp=c1.exp)
    c3.skills = [{"id": "delete", "name": "Delete everything"}]
    out.append(("A2 改内容后摘要不同", c3.content_hash() != c1.content_hash()))

    # --- B 缺失标识 ---
    try:
        AgentCard(agent_idn="", name="x")
        out.append(("B1 空 agent_idn 被拒", False))
    except ValueError:
        out.append(("B1 空 agent_idn 被拒", True))

    # --- C 签名往返 ---
    r = signer.sign(c1, issuer_idn="agent://acme/ops", jti="jti-001")
    out.append(("C1 签名成功", r.get("ok") is True))
    out.append(("C2 含签名扩展", "x-cryptid-signature" in r["card"]))
    ok, why = signer.verify(c1)
    out.append(("C3 验签通过", ok is True and why == "ok"))

    # --- D 篡改检测 ---
    c1.name = "Evil Agent"
    ok, why = signer.verify(c1)
    out.append(("D1 改名称后验签失败", ok is False))
    out.append(("D2 失败原因是篡改/签名无效",
                why in ("card tampered", "signature invalid")))

    c_fresh = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent",
                        url="https://ops.acme.example")
    signer.sign(c_fresh, issuer_idn="agent://acme/ops", jti="jti-002")
    c_fresh.agent_idn = "agent://evil/ops"
    ok, why = signer.verify(c_fresh)
    out.append(("D3 改 agent_idn 后验签失败", ok is False))

    # --- E 主体绑定 ---
    c_e = AgentCard(agent_idn="agent://acme/ops", name="Ops Agent")
    signer.sign(c_e, issuer_idn="agent://acme/ops", jti="jti-003")
    ok, why = signer.verify(c_e, expected_subject="agent://acme/ops")
    out.append(("E1 期望主体一致通过", ok is True))
    ok, why = signer.verify(c_e, expected_subject="agent://other/x")
    out.append(("E2 期望主体不符被拒", ok is False and why == "agent idn mismatch"))

    # --- F 无签名 ---
    c_f = AgentCard(agent_idn="agent://acme/ops", name="No Sig")
    ok, why = signer.verify(c_f)
    out.append(("F1 无签名被拒", ok is False and why == "missing signature"))

    # --- G 过期 / 未生效 ---
    now = int(time.time())
    c_g = AgentCard(agent_idn="agent://acme/ops", name="Old",
                    iat=now - 7200, exp=now - 3600)
    signer.sign(c_g, issuer_idn="agent://acme/ops", jti="jti-004")
    ok, why = signer.verify(c_g)
    out.append(("G1 过期卡片被拒", ok is False and why == "card expired"))

    c_h = AgentCard(agent_idn="agent://acme/ops", name="Future",
                    iat=now + 3600, exp=now + 7200)
    signer.sign(c_h, issuer_idn="agent://acme/ops", jti="jti-005")
    ok, why = signer.verify(c_h, now=now)
    out.append(("G2 未生效卡片被拒", ok is False and why == "not yet valid"))

    # --- H 撤销感知 ---
    c_i = AgentCard(agent_idn="agent://acme/ops", name="Revocable")
    signer.sign(c_i, issuer_idn="agent://acme/ops", jti="jti-006")
    ok, _ = signer.verify(c_i)
    out.append(("H1 撤销前验签通过", ok is True))
    ok, why = signer.verify(c_i, revoked_jtis={"jti-006"})
    out.append(("H2 凭证撤销后卡片失效",
                ok is False and why == "revoked"))

    # --- I 算法档位防降级 ---
    c_j = AgentCard(agent_idn="agent://acme/ops", name="AlgTest")
    signer.sign(c_j, issuer_idn="agent://acme/ops", jti="jti-007")
    c_j.signature["alg_tier"] = ALG_SM9  # 篡改档位，sig 仍是 SM2 结构
    ok, why = signer.verify(c_j)
    out.append(("I1 篡改 alg_tier 被拒",
                ok is False and why == "signature invalid"))

    # --- J 未知签名方 ---
    c_k = AgentCard(agent_idn="agent://acme/ops", name="UnknownSigner")
    signer.sign(c_k, issuer_idn="agent://acme/ops", jti="jti-008")
    c_k.signature["signer_idn"] = "agent://ghost/x"
    ok, why = signer.verify(c_k)
    out.append(("J1 未知签名方被拒", ok is False and why == "unknown signer"))

    # --- K dict 往返 ---
    c_l = AgentCard(agent_idn="agent://acme/ops", name="Roundtrip",
                    url="https://x.example")
    signed = signer.sign(c_l, issuer_idn="agent://acme/ops", jti="jti-009")
    restored = AgentCard.from_dict(signed["card"])
    ok, why = signer.verify(restored)
    out.append(("K1 dict 往返后验签通过", ok is True))
    out.append(("K2 还原保留签名", restored.signature is not None))

    # --- L 上级 CA 代签 ---
    c_m = AgentCard(agent_idn="agent://acme/worker", name="Worker")
    r2 = signer.sign(c_m, issuer_idn="agent://acme/ca", jti="jti-010",
                     secret_signer_idn="agent://acme/ca")
    out.append(("L1 CA 代签成功", r2.get("ok") is True))
    ok, why = signer.verify(c_m)
    out.append(("L2 代签卡片验签通过", ok is True))

    # --- M 审计入链 ---
    kinds = [e.get("event", {}).get("kind")
             for e in p.audit.chain]
    out.append(("M1 签名事件入审计链", "agentcard.sign" in kinds))

    return out


if __name__ == "__main__":
    n_ok = 0
    for name, passed in self_check():
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            n_ok += 1
    res = self_check()
    print("\nRESULT  PASS=%d  FAIL=%d" % (n_ok, len(res) - n_ok))
