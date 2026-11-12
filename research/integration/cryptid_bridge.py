# -*- coding: utf-8 -*-
"""cryptid → A2A/MCP 桥接核心（纯逻辑，无 SDK 依赖）。

定位
----
把 agent-cryptid 的 `proto/` 凭证体系包装成「可在 A2A / MCP 的
`Authorization: Bearer <token>` 头里承载、并被服务端本地校验」的最小桥。
本模块只做三件事，且**不 import 任何 a2a / mcp / fastapi**——它被
`mcp_guard.py` 与 `a2a_guard.py` 共同引用，故必须保持零 SDK 依赖。

与协议缺口的对应
----------------
- **Bearer 承载**：cryptid wire 凭证（dict）经 `json → base64url` 压成
  紧凑 token，直接放进标准 `Authorization: Bearer` 头。现有 A2A/MCP
  客户端本就会发 Bearer，零协议改动接入。
- **audience 绑定（= MCP 禁 passthrough 的答案）**：token 的 `aud`
  在验签时与服务端期望受众比对，发给 server A 的 token 用于 server B
  会被 `audience mismatch` 拒绝——这正是 MCP「禁止 token 透传」要求的
  逐跳受众绑定。RFC 8707 的 `resource` ≡ cryptid `aud`。
- **scope / nonce / 撤销**：全部复用 `Platform.verify_credential` 的
  本地校验（签名 + 时间窗 + nonce 一次性 + 累加器撤销），无网络往返。

关键实现说明
------------
- **共享 Platform**：签发端与资源服务端必须信任同一份签发方公钥登记簿。
  演示里共用一个 in-memory `Platform`（等价于「资源服务器本地缓存了
  签发方身份」）；真实部署中二者分离，仅公钥/撤销快照同步。
- **nonce 一次性语义**：`verify_bearer(record_nonce=True)` 会登记 nonce，
  同一 token 第二次校验将因 `nonce replay` 失败——这是防重放的正确行为，
  测试须为每个 case 签新 token。
"""
import base64
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROTO = os.path.join(_HERE, "..", "..", "proto")
_PROTO = os.path.abspath(_PROTO)
if _PROTO not in sys.path:
    sys.path.insert(0, _PROTO)

from agent_platform import Platform  # noqa: E402


# ----------------------------------------------------------------------
# Bearer token 编解码（wire dict ↔ 紧凑字符串）
# ----------------------------------------------------------------------
def encode_bearer(wire_dict: dict) -> str:
    """wire dict → base64url(JSON) 紧凑 token（去 padding，可放 HTTP 头）。"""
    raw = json.dumps(wire_dict, separators=(",", ":"),
                     sort_keys=True, ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_bearer(token: str):
    """紧凑 token → wire dict；任何畸形输入返回 None（绝不抛异常）。"""
    if not token or not isinstance(token, str):
        return None
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad)
        d = json.loads(raw.decode("utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


# ----------------------------------------------------------------------
# 签发 / 校验
# ----------------------------------------------------------------------
class CryptidAuthority:
    """签发端：封装 Platform 的标识注册与凭证签发，产出 Bearer token。

    用法::
        auth = CryptidAuthority()
        auth.register("agent://org/issuer", agent_type="issuance")
        auth.register("agent://org/worker", agent_type="worker")
        tok = auth.issue(issuer="agent://org/issuer",
                         subject="agent://org/worker",
                         audience="service://invoice",
                         scope=["invoice:read"], ttl=3600)
    """

    def __init__(self, platform: Platform = None):
        self.platform = platform if platform is not None else Platform()

    def register(self, idn, org=None, agent_type="worker", owner="admin"):
        return self.platform.register_identity(idn, org=org,
                                               agent_type=agent_type,
                                               owner=owner)

    def issue(self, issuer, subject, audience, scope, ttl=3600,
              alg_tier="sm2"):
        """签发凭证并返回紧凑 Bearer token 字符串。

        返回 (token, meta)；meta 含 jti/exp 便于测试引用。
        签发失败时 meta["ok"]=False，token=None。
        """
        r = self.platform.issue_credential(issuer, subject, audience,
                                           scope, ttl=ttl, alg_tier=alg_tier)
        if not r.get("ok"):
            return None, {"ok": False, "reason": r.get("reason")}
        token = encode_bearer(r["cred"])
        return token, {"ok": True, "jti": r["jti"], "exp": r["exp"],
                       "alg_tier": alg_tier}

    def revoke(self, jti, reason="demo"):
        return self.platform.revoke(jti, reason=reason)


def verify_bearer(platform: Platform, token: str, audience=None,
                  record_nonce=True) -> dict:
    """资源服务端校验入口：Bearer token → cryptid 本地校验结果。

    返回 `Platform.verify_credential` 的结果 dict：
        {"ok": bool, "reason": str, "sub":..., "iss":..., "scope":[...], ...}
    - audience：本服务端期望的 cryptid 受众（= token 的 aud 必须等于它）。
      传入即执行受众绑定；None 则不校验受众（仅签名/时间/nonce/撤销）。
    - record_nonce：True 时登记 nonce（防重放，生产行为）；同一 token
      二次校验将得到 reason="nonce replay"。
    """
    wire = decode_bearer(token)
    if wire is None:
        return {"ok": False, "reason": "malformed token"}
    return platform.verify_credential(wire, audience=audience,
                                      record_nonce=record_nonce)


def principal_from_result(result: dict) -> dict:
    """把校验结果提炼成「主体三元组 + scope」，供 A2A/MCP 注入 request state。"""
    return {
        "sub": result.get("sub"),
        "iss": result.get("iss"),
        "scope": list(result.get("scope") or []),
        "jti": result.get("jti"),
    }


# ----------------------------------------------------------------------
# 自测（python cryptid_bridge.py）
# ----------------------------------------------------------------------
def self_check():
    out = []
    auth = CryptidAuthority()
    auth.register("agent://demo/issuer", agent_type="issuance")
    auth.register("agent://demo/worker", agent_type="worker")

    # 1) 编码往返
    tok, meta = auth.issue("agent://demo/issuer", "agent://demo/worker",
                           "service://invoice", ["invoice:read"], ttl=3600)
    out.append(("签发返回 token", tok is not None and meta["ok"]))
    out.append(("token 可解码回 dict", isinstance(decode_bearer(tok), dict)))
    out.append(("畸形 token 解码为 None", decode_bearer("!!!not-base64!!!") is None))
    out.append(("空 token 解码为 None", decode_bearer("") is None))

    # 2) 正常校验（受众匹配）
    r = verify_bearer(auth.platform, tok, audience="service://invoice")
    out.append(("有效 token 校验通过", r["ok"] and r["reason"] == "ok"))
    out.append(("校验带出 sub/scope",
                r.get("sub") == "agent://demo/worker"
                and r.get("scope") == ["invoice:read"]))

    # 3) 受众不匹配（passthrough 防御）：给 invoice 的 token 拿去 billing
    r = verify_bearer(auth.platform, tok, audience="service://billing",
                      record_nonce=False)
    out.append(("跨服务受众被拒", not r["ok"] and r["reason"] == "audience mismatch"))

    # 4) 篡改 token（反转载体破坏签名）
    tampered = tok[:-4] + ("AAAA" if tok[-4:] != "AAAA" else "BBBB")
    r = verify_bearer(auth.platform, tampered, audience="service://invoice",
                      record_nonce=False)
    out.append(("篡改 token 被拒", not r["ok"]))

    # 5) 撤销
    tok2, meta2 = auth.issue("agent://demo/issuer", "agent://demo/worker",
                             "service://invoice", ["invoice:read"], ttl=3600)
    auth.revoke(meta2["jti"], reason="compromise")
    r = verify_bearer(auth.platform, tok2, audience="service://invoice")
    out.append(("撤销后 token 被拒", not r["ok"] and r["reason"] == "revoked"))

    # 6) nonce 重放：同一 token 第二次校验失败
    tok3, _ = auth.issue("agent://demo/issuer", "agent://demo/worker",
                         "service://invoice", ["invoice:read"], ttl=3600)
    r1 = verify_bearer(auth.platform, tok3, audience="service://invoice")
    r2 = verify_bearer(auth.platform, tok3, audience="service://invoice")
    out.append(("首次校验通过", r1["ok"]))
    out.append(("重放被拒(nonce replay)", not r2["ok"] and r2["reason"] == "nonce replay"))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
