# -*- coding: utf-8 -*-
"""委托链层：多跳委托的构造、审计哈希链上链存证与本地验链。

委托链结构：
    hop0 = 根凭证（root issuer → agent A）
    hop1 = A → B 的委托（sub=B, iss=A, act=A）
    hop2 = B → C 的委托（sub=C, iss=B, act=B）
    ...
    最终 hopN 是持链方 agent。

本地验链：
    从根到末端逐跳校验：
      1) 每一跳的签名有效（用跳签发方的公钥）
      2) 每一跳的 sub 与下一跳的 act/iss 对得上（防跳链伪造）
      3) 每一跳的 aud 匹配（受众一致）
      4) 时间窗未过期（所有跳）
      5) jti 未撤销（所有跳）
      6) nonce 未复用（所有跳）

审计哈希链：
    每条委托生成一个审计事件，事件以 SHA-256 前链绑定；
    本地存证，模拟区块链上链。返回根哈希与叶子链。
"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402
from credential import Credential  # noqa: E402


GENESIS_HEX = "0" * 64  # 64 位十六进制零串，对应 32 字节空哈希
GENESIS = GENESIS_HEX.encode("utf-8")


def _canonical_audit(event):
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def verify_chain(chain, issuers, now=None, seen_nonces=None,
                 revoked_jtis=None, pq_pubs=None):
    """校验委托链。

    chain       [cred0, cred1, ..., credN]
                cred0 = root, cred[i].sub = cred[i+1].act/iss
    issuers     dict: idn -> pub_id  (所有签发方)
    now         当前时间戳
    seen_nonces 已见 nonce 集合
    revoked_jtis 已撤销 jti 集合
    pq_pubs     v2.16：dict: idn -> PQ 公钥（抗量子档位链路的额外公钥），
                可为 None。

    返回 (bool, [str, ...])：整体是否通过 + 每跳原因列表。
    """
    now = now if now is not None else int(time.time())
    reasons = []
    if not chain:
        return False, ["empty chain"]

    for i, cred in enumerate(chain):
        issuer_idn = cred.iss
        if issuer_idn not in issuers:
            reasons.append("hop %d: unknown issuer %s" % (i, issuer_idn))
            continue
        pq_pub = (pq_pubs or {}).get(issuer_idn)
        ok, why = cred.verify(issuer_idn, issuers[issuer_idn], now=now,
                              seen_nonces=seen_nonces,
                              revoked_jtis=revoked_jtis, pq_pub=pq_pub)
        if not ok:
            reasons.append("hop %d: %s" % (i, why))
            continue
        reasons.append("hop %d: ok" % i)

        # 跳间连续性：本跳的 sub 必须等于下一跳的 iss
        if i + 1 < len(chain):
            nxt = chain[i + 1]
            if nxt.iss != cred.sub:
                reasons.append("hop %d→%d: issuer continuity broken" %
                               (i, i + 1))
            # 受众传递：下一跳的 aud 必须与根一致
            if nxt.aud != chain[0].aud:
                reasons.append("hop %d→%d: audience mismatch" %
                               (i, i + 1))
            # FR3-02 权限收敛：子级作用域不得超出父级
            if not set(nxt.scope).issubset(set(cred.scope)):
                esc = sorted(set(nxt.scope) - set(cred.scope))
                reasons.append("hop %d→%d: scope escalation %s" %
                               (i, i + 1, esc))
            # FR3-05 有效期收敛：子级有效期不得超出父级
            if nxt.exp > cred.exp:
                reasons.append("hop %d→%d: exp exceeds parent" %
                               (i, i + 1))

    all_ok = all(r.endswith(": ok") for r in reasons)
    return all_ok, reasons


class AuditLog:
    """审计哈希链（本地存证，模拟上链）。"""

    def __init__(self):
        self.chain = []  # 每项：{hash, prev, event}

    def append(self, event):
        prev_hex = self.chain[-1]["hash"] if self.chain else GENESIS_HEX
        ts = int(time.time())
        payload = _canonical_audit({
            "seq": len(self.chain),
            "ts": ts,
            "event": event,
        })
        h = hashlib.sha256(prev_hex.encode("utf-8") + payload).hexdigest()
        entry = {
            "hash": h,
            "prev": prev_hex,
            "event": event,
            "payload": payload.decode("utf-8"),
            # v2.10：事件时间直接挂在条目上，供审计检索与合规报表使用
            # （此前只能从 payload 反解，持久化路径还有字段不一致的坑）
            "ts": ts,
        }
        self.chain.append(entry)
        return entry

    def verify(self):
        """验证审计链完整性。返回 (bool, reason)。"""
        prev_hex = GENESIS_HEX
        for i, entry in enumerate(self.chain):
            if entry["prev"] != prev_hex:
                return False, "hash link broken at %d" % i
            if not entry["hash"]:
                return False, "missing hash at %d" % i
            prev_hex = entry["hash"]
        return True, "ok"

    @property
    def root_hash(self):
        return self.chain[-1]["hash"] if self.chain else None

    def count(self):
        return len(self.chain)


def build_chain(identity_authority, root_issuer, sub0, aud, scope, ttl,
                hops, delegator_key=None):
    """构建委托链。hops = [id1, id2, ..., idN]，从 sub0 逐跳委托。

    返回 [cred0, cred1, ..., credN]。
    """
    chain = []
    # 第 0 跳：root issuer 给 sub0 签发根凭证
    cred0 = Credential(sub=sub0, iss=root_issuer, aud=aud, scope=scope,
                       exp=int(time.time()) + ttl)
    d0 = _derive(identity_authority, root_issuer)
    cred0.sign(root_issuer, d0)
    chain.append(cred0)

    prev = cred0
    for hop_idn in hops:
        # hop_idn 是"发起委托"的标识，把权限委托给下一跳（用新的 sub）
        # 这里 hops 里放的是"委托链中的每个新主体"
        d_prev = _derive(identity_authority, prev.sub)
        # FR3-05：子级有效期不得超出父级。连续签发时 now 递增，
        # now+ttl 天然大于父级 exp，故显式截断到 prev.exp。
        child_exp = min(int(time.time()) + ttl, prev.exp)
        cred = Credential(sub=hop_idn, iss=prev.sub, aud=aud, scope=scope,
                          exp=child_exp)
        cred.act = prev.sub  # 明确 act 字段
        cred.sign(prev.sub, d_prev)
        chain.append(cred)
        prev = cred
    return chain


def _derive(identity_authority, idn):
    """从 IdentityAuthority 反查标识密钥。"""
    from identity import _kdf
    return int.from_bytes(
        _kdf(identity_authority.mk, idn.encode("utf-8")), "big"
    ) % (sm2.N - 1) + 1


def self_check():
    """内部自检。"""
    from identity import IdentityAuthority
    import time as _t

    out = []
    ia = IdentityAuthority()

    # 生成 4 个标识
    ids = [
        "agent://root/issuance-authority",
        "agent://org-a/agent-01",
        "agent://org-b/agent-02",
        "agent://org-c/agent-03",
    ]
    pub_by_id = {}
    for idn in ids:
        _, pub, _ = ia.issue(idn.encode("utf-8"))
        pub_by_id[idn] = pub

    # 建 3 跳委托链
    chain = build_chain(ia, ids[0], ids[1], "service://invoice",
                        ["invoice:read"], 3600, [ids[2], ids[3]])
    ok, reasons = verify_chain(chain, pub_by_id, now=int(_t.time()))
    out.append(("三跳委托链完整校验通过",
                ok and len(reasons) == len(chain)))

    # 撤销中间一跳 → 失败
    revoked = {chain[1].jti}
    ok2, reasons2 = verify_chain(chain, pub_by_id, now=int(_t.time()),
                                revoked_jtis=revoked)
    out.append(("中间跳撤销后校验失败", not ok2))

    # 篡改某跳签名（改 aud）→ 失败
    bad = [c for c in chain]
    bad[0] = Credential(sub=bad[0].sub, iss=bad[0].iss, aud="service://other",
                        scope=bad[0].scope, exp=bad[0].exp,
                        iat=bad[0].iat, nbf=bad[0].nbf,
                        nonce=bad[0].nonce, alg_tier=bad[0].alg_tier,
                        jti=bad[0].jti, act=bad[0].act)
    ok3, reasons3 = verify_chain(bad, pub_by_id, now=int(_t.time()))
    out.append(("篡改根凭证受众后校验失败", not ok3))

    # 审计哈希链：三条委托全部入链
    audit = AuditLog()
    for i, c in enumerate(chain):
        audit.append({"kind": "delegate", "seq": i, "jti": c.jti})
    out.append(("审计哈希链写入 %d 条" % len(chain),
                audit.count() == len(chain) and audit.root_hash is not None))

    # 审计链完整性
    ok5, why5 = audit.verify()
    out.append(("审计哈希链完整性", ok5))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
