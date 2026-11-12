# -*- coding: utf-8 -*-
"""审计哈希链锚点（P2 v3.0「上链存证」雏形）。

设计
----
审计哈希链本身是内存结构，重启即失。锚点机制的核心是：
- 在**已知时刻**对当时的审计链根做签名承诺，形成"防篡改时间承诺"；
- 即使审计链本体丢失，事后仍可凭锚点证明"在 ts 时刻，链长为 N、
  根哈希为 H，且签发方确实承诺过这一点"；
- 未来上真链时，只需把锚点签名替换成"txid + 上链根"，接口不变。

结构
----
AuditAnchor：
    ts          锚点生成时间（Unix 秒）
    chain_len   当时的审计链长度
    root_hash   当时的审计链根哈希（hex）
    issuer_idn  签发锚点的标识（用于绑定公钥）
    sig_r, sig_s 签发方 SM2 签名
    anchor_id   存储后的自增序号（Store 分配）

Store：
    - 内存实现（默认）：进程内可查
    - 可选持久化钩子：pers.append_audit_anchor(tenant, dict)

安全性质
--------
- 载荷 payload = JSON({ts, chain_len, root_hash})，字典序、紧凑 JSON
- 签名覆盖 payload，与 IA 标识密钥绑定（ZA 机制）
- 验证方只需 (issuer_pub, anchor) 即可离线校验，不需要审计链本体
- 篡改 ts / chain_len / root_hash 任意一个 → 签名验证失败

API
---
- AuditAnchor.sign(priv_key)         用 IA 私钥签名
- AuditAnchor.verify(issuer_pub)     用 IA 公钥离线验证
- AuditAnchorStore.add(anchor)       加入存储（可选持久化）
- AuditAnchorStore.list(since_ts)    按时间倒序列出
- AuditAnchorStore.latest()          最新锚点
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

try:
    from sm2_fast import FastSigner as _FastSigner
    _FAST = True
except ImportError:
    _FastSigner = None
    _FAST = False


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class AuditAnchor:
    """审计哈希链锚点。"""

    def __init__(self, ts, chain_len, root_hash, issuer_idn,
                 sig_r=None, sig_s=None):
        self.ts = int(ts)
        self.chain_len = int(chain_len)
        self.root_hash = str(root_hash)
        self.issuer_idn = str(issuer_idn)
        self.sig_r = sig_r
        self.sig_s = sig_s
        self.anchor_id = None  # 由 Store 分配

    # ----- 载荷 -----
    def payload_bytes(self) -> bytes:
        return _canonical({
            "ts": self.ts,
            "chain_len": self.chain_len,
            "root_hash": self.root_hash,
        })

    # ----- 签名 -----
    def sign(self, priv_key, idn_bytes=None) -> "AuditAnchor":
        idn = idn_bytes if idn_bytes is not None \
            else self.issuer_idn.encode("utf-8")
        msg = self.payload_bytes()
        if _FAST:
            pub = sm2.scalar_mult(priv_key)
            fs = _FastSigner(priv_key, pub)
            r, s = fs.sign(idn, msg)
        else:
            r, s = sm2.sign(idn, priv_key, msg)
        self.sig_r, self.sig_s = r, s
        return self

    def verify(self, issuer_pub) -> tuple:
        if self.sig_r is None or self.sig_s is None:
            return False, "no signature"
        idn = self.issuer_idn.encode("utf-8")
        msg = self.payload_bytes()
        if _FAST:
            fs = _FastSigner(1, issuer_pub)
            ok = fs.verify(idn, self.sig_r, self.sig_s, msg)
        else:
            ok = sm2.verify(idn, issuer_pub, self.sig_r, self.sig_s, msg)
        return (True, "ok") if ok else (False, "signature invalid")

    # ----- 序列化 -----
    @property
    def has_signature(self) -> bool:
        return self.sig_r is not None and self.sig_s is not None

    def to_dict(self) -> dict:
        d = {
            "ts": self.ts,
            "chain_len": self.chain_len,
            "root_hash": self.root_hash,
            "issuer_idn": self.issuer_idn,
            "sig_r": self.sig_r,
            "sig_s": self.sig_s,
        }
        if self.anchor_id is not None:
            d["anchor_id"] = self.anchor_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AuditAnchor":
        a = cls(
            ts=d["ts"], chain_len=d["chain_len"],
            root_hash=d["root_hash"], issuer_idn=d["issuer_idn"],
            sig_r=d.get("sig_r"), sig_s=d.get("sig_s"),
        )
        # anchor_id 由 Store 分配，dict 里有就还原，没有保持 None
        a.anchor_id = d.get("anchor_id")
        return a


class AuditAnchorStore:
    """锚点存储。默认内存；可通过 pers 钩子同步到持久化后端。"""

    def __init__(self, pers=None):
        self._pers = pers
        self._anchors = []
        self._id_seq = 0
        self._tenant = "default"

    def set_tenant(self, tenant):
        self._tenant = tenant

    def hydrate(self, rows: list, tenant: str) -> None:
        """从持久化后端恢复锚点。rows 是 list_audit_anchors 返回的 dict 列表。"""
        self._tenant = tenant
        for row in rows:
            try:
                a = AuditAnchor.from_dict(row)
                self._anchors.append(a)
                if a.anchor_id:
                    self._id_seq = max(self._id_seq, a.anchor_id)
            except Exception:
                continue

    def add(self, anchor: AuditAnchor, tenant=None) -> AuditAnchor:
        t = tenant if tenant is not None else self._tenant
        self._id_seq += 1
        anchor.anchor_id = self._id_seq
        self._anchors.append(anchor)
        if self._pers is not None:
            try:
                self._pers.append_audit_anchor(t, anchor.to_dict())
            except Exception:
                pass  # 持久化失败不阻塞
        return anchor

    def list(self, since_ts=None, limit=100, tenant=None) -> list:
        if self._pers is not None and tenant:
            try:
                rows = self._pers.list_audit_anchors(
                    tenant, since_ts=since_ts, limit=limit)
                return [AuditAnchor.from_dict(r) for r in rows]
            except Exception:
                pass
        result = list(self._anchors)
        if since_ts is not None:
            result = [a for a in result if a.ts >= since_ts]
        # 用 (ts, anchor_id) 作排序键：ts 秒级精度易撞车，
        # 用 anchor_id（严格单调递增）作 tie-break，保证倒序稳定
        result.sort(key=lambda a: (a.ts, a.anchor_id or 0), reverse=True)
        return result[:limit]

    def latest(self, tenant=None) -> AuditAnchor:
        if self._pers is not None and tenant:
            try:
                rows = self._pers.list_audit_anchors(tenant, limit=1)
                return AuditAnchor.from_dict(rows[0]) if rows else None
            except Exception:
                pass
        if not self._anchors:
            return None
        return max(self._anchors, key=lambda a: (a.ts, a.anchor_id or 0))

    def __len__(self):
        return len(self._anchors)


def self_check() -> list:
    """审计锚点自测。"""
    out = []
    # 准备 IA 密钥
    ia_mk = sm2.sm3(b"audit-anchor-test-mk")
    priv = int.from_bytes(ia_mk, "big") % (sm2.N - 1) + 1
    pub = sm2.scalar_mult(priv)

    issuer_idn = "agent://anchor-test/ia"

    # 1) 构造锚点 + 签名
    a = AuditAnchor(ts=1000, chain_len=42, root_hash="ab" * 32,
                    issuer_idn=issuer_idn)
    a.sign(priv)
    out.append(("锚点签名后 sig_r 非空", a.sig_r is not None))
    out.append(("锚点签名后 sig_s 非空", a.sig_s is not None))

    # 2) 用正确公钥验证
    ok, why = a.verify(pub)
    out.append(("正确公钥验证通过", ok is True and why == "ok"))

    # 3) 用错误公钥验证
    _, pub_wrong = sm2.gen_keypair()
    ok, why = a.verify(pub_wrong)
    out.append(("错误公钥验证失败", ok is False))

    # 4) 未签名锚点
    a2 = AuditAnchor(ts=2000, chain_len=1, root_hash="cd" * 32,
                     issuer_idn=issuer_idn)
    ok, why = a2.verify(pub)
    out.append(("未签名锚点验证失败", ok is False and why == "no signature"))

    # 5) 篡改 root_hash 后验证失败
    a3 = AuditAnchor(ts=3000, chain_len=7, root_hash="ef" * 32,
                     issuer_idn=issuer_idn)
    a3.sign(priv)
    a3.root_hash = "ff" * 32  # 篡改
    ok, why = a3.verify(pub)
    out.append(("篡改 root_hash 后验证失败", ok is False))

    # 6) 篡改 ts 后验证失败
    a4 = AuditAnchor(ts=4000, chain_len=8, root_hash="12" * 32,
                     issuer_idn=issuer_idn)
    a4.sign(priv)
    a4.ts = 4001  # 篡改
    ok, why = a4.verify(pub)
    out.append(("篡改 ts 后验证失败", ok is False))

    # 7) 篡改 chain_len 后验证失败
    a5 = AuditAnchor(ts=5000, chain_len=9, root_hash="34" * 32,
                     issuer_idn=issuer_idn)
    a5.sign(priv)
    a5.chain_len = 10  # 篡改
    ok, why = a5.verify(pub)
    out.append(("篡改 chain_len 后验证失败", ok is False))

    # 8) Store 基本操作
    store = AuditAnchorStore()
    a1 = AuditAnchor(ts=100, chain_len=1, root_hash="aa" * 32,
                     issuer_idn=issuer_idn)
    a2 = AuditAnchor(ts=200, chain_len=2, root_hash="bb" * 32,
                     issuer_idn=issuer_idn)
    a3 = AuditAnchor(ts=300, chain_len=3, root_hash="cc" * 32,
                     issuer_idn=issuer_idn)
    store.add(a1)
    store.add(a2)
    store.add(a3)
    out.append(("Store 加入 3 个锚点", len(store) == 3))

    # 9) Store list 按时间倒序
    lst = store.list(limit=10)
    out.append(("list 按时间倒序", [a.ts for a in lst] == [300, 200, 100]))

    # 10) Store latest
    out.append(("latest 返回最新", store.latest().ts == 300))

    # 11) Store list 按时间过滤
    lst = store.list(since_ts=200, limit=10)
    out.append(("list since_ts 过滤", [a.ts for a in lst] == [300, 200]))

    # 12) 序列化往返
    a6 = AuditAnchor(ts=900, chain_len=5, root_hash="dd" * 32,
                     issuer_idn=issuer_idn)
    a6.sign(priv)
    d = a6.to_dict()
    a7 = AuditAnchor.from_dict(d)
    ok, why = a7.verify(pub)
    out.append(("序列化往返后可验证", ok is True))

    # 13) 载荷稳定（同 anchor 多次取 payload 一致）
    p1 = a.payload_bytes()
    p2 = a.payload_bytes()
    out.append(("payload 稳定", p1 == p2))

    return out


def main():
    results = self_check()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%s  %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "audit_anchor_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
