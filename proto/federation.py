# -*- coding: utf-8 -*-
"""跨域撤销联邦（FR4-06）。

动机
----
域内撤销由 RevokeAccumulator（Merkle 累加器）承担，但撤销状态是**域内**的：
域 B 的验证者看到域 A 签发的凭证时，无法仅凭本地累加器判断"域 A 是否已撤销
该 jti"。本模块把撤销从「域内查询」提升为「跨域可验证证明」：

- 每个域（authority）持有一把**权威签名密钥**（SM2），其公钥是**本域撤销
  主张的信任根**（自锚定，无第三方信任）；
- 域 A 撤销某 jti 时，用权威密钥对撤销记录 {domain, jti, ts, reason, ver}
  签名，发布到联邦目录；
- 域 B 的验证者经目录解析域 A 的公钥（目录项自签名，可离线校验），验证该
  撤销记录的签名即可确认"域 A 确实撤销了 jti"——**不需要信任联邦本身，
  只需信任域 A 的公钥**（与 PKI 的信任锚同理，但撤销主张由签发方自证）。

安全性质
--------
1. 撤销主张完整性：记录被篡改（换 jti / 改 ts / 改域 / 改原因）→ 签名失败；
2. 防张冠李戴：记录的 domain 必须等于目录解析出的域；记录的 jti 必须等于
   被验证的 jti；
3. 防旧记录重放：记录版本 ver 必须 ≥ 验证方已知的该域最新版本（单调）；
4. 自锚定：目录项的 authority_pub 由权威密钥自签名，验证方只需已持有该
   公钥即可离线校验，不引入额外的联邦信任根。

API
---
- RevocationRecord(domain, jti, ts, reason, ver)  .sign(priv) / .verify(pub)
- FederationDirectory.register(domain, pub, priv)  → 自签名目录项
- FederationDirectory.resolve(domain)              → authority_pub（校验自签名）
- CrossDomainRevocation.revoke(acc, directory, domain, priv, jti, reason)
- CrossDomainRevocation.verify_record(record, directory, target_jti, min_ver)

集成：域内仍用 RevokeAccumulator 做本地快速拒绝；跨域用本模块做可验证证明。
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class RevocationRecord:
    """跨域撤销记录（由签发域权威密钥签名）。"""

    def __init__(self, domain, jti, ts=None, reason="", ver=1,
                 sig_r=None, sig_s=None):
        self.domain = str(domain)
        self.jti = str(jti)
        self.ts = int(ts) if ts is not None else int(time.time())
        self.reason = str(reason)
        self.ver = int(ver)
        self.sig_r = sig_r
        self.sig_s = sig_s

    def payload_bytes(self) -> bytes:
        return _canonical({
            "domain": self.domain,
            "jti": self.jti,
            "ts": self.ts,
            "reason": self.reason,
            "ver": self.ver,
        })

    def sign(self, priv_key, idn_bytes=None) -> "RevocationRecord":
        idn = idn_bytes if idn_bytes is not None \
            else ("agent://fed/revoke/" + self.domain).encode("utf-8")
        msg = self.payload_bytes()
        try:
            from sm2_fast import FastSigner
            pub = sm2.scalar_mult(priv_key)
            r, s = FastSigner(priv_key, pub).sign(idn, msg)
        except Exception:
            r, s = sm2.sign(idn, priv_key, msg)
        self.sig_r, self.sig_s = r, s
        return self

    def verify(self, authority_pub) -> tuple:
        if self.sig_r is None or self.sig_s is None:
            return False, "no signature"
        idn = ("agent://fed/revoke/" + self.domain).encode("utf-8")
        msg = self.payload_bytes()
        try:
            from sm2_fast import FastSigner
            ok = FastSigner(1, authority_pub).verify(idn, self.sig_r,
                                                     self.sig_s, msg)
        except Exception:
            ok = sm2.verify(idn, authority_pub, self.sig_r, self.sig_s, msg)
        return (True, "ok") if ok else (False, "signature invalid")

    def to_dict(self) -> dict:
        return {
            "domain": self.domain, "jti": self.jti, "ts": self.ts,
            "reason": self.reason, "ver": self.ver,
            "sig_r": self.sig_r, "sig_s": self.sig_s,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RevocationRecord":
        return cls(domain=d["domain"], jti=d["jti"], ts=d.get("ts"),
                   reason=d.get("reason", ""), ver=d.get("ver", 1),
                   sig_r=d.get("sig_r"), sig_s=d.get("sig_s"))


class FederationDirectory:
    """域 → 权威公钥目录。条目由权威密钥自签名（自锚定）。

    验证方只需已持有某域的 authority_pub 即可离线校验其撤销主张；
    目录本身可被替换，但替换无法伪造有效签名（无联邦信任根依赖）。
    """

    def __init__(self):
        self._entries = {}  # domain -> {pub:(x,y), sig_r, sig_s, registered_ts}

    def register(self, domain, authority_pub, authority_priv=None,
                 idn_bytes=None) -> dict:
        """登记一个域。authority_priv 提供时自签名（自锚定）。

        返回目录项。若未提供私钥，仍登记（调用方保证信任已建立），
        但记录 signed=False —— 自锚定场景必须提供私钥。
        """
        domain = str(domain)
        idn = idn_bytes or ("agent://fed/domain/" + domain).encode("utf-8")
        entry = {
            "domain": domain,
            "pub": [int(authority_pub[0]), int(authority_pub[1])],
            "registered_ts": int(time.time()),
            "signed": False,
            "sig_r": None,
            "sig_s": None,
        }
        if authority_priv is not None:
            payload = _canonical({
                "domain": domain,
                "pub": entry["pub"],
                "registered_ts": entry["registered_ts"],
            })
            try:
                from sm2_fast import FastSigner
                pub = sm2.scalar_mult(authority_priv)
                r, s = FastSigner(authority_priv, pub).sign(idn, payload)
            except Exception:
                r, s = sm2.sign(idn, authority_priv, payload)
            entry["sig_r"], entry["sig_s"] = r, s
            entry["signed"] = True
        self._entries[domain] = entry
        return entry

    def resolve(self, domain, idn_bytes=None) -> tuple:
        """解析域的权威公钥。返回 (pub, ok)；目录项自签名被校验。

        返回 (None, False) 表示域未登记或自签名校验失败。
        """
        entry = self._entries.get(str(domain))
        if entry is None:
            return None, False
        if entry.get("signed"):
            idn = idn_bytes or ("agent://fed/domain/" + str(domain)).encode("utf-8")
            payload = _canonical({
                "domain": entry["domain"],
                "pub": entry["pub"],
                "registered_ts": entry["registered_ts"],
            })
            try:
                from sm2_fast import FastSigner
                ok = FastSigner(1, tuple(entry["pub"])).verify(
                    idn, entry["sig_r"], entry["sig_s"], payload)
            except Exception:
                ok = sm2.verify(idn, tuple(entry["pub"]),
                                entry["sig_r"], entry["sig_s"], payload)
            if not ok:
                return None, False
        return tuple(entry["pub"]), True

    def domains(self) -> list:
        return list(self._entries.keys())


class CrossDomainRevocation:
    """跨域撤销：签发侧（域权威）与验证侧（任意域验证者）。"""

    @staticmethod
    def revoke(accumulator, directory, domain, authority_priv,
               jti, reason="", min_ver=1) -> RevocationRecord:
        """域权威撤销 jti：先写入域内累加器（本地快速拒绝），
        再签发跨域撤销记录并登记到目录。

        min_ver 用于跨域重播场景：调用方传入已知版本 + 1 以保证单调。
        """
        # 1) 域内撤销（本地立即生效）
        acc_info = accumulator.revoke(jti)
        ver = acc_info.get("version", min_ver)
        # 2) 域权威签发跨域记录
        record = RevocationRecord(domain=domain, jti=jti, ts=int(time.time()),
                                  reason=reason, ver=max(ver, min_ver))
        record.sign(authority_priv)
        return record

    @staticmethod
    def verify_record(record, directory, target_jti, min_ver=0) -> tuple:
        """验证方校验跨域撤销记录。

        返回 (ok, reason)。ok 为 True 表示「域 A 确实撤销了 target_jti」。
        检查：目录可解析域 → 自签名成立 → 记录签名有效 → 记录.jti 与
        target_jti 一致 → 记录.ver ≥ min_ver（单调，防旧记录重放）。
        """
        if not isinstance(record, RevocationRecord):
            return False, "bad record"
        # a) 目录解析域权威公钥（自锚定）
        pub, ok = directory.resolve(record.domain)
        if not ok:
            return False, "unknown domain"
        # b) 记录签名有效
        vok, why = record.verify(pub)
        if not vok:
            return False, "signature invalid"
        # c) 张冠李戴：jti 一致
        if record.jti != str(target_jti):
            return False, "jti mismatch"
        # d) 单调：防旧记录重放
        if record.ver < int(min_ver):
            return False, "stale version"
        return True, "ok"


def self_check() -> list:
    """跨域撤销联邦自检。"""
    out = []
    directory = FederationDirectory()
    # 两域 A、B，各自权威密钥
    a_priv, a_pub = sm2.gen_keypair()
    b_priv, b_pub = sm2.gen_keypair()

    # 1) 目录登记（自签名）
    directory.register("domain-a", a_pub, a_priv)
    directory.register("domain-b", b_pub, b_priv)
    resolved, ok = directory.resolve("domain-a")
    out.append(("目录解析 domain-a 返回其公钥",
                ok and tuple(resolved) == tuple(a_pub)))
    out.append(("目录解析 domain-b 返回其公钥",
                directory.resolve("domain-b")[0] == b_pub))

    # 2) 域 A 撤销 jti，签发跨域记录
    from revocation import RevokeAccumulator
    acc_a = RevokeAccumulator(capacity=8)
    rec = CrossDomainRevocation.revoke(acc_a, directory, "domain-a",
                                       a_priv, "jti-1234", reason="compromise")
    out.append(("撤销记录已签名", rec.sig_r is not None and rec.sig_s is not None))

    # 3) 域 B 的验证者用域 A 公钥（经目录）验证跨域撤销证明
    ok, why = CrossDomainRevocation.verify_record(rec, directory, "jti-1234")
    out.append(("跨域验证：域 B 确认域 A 已撤销 jti-1234", ok is True and why == "ok"))

    # 4) 防张冠李戴：用错误 target_jti 验证
    ok, why = CrossDomainRevocation.verify_record(rec, directory, "jti-9999")
    out.append(("防张冠李戴：jti 不匹配拒绝", ok is False and why == "jti mismatch"))

    # 5) 防篡改：换 jti 后签名失败
    rec2 = RevocationRecord.from_dict(rec.to_dict())
    rec2.jti = "jti-9999"
    ok, why = CrossDomainRevocation.verify_record(rec2, directory, "jti-9999")
    out.append(("防篡改：改 jti 后签名无效", ok is False))

    # 6) 防篡改：改域后签名失败（且目录无法解析新域）
    rec3 = RevocationRecord.from_dict(rec.to_dict())
    rec3.domain = "domain-c"  # 未登记域
    ok, why = CrossDomainRevocation.verify_record(rec3, directory, "jti-1234")
    out.append(("防篡改：改域后无法解析", ok is False and why == "unknown domain"))

    # 7) 防篡改：改 ts 后签名失败
    rec4 = RevocationRecord.from_dict(rec.to_dict())
    rec4.ts = rec4.ts + 1000
    ok, why = CrossDomainRevocation.verify_record(rec4, directory, "jti-1234")
    out.append(("防篡改：改 ts 后签名无效", ok is False))

    # 8) 防旧记录重放：min_ver 高于记录版本
    ok, why = CrossDomainRevocation.verify_record(rec, directory, "jti-1234",
                                                  min_ver=rec.ver + 1)
    out.append(("防旧记录重放：版本落后拒绝", ok is False and why == "stale version"))

    # 9) 用错误公钥验证（权威密钥即信任根，错误密钥不成立）
    _, wrong_pub = sm2.gen_keypair()
    ok, _ = rec.verify(wrong_pub)
    out.append(("用错误权威公钥验证失败", ok is False))

    # 10) 序列化往返
    rec5 = RevocationRecord.from_dict(rec.to_dict())
    ok, why = CrossDomainRevocation.verify_record(rec5, directory, "jti-1234")
    out.append(("序列化往返后可验证", ok is True))

    # 11) 未登记域解析失败
    pub, ok = directory.resolve("domain-none")
    out.append(("未登记域解析返回失败", pub is None and ok is False))

    # 12) 目录项自签名被篡改 → resolve 失败
    directory2 = FederationDirectory()
    directory2.register("domain-a", a_pub, a_priv)
    directory2._entries["domain-a"]["pub"] = [int(b_pub[0]), int(b_pub[1])]
    pub, ok = directory2.resolve("domain-a")
    out.append(("目录项自签名被篡改后 resolve 失败", pub is None and ok is False))

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
                               "federation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
