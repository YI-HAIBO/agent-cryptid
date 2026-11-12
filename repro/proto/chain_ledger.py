# -*- coding: utf-8 -*-
"""链式锚定存证（FR5-06，可复现替代「真上链」）。

动机
----
审计锚（audit_anchor）在内存/持久化后端存储，篡改不易被第三方检测；
「上链存证」要求锚点进入**不可篡改、可验证**的链式结构。本模块实现
ChainLedger：一条**可复现的 append-only 哈希链**（PoA 单权威签发 + 前块
哈希链接 + 块内 Merkle 根），真实写入审计锚并回读验证。

与「真上链（公链/联盟链 txid）」的接口同构：
- 上链 = ledger.append(anchor) → 返回 (height, block_hash)，block_hash 即
  链上引用（对应真链的 txid）；
- 验证 = ledger.verify_chain() + get(block_hash)；
- 若把本模块替换为 EVM 后端（每个 append 发布一笔 tx、返回 txid），
  上层接口不变——ledger-agnostic 承诺成立。

安全性质（self_check 逐条验证）
--------------------------------
1. 链完整性：每块 block_hash 由 header（height/prev_hash/ts/merkle_root/
   tx_hashes）推导，后继块的 prev_hash 必须等于前块 block_hash；
2. 块内承诺：merkle_root 是块内全部交易哈希的 Merkle 根，任何交易改动
   → 根不匹配；
3. 权威签名：块头由 PoA 权威 SM2 签名，错误密钥 → 拒绝；
4. 篡改可检测：改任意历史块（数据/根/签名）→ verify_chain 定位坏块高度；
5. 自锚定：验证方只需持有权威公钥即可离线校验整链（无第三方信任）。

API
---
- ChainLedger(authority_priv, authority_pub)
- .append(anchor_dict) → {"height", "block_hash", "tx_count"}
- .get(block_hash) / .latest() / .height
- .verify_chain() → (ok, bad_height)
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

GENESIS_PREV = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _merkle_root(hashes) -> str:
    if not hashes:
        return ""
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])  # 奇数补双（Bitcoin 风格）
        level = [sm2.sm3(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0].hex()


class ChainLedger:
    """append-only 哈希链（PoA 单权威签发），审计锚上链存证。"""

    def __init__(self, authority_priv, authority_pub):
        self._priv = authority_priv
        self._pub = authority_pub
        self._blocks = []       # list[Block]
        self._by_hash = {}      # block_hash -> Block

    # ----------------------------------------------------------------
    # 追加（上链）
    # ----------------------------------------------------------------
    def append(self, anchor_dict) -> dict:
        """把审计锚上链。anchor_dict 是 AuditAnchor.to_dict()（含签名）。

        返回 {"height", "block_hash", "tx_count"}；block_hash 是链上引用
        （对应真链 txid）。
        """
        tx = _canonical(anchor_dict)
        tx_hash = sm2.sm3(tx).hex()
        prev = self._blocks[-1]["block_hash"] if self._blocks else GENESIS_PREV
        height = len(self._blocks)
        ts = int(time.time())
        tx_hashes = [tx_hash]
        merkle = _merkle_root(tx_hashes)
        header = {
            "height": height, "prev_hash": prev, "ts": ts,
            "merkle_root": merkle, "tx_hashes": tx_hashes,
        }
        hb = _canonical(header)
        block_hash = sm2.sm3(hb).hex()
        try:
            from sm2_fast import FastSigner
            pub = sm2.scalar_mult(self._priv)
            r, s = FastSigner(self._priv, pub).sign(
                b"agent://ledger/authority", hb)
        except Exception:
            r, s = sm2.sign(b"agent://ledger/authority", self._priv, hb)
        block = {
            "header": header, "block_hash": block_hash,
            "tx": anchor_dict, "tx_hash": tx_hash,
            "sig_r": r, "sig_s": s,
        }
        self._blocks.append(block)
        self._by_hash[block_hash] = block
        return {"height": height, "block_hash": block_hash, "tx_count": 1}

    # ----------------------------------------------------------------
    # 查询
    # ----------------------------------------------------------------
    @property
    def height(self):
        return len(self._blocks)

    def latest(self):
        return self._blocks[-1] if self._blocks else None

    def get(self, block_hash):
        return self._by_hash.get(block_hash)

    def get_anchor(self, block_hash):
        b = self._by_hash.get(block_hash)
        return b["tx"] if b else None

    # ----------------------------------------------------------------
    # 整链验证
    # ----------------------------------------------------------------
    def verify_chain(self) -> tuple:
        """从创世走到顶，校验每块的 prev_hash 链接、块哈希、Merkle 根、
        权威签名。返回 (ok, bad_height)；ok=False 时 bad_height 指向坏块。
        """
        prev_hash = GENESIS_PREV
        for i, b in enumerate(self._blocks):
            hdr = b["header"]
            # a) prev_hash 链接
            if hdr["prev_hash"] != prev_hash:
                return False, i
            # b) 块哈希自洽
            if sm2.sm3(_canonical(hdr)).hex() != b["block_hash"]:
                return False, i
            # c) Merkle 根承诺
            if _merkle_root(hdr["tx_hashes"]) != hdr["merkle_root"]:
                return False, i
            # e) 交易承诺：块内交易内容确实哈希到 header.tx_hashes
            if len(hdr["tx_hashes"]) != 1:
                return False, i
            if sm2.sm3(_canonical(b["tx"])).hex() != hdr["tx_hashes"][0]:
                return False, i
            # d) 权威签名
            try:
                from sm2_fast import FastSigner
                ok = FastSigner(1, self._pub).verify(
                    b"agent://ledger/authority", b["sig_r"], b["sig_s"],
                    _canonical(hdr))
            except Exception:
                ok = sm2.verify(b"agent://ledger/authority", self._pub,
                                b["sig_r"], b["sig_s"], _canonical(hdr))
            if not ok:
                return False, i
            prev_hash = b["block_hash"]
        return True, None


def self_check() -> list:
    """链式锚定自检。"""
    out = []
    priv, pub = sm2.gen_keypair()
    ledger = ChainLedger(priv, pub)

    # 1) 追加 3 个审计锚（模拟 audit_anchor 输出）
    anchors = []
    for i in range(3):
        a = {"anchor_id": i + 1, "ts": 1000 + i,
             "chain_len": 10 + i, "root_hash": ("ab%02x" % i) * 32,
             "issuer_idn": "agent://anchor/ledger",
             "sig_r": i + 1, "sig_s": i + 2}
        r = ledger.append(a)
        anchors.append((r, a))
    out.append(("追加 3 块后链高=3", ledger.height == 3))
    out.append(("返回 block_hash 非空", all(a[0]["block_hash"] for a in anchors)))

    # 2) 整链验证通过
    ok, bad = ledger.verify_chain()
    out.append(("整链验证通过", ok is True and bad is None))

    # 3) 前块哈希链接（第 1 块 prev=创世，第 2 块 prev=第 1 块 hash）
    b0, b1 = ledger._blocks[0], ledger._blocks[1]
    out.append(("创世块 prev_hash=创世占位", b0["header"]["prev_hash"] == GENESIS_PREV))
    out.append(("后继块 prev_hash=前块 block_hash",
                b1["header"]["prev_hash"] == b0["block_hash"]))

    # 4) 篡改历史块数据 → 块哈希自洽失败
    b0["tx"]["root_hash"] = "ff" * 32  # 改交易数据
    ok, bad = ledger.verify_chain()
    out.append(("篡改块数据后验证定位坏块 0",
                ok is False and bad == 0))
    b0["tx"]["root_hash"] = ("ab00") * 32  # 还原
    out.append(("还原后整链验证通过", ledger.verify_chain()[0] is True))

    # 5) 篡改 Merkle 根 → 根承诺失败
    b0["header"]["merkle_root"] = "ee" * 32
    ok, bad = ledger.verify_chain()
    out.append(("篡改 Merkle 根后验证定位坏块 0",
                ok is False and bad == 0))
    b0["header"]["merkle_root"] = _merkle_root(b0["header"]["tx_hashes"])

    # 6) 篡改签名 → 权威签名失败
    sig_orig = b0["sig_r"]
    b0["sig_r"] = (b0["sig_r"] + 1) % sm2.N
    ok, bad = ledger.verify_chain()
    out.append(("篡改签名后验证定位坏块 0",
                ok is False and bad == 0))
    b0["sig_r"] = sig_orig  # 还原
    out.append(("还原签名后整链验证通过", ledger.verify_chain()[0] is True))

    # 7) 错误权威密钥 → 整链拒绝
    _, wrong_pub = sm2.gen_keypair()
    ledger2 = ChainLedger(priv, pub)
    ledger2._pub = wrong_pub
    for i in range(2):
        ledger2.append({"anchor_id": i, "ts": 1 + i, "chain_len": 1,
                        "root_hash": "aa" * 32, "issuer_idn": "x",
                        "sig_r": 1, "sig_s": 2})
    ok, bad = ledger2.verify_chain()
    out.append(("错误权威密钥整链拒绝", ok is False and bad == 0))

    # 8) get / get_anchor 回读
    h = anchors[1][0]["block_hash"]
    got = ledger.get_anchor(h)
    out.append(("按 block_hash 回读锚点", got is not None
                and got["anchor_id"] == 2))

    # 9) 交易哈希承诺：块内 tx_hash 与交易内容一致
    b = ledger._blocks[2]
    out.append(("块内 tx_hash=SM3(交易) 一致",
                b["tx_hash"] == sm2.sm3(_canonical(b["tx"])).hex()))

    # 10) 序列化往返（链可持久化）
    import copy
    snap = copy.deepcopy(ledger._blocks)
    ledger3 = ChainLedger(priv, pub)
    ledger3._blocks = snap
    ledger3._by_hash = {b["block_hash"]: b for b in snap}
    out.append(("链快照恢复后验证通过", ledger3.verify_chain()[0] is True))

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
                               "chain_ledger_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
