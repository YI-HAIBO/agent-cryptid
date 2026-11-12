# -*- coding: utf-8 -*-
"""基于 Merkle Tree 的撤销累加器（v2.1 引入）。

替代 v2.0 之前的「jti 黑名单」方案：
- 撤销集合随时间单调增长，黑名单 O(N) 全量下发给每个客户端不现实；
- Merkle 累加器把撤销集合组织成一棵满二叉树，每次 revoke 只需 O(log N)
  的认证路径，客户端本地可离线验证某 jti 是否已被撤销；
- 快照根（root hash）O(1) 大小，便于控制面下发、数据面缓存；
- 树满时（默认 1024 个撤销位）冻结当前树，另起新树，历史树根一起下发。

设计取舍
--------
- **哈希选 SM3**：项目零第三方依赖 + 国密合规双重要求，直接用 sm2.sm3；
- **空叶子哨兵**：`SM3(b"EMPTY")` 32 字节，保证任意索引位置都有确定值，
  验证路径无需处理"叶子缺失"分支；
- **只增不减**：撤销是永久事件（不做"恢复"），因此树的 leaf 位置一次
  占用后不再变化——这是累加器的正确性前提；
- **树容量固定 2 的幂**：1024，避免奇数叶子处理；超过则冻结并另起；
- **不追求去匿名化**：目前证明里带 jti 本身；如需匿名可加一层 HMAC，
  留给 v3.0 上链存证方案配合。

API（对齐《技术方案》API-07 / API-08 语义）
-------------------------------------------
- revoke(jti)          -> 证明 dict；同时递增版本
- proof(jti)           -> {leaf_hash, sibling_path, root, tree_id, version}
- verify_proof(proof)  -> bool；纯本地，无 I/O
- snapshot()           -> {version, current_root, frozen_roots, total}
"""
import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

# SM3 输出 256 位 = 32 字节；空叶子哨兵
EMPTY_LEAF = sm2.sm3(b"__REVACC_EMPTY_LEAF__")
CAPACITY = 1024  # 满二叉树叶子数，2 的幂


def _merkle_root(leaves: List[bytes]) -> bytes:
    """从叶子列表折叠出根哈希。要求 len(leaves) 为 2 的幂。"""
    assert len(leaves) and (len(leaves) & (len(leaves) - 1)) == 0
    level = list(leaves)
    while len(level) > 1:
        level = [sm2.sm3(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


class RevokeAccumulator:
    """单调增长的 Merkle 撤销累加器。

    - `revoke(jti)`：把 jti 加入当前活跃树；树满则冻结、另起新树。
    - `proof(jti)`：返回该 jti 的认证路径（若已撤销）；未撤销返回 None。
    - `verify_proof(proof)`：静态方法，本地校验证明是否对得上 root。
    - `snapshot()`：下发 {version, current_root, frozen_roots, total}。

    线程安全：本类本身不加锁；生产环境由上层（Platform 或 SQLiteBackend）
    保证 revoke 与 snapshot 的互斥。
    """

    def __init__(self, capacity: int = CAPACITY):
        assert (capacity & (capacity - 1)) == 0 and capacity > 0, \
            "capacity must be a power of 2"
        self.capacity = capacity
        self.leaves: List[bytes] = [EMPTY_LEAF] * capacity
        self.count = 0                       # 当前活跃树已用的叶子数
        self.frozen_roots: List[bytes] = []  # 历史冻结树的根
        self.version = 0                     # 全局撤销版本号
        self._jti_index = {}                 # jti -> (tree_id, leaf_index)

    # ---------------------------------------------------------------
    # 写入
    # ---------------------------------------------------------------
    def revoke(self, jti: str) -> dict:
        """把 jti 加入撤销集合；返回本次撤销记录（含证明）。

        jti 已存在则抛 ValueError——撤销是幂等操作，重复调用应视为调用
        方错误（Platform 层已保证，此处作为累加器自身的防御性校验）。
        """
        if jti in self._jti_index:
            raise ValueError("already revoked: %s" % jti)
        # 树满则冻结
        if self.count >= self.capacity:
            self.frozen_roots.append(_merkle_root(self.leaves))
            self.leaves = [EMPTY_LEAF] * self.capacity
            self.count = 0

        # 找空叶子：从 count 位置向后扫；因为只增不减，第一个空叶子即目标
        idx = None
        for i in range(self.count, self.capacity):
            if self.leaves[i] == EMPTY_LEAF:
                idx = i
                break
        if idx is None:  # 理论上不会到这里（已在上面冻结）
            raise RuntimeError("accumulator capacity underflow")

        leaf = sm2.sm3(jti.encode("utf-8"))
        self.leaves[idx] = leaf
        self.count += 1
        self.version += 1

        tree_id = len(self.frozen_roots)  # 当前树编号（0-based）
        self._jti_index[jti] = (tree_id, idx)

        return {
            "version": self.version,
            "jti": jti,
            "tree_id": tree_id,
            "leaf_index": idx,
            "leaf_hash": leaf,
        }

    # ---------------------------------------------------------------
    # 查询与证明
    # ---------------------------------------------------------------
    def proof(self, jti: str) -> Optional[dict]:
        """若 jti 已被撤销，返回认证路径；否则返回 None。"""
        loc = self._jti_index.get(jti)
        if loc is None:
            return None
        tree_id, leaf_index = loc

        # 选目标树：tree_id < len(frozen_roots) 则从 leaves 快照取
        # 这里简化：只对"当前活跃树"计算证明；历史树证明需要持久化时
        # 再实现（v2.1 范围外）
        if tree_id != len(self.frozen_roots):
            return None  # 冻结树暂不支持（当前原型规模远小于 1024）

        leaf_hash = self.leaves[leaf_index]
        path = self._sibling_path(leaf_index)
        return {
            "jti": jti,
            "tree_id": tree_id,
            "leaf_index": leaf_index,
            "leaf_hash": leaf_hash.hex(),
            "sibling_path": [b.hex() for b in path],
            "root": _merkle_root(self.leaves).hex(),
            "version": self.version,
            "capacity": self.capacity,
        }

    def _sibling_path(self, idx: int) -> List[bytes]:
        """从 leaf 起，逐层取 sibling 哈希，直到 root。"""
        level = list(self.leaves)
        path = []
        while len(level) > 1:
            sib_idx = idx ^ 1
            path.append(level[sib_idx])
            nxt = [sm2.sm3(level[i] + level[i + 1])
                   for i in range(0, len(level), 2)]
            level = nxt
            idx //= 2
        return path

    # ---------------------------------------------------------------
    # 验证
    # ---------------------------------------------------------------
    @staticmethod
    def verify_proof(proof: dict) -> bool:
        """本地验证累加器证明：从 leaf 起逐层折 sibling 直到 root。

        纯本地、零 I/O、无累加器实例依赖——这正是「数据面分离」的价值。
        """
        if not isinstance(proof, dict):
            return False
        try:
            h = bytes.fromhex(proof["leaf_hash"])
            idx = int(proof["leaf_index"])
            target_root = bytes.fromhex(proof["root"])
            path = [bytes.fromhex(x) for x in proof["sibling_path"]]
        except Exception:
            return False

        for sib in path:
            if idx % 2 == 0:
                h = sm2.sm3(h + sib)
            else:
                h = sm2.sm3(sib + h)
            idx //= 2
        return h == target_root

    @staticmethod
    def verify_revocation(proof: dict, jti: str) -> bool:
        """验证证明且证明的 jti 与目标一致（防"证明张冠李戴"）。"""
        if not isinstance(proof, dict):
            return False
        if proof.get("jti") != jti:
            return False
        return RevokeAccumulator.verify_proof(proof)

    # ---------------------------------------------------------------
    # 快照
    # ---------------------------------------------------------------
    # ---------------------------------------------------------------
    # 持久化（v2.4：直接存 leaves，避免每次启动 O(n) replay 重建）
    # ---------------------------------------------------------------
    def state_dict(self) -> dict:
        """完整可恢复状态（含 leaves 与 jti 索引），用于持久化。"""
        return {
            "version": self.version,
            "capacity": self.capacity,
            "count": self.count,
            "leaves": [b.hex() for b in self.leaves],
            "frozen_roots": [b.hex() for b in self.frozen_roots],
            "jti_index": {k: list(v) for k, v in self._jti_index.items()},
        }

    def load_state(self, state: dict) -> bool:
        """从 state_dict 恢复。容量不匹配则拒绝恢复。"""
        try:
            cap = int(state["capacity"])
            if cap != self.capacity:
                return False
            leaves = [bytes.fromhex(x) for x in state["leaves"]]
            if len(leaves) != self.capacity:
                return False
            self.leaves = leaves
            self.count = int(state["count"])
            self.version = int(state["version"])
            self.frozen_roots = [bytes.fromhex(x)
                                 for x in state.get("frozen_roots", [])]
            self._jti_index = {k: (int(v[0]), int(v[1]))
                               for k, v in state.get("jti_index", {}).items()}
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------
    # 快照
    # ---------------------------------------------------------------
    def snapshot(self) -> dict:
        """返回下发给数据面的最小累加器状态。"""
        if self.count == 0 and not self.frozen_roots:
            return {
                "version": self.version,
                "current_root": None,
                "frozen_roots": [],
                "total_revoked": 0,
                "capacity": self.capacity,
            }
        return {
            "version": self.version,
            "current_root": _merkle_root(self.leaves).hex()
                            if self.count > 0 else None,
            "frozen_roots": [b.hex() for b in self.frozen_roots],
            "total_revoked": self.version,
            "capacity": self.capacity,
        }


def self_check() -> list:
    """累加器自检。返回 [(name, ok), ...]。"""
    out = []
    acc = RevokeAccumulator(capacity=8)  # 用小容量方便触发表满

    # 1) 空累加器快照
    snap = acc.snapshot()
    out.append(("空累加器 version=0", snap["version"] == 0))
    out.append(("空累加器 total=0", snap["total_revoked"] == 0))
    out.append(("空累加器 root=None", snap["current_root"] is None))

    # 2) 撤销第一个 jti
    rec1 = acc.revoke("jti-001")
    out.append(("revoke#1 version=1", rec1["version"] == 1))
    out.append(("revoke#1 leaf_index=0", rec1["leaf_index"] == 0))

    p1 = acc.proof("jti-001")
    out.append(("proof(jti-001) 非空", p1 is not None))
    out.append(("proof(jti-001) 验证通过", RevokeAccumulator.verify_proof(p1)))
    out.append(("proof(jti-001) jti 匹配",
                RevokeAccumulator.verify_revocation(p1, "jti-001")))
    out.append(("proof(jti-001) jti 不匹配则失败",
                not RevokeAccumulator.verify_revocation(p1, "jti-other")))

    # 3) 未撤销的 jti 无证明
    out.append(("proof(未撤销 jti) 返回 None", acc.proof("jti-999") is None))

    # 4) 撤销多个
    acc.revoke("jti-002")
    acc.revoke("jti-003")
    for jti in ("jti-001", "jti-002", "jti-003"):
        p = acc.proof(jti)
        out.append(("proof(%s) 验证通过" % jti,
                    RevokeAccumulator.verify_proof(p)))

    # 5) 快照
    snap = acc.snapshot()
    out.append(("snapshot total=3", snap["total_revoked"] == 3))
    out.append(("snapshot version=3", snap["version"] == 3))
    out.append(("snapshot root 非空", snap["current_root"] is not None))

    # 6) 独立验证：模拟数据面（不持有 acc 实例）
    #    取 proof 与 root 后，仅凭两者离线验证
    p = acc.proof("jti-002")
    root_hex = snap["current_root"]
    proof_standalone = dict(p)
    proof_standalone["root"] = root_hex  # 覆盖成最新 root
    out.append(("独立验证：最新 root 可验证证明",
                RevokeAccumulator.verify_proof(proof_standalone)))

    # 7) 篡改 leaf_hash 应失败
    tampered = dict(p)
    bad_leaf = bytes(32).hex()
    tampered["leaf_hash"] = bad_leaf
    out.append(("篡改 leaf_hash 后验证失败",
                not RevokeAccumulator.verify_proof(tampered)))

    # 8) 篡改 sibling_path 应失败
    tampered = dict(p)
    path = list(tampered["sibling_path"])
    path[0] = bytes(32).hex()
    tampered["sibling_path"] = path
    out.append(("篡改 sibling_path 后验证失败",
                not RevokeAccumulator.verify_proof(tampered)))

    # 9) 篡改 root 应失败
    tampered = dict(p)
    tampered["root"] = bytes(32).hex()
    out.append(("篡改 root 后验证失败",
                not RevokeAccumulator.verify_proof(tampered)))

    # 10) 表满触发冻结：capacity=8，已用 3，再撤销 5 个刚好满，第 6 个应冻结
    for i in range(4, 9):
        acc.revoke("jti-%03d" % i)  # jti-004..jti-008（补齐到 8）
    out.append(("填至满时 frozen_roots=0", len(acc.frozen_roots) == 0))
    acc.revoke("jti-009")  # 第 9 个 → 触发冻结
    out.append(("第 9 次撤销触发冻结", len(acc.frozen_roots) == 1))
    out.append(("冻结后 count=1", acc.count == 1))
    out.append(("冻结后 version=9", acc.version == 9))

    # 11) 快照含冻结根
    snap = acc.snapshot()
    out.append(("冻结后 frozen_roots=1", len(snap["frozen_roots"]) == 1))
    out.append(("冻结后 total=9", snap["total_revoked"] == 9))

    # 12) capacity 校验：非 2 的幂应抛错
    try:
        RevokeAccumulator(capacity=1000)
        out.append(("非 2 的幂 capacity 应拒绝", False))
    except AssertionError:
        out.append(("非 2 的幂 capacity 应拒绝", True))

    # 13) 重复 revoke 应抛 ValueError
    try:
        acc.revoke("jti-001")
        out.append(("重复 revoke 应拒绝", False))
    except ValueError:
        out.append(("重复 revoke 应拒绝", True))

    # 14) v2.4：状态持久化往返（保存 → 新实例恢复 → 证明仍可验证）
    st = acc.state_dict()
    acc2 = RevokeAccumulator(capacity=8)
    out.append(("state_dict → load_state 恢复成功",
                acc2.load_state(st) is True))
    out.append(("恢复后 version 一致", acc2.version == acc.version))
    out.append(("恢复后 count 一致", acc2.count == acc.count))
    out.append(("恢复后根一致",
                acc2.snapshot()["current_root"] ==
                acc.snapshot()["current_root"]))
    p9 = acc2.proof("jti-009")
    out.append(("恢复后 proof(jti-009) 可验证",
                RevokeAccumulator.verify_proof(p9)))
    out.append(("恢复后 jti 索引完整",
                acc2._jti_index.get("jti-001") == (0, 0)))

    # 15) v2.4：容量不匹配应拒绝恢复（防状态串租户/串配置污染）
    acc3 = RevokeAccumulator(capacity=16)
    out.append(("容量不匹配应拒绝恢复", acc3.load_state(st) is False))

    # 16) v2.4：损坏状态（截断的 leaves）应拒绝恢复而非抛异常
    acc4 = RevokeAccumulator(capacity=8)
    bad = dict(st)
    bad["leaves"] = st["leaves"][:4]
    out.append(("损坏状态应拒绝恢复且不抛异常",
                acc4.load_state(bad) is False))

    return out


def main():
    import os
    results = self_check()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%s  %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "revocation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
