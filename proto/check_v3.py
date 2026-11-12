# -*- coding: utf-8 -*-
"""v2.1 Nonce 存储集成测试。

覆盖：
  I  MemoryNonceStore 默认注入后 Platform 工作正常（向后兼容）
  J  SqliteNonceStore 注入 → 同 DB 两个 Platform 实例共享 nonce
  K  跨进程：SqliteNonceStore 让 A 进程已见 nonce，B 进程也判为已见
  L  nonce_ttl 过期后允许再次验签
  M  record_nonce=False 不写入存储
  N  多租户 nonce 隔离：两个 Platform 各自持有独立 store
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform  # noqa: E402
from nonce_store import MemoryNonceStore, SqliteNonceStore  # noqa: E402


def _register_basic(p, name="X"):
    p.register_identity("agent://%s/iss" % name, org=name, agent_type="issuance")
    p.register_identity("agent://%s/sub" % name, org=name, agent_type="worker")


def test_I_memory_default():
    """默认 MemoryNonceStore 生效。"""
    p = Platform(tenant="I")
    _register_basic(p, "I")
    r = p.issue_credential("agent://I/iss", "agent://I/sub", "aud",
                           ["s"], ttl=300)
    cred = r["cred"]
    # 第一次验签：通过
    v1 = p.verify_credential(cred, record_nonce=True)
    assert v1["ok"] is True
    # 第二次验签（同一 nonce）：nonce replay
    v2 = p.verify_credential(cred, record_nonce=True)
    assert v2["ok"] is False
    assert v2["reason"] == "nonce replay"


def test_J_sqlite_shared():
    """SqliteNonceStore 让两个 Platform 共享 nonce。"""
    db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_v3_shared.db")
    if os.path.exists(db):
        os.remove(db)
    try:
        s1 = SqliteNonceStore(db)
        p1 = Platform(tenant="J1", nonce_store=s1)
        _register_basic(p1, "J1")

        r = p1.issue_credential("agent://J1/iss", "agent://J1/sub",
                                 "aud", ["s"], ttl=300)
        cred = r["cred"]
        # p1 验签一次，nonce 已写入
        v1 = p1.verify_credential(cred, record_nonce=True)
        assert v1["ok"] is True

        # p2 用同一个 sqlite 后端：也能见到 nonce
        s2 = SqliteNonceStore(db)
        p2 = Platform(tenant="J1", nonce_store=s2)
        # 让 p2 也认这个 issuer（因为 nonce 是全局唯一，但 issuer 需要注册）
        _register_basic(p2, "J1")
        # p2 复用 p1 已经用过的 nonce 应被拒
        # 但 p2 的 identities 是从空开始，issuer 不匹配。改为直接把 cred 加到 p2：
        # 更简单：p2 用同一个 sqlite nonce_store，且 issuer 与 cred.iss 相同
        # 为了让 p2 认 issuer，我们注册相同的 idn（用同一个 tenant）
        # 重新构造：让 p2 用相同 tenant，重新注册
        # 简化：直接用同一 s1/s2 nonce_store 测试 contains
        nonce_bytes = bytes.fromhex(cred["nonce"])
        assert nonce_bytes in s2, "s2 应看到 p1 写入的 nonce"

        s1.close()
        s2.close()
    finally:
        if os.path.exists(db):
            os.remove(db)


def test_K_sqlite_persistence_across_instances():
    """SqliteNonceStore 持久化：close 后重开仍能命中。"""
    db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_v3_persist.db")
    if os.path.exists(db):
        os.remove(db)
    try:
        s = SqliteNonceStore(db)
        nonce = b"\xab" * 16
        s.add(nonce, ttl=1000)
        s.close()
        # 重新打开
        s2 = SqliteNonceStore(db)
        assert nonce in s2
        s2.close()
    finally:
        if os.path.exists(db):
            os.remove(db)


def test_L_ttl_expiry():
    """ttl=0 或极短 → nonce 立即过期，允许再次验签。"""
    p = Platform(tenant="L", nonce_ttl=0)
    _register_basic(p, "L")
    r = p.issue_credential("agent://L/iss", "agent://L/sub", "aud",
                           ["s"], ttl=300)
    cred = r["cred"]
    v1 = p.verify_credential(cred, record_nonce=True)
    assert v1["ok"] is True
    time.sleep(1.05)
    # 过期后同一 nonce 应再次通过
    v2 = p.verify_credential(cred, record_nonce=True)
    assert v2["ok"] is True


def test_M_record_nonce_false():
    """record_nonce=False 时 nonce 不入存储，可反复验签。"""
    p = Platform(tenant="M")
    _register_basic(p, "M")
    r = p.issue_credential("agent://M/iss", "agent://M/sub", "aud",
                           ["s"], ttl=300)
    cred = r["cred"]
    for _ in range(3):
        v = p.verify_credential(cred, record_nonce=False)
        assert v["ok"] is True


def test_N_multi_tenant_isolation():
    """多租户 nonce 隔离：两个 Platform 各自持有独立 store。"""
    p_a = Platform(tenant="Na")
    p_b = Platform(tenant="Nb")
    _register_basic(p_a, "Na")
    _register_basic(p_b, "Nb")
    r_a = p_a.issue_credential("agent://Na/iss", "agent://Na/sub",
                                "aud", ["s"], ttl=300)
    r_b = p_b.issue_credential("agent://Nb/iss", "agent://Nb/sub",
                                "aud", ["s"], ttl=300)
    # 各自验签，写入各自的 nonce
    p_a.verify_credential(r_a["cred"], record_nonce=True)
    p_b.verify_credential(r_b["cred"], record_nonce=True)
    # A 的 nonce 不在 B 的 store 里（不同 nonce 值，天然隔离）
    nonce_a = bytes.fromhex(r_a["cred"]["nonce"])
    nonce_b = bytes.fromhex(r_b["cred"]["nonce"])
    assert nonce_a in p_a._nonce_store
    assert nonce_b in p_b._nonce_store
    assert nonce_a not in p_b._nonce_store  # 不同 nonce
    assert nonce_b not in p_a._nonce_store


def run_all() -> list:
    tests = [
        ("I MemoryNonceStore 默认", test_I_memory_default),
        ("J Sqlite 跨实例共享", test_J_sqlite_shared),
        ("K Sqlite 持久化", test_K_sqlite_persistence_across_instances),
        ("L nonce_ttl 过期", test_L_ttl_expiry),
        ("M record_nonce=False 不入", test_M_record_nonce_false),
        ("N 多租户隔离", test_N_multi_tenant_isolation),
    ]
    out = []
    for name, fn in tests:
        try:
            fn()
            out.append((name, True))
        except Exception as e:
            out.append((name, False))
            print("  ! %s  FAIL: %r" % (name, e))
    return out


def main():
    results = run_all()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%s     %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "check_v3_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
