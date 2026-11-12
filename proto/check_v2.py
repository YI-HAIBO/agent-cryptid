# -*- coding: utf-8 -*-
"""v2.1 累加器撤销集成测试。

覆盖：
  A  revoke 后同时更新 jti 黑名单与 Merkle 累加器
  B  revocation_snapshot 附带累加器根哈希
  C  verify_revocation 返回可独立验证的证明
  D  未撤销 jti 返回 revoked=False
  E  跨租户隔离：tenant A 撤销不影响 tenant B 的累加器
  F  与 jti 黑名单兼容（凭证校验仍走黑名单路径）
  G  证明可篡改检测（leaf/sibling/root 三处）
  H  撤销持久化后可恢复累加器状态（若后端支持，则至少快照字段一致）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform  # noqa: E402
from revocation import RevokeAccumulator  # noqa: E402


def _new_platform(tenant, pers=None):
    return Platform(tenant=tenant, persistence=pers)


def test_A_acc_sync():
    """revoke 后累加器与 jti 黑名单同步增长。"""
    p = _new_platform("A")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    jti = r["jti"]
    r2 = p.revoke(jti, reason="test")
    assert r2["ok"], "revoke failed"
    assert r2["version"] == 1
    assert "acc_version" in r2 and r2["acc_version"] == 1
    assert jti in p._revoked_jtis, "jti 黑名单未同步"
    assert p._acc.version == 1, "累加器 version 未同步"


def test_B_snapshot_has_root():
    """撤销快照附带累加器根。"""
    p = _new_platform("B")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    p.revoke(r["jti"])
    snap = p.revocation_snapshot()
    assert snap["ok"]
    assert snap["acc_version"] == 1
    assert snap["acc_current_root"] is not None
    assert isinstance(snap["acc_frozen_roots"], list)


def test_C_verify_revocation():
    """verify_revocation 返回的证明可独立验证。"""
    p = _new_platform("C")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    jti = r["jti"]
    p.revoke(jti)
    rr = p.verify_revocation(jti)
    assert rr["ok"] and rr["revoked"] is True
    proof = rr["proof"]
    # 用静态方法独立验证（不持有累加器实例）
    assert RevokeAccumulator.verify_proof(proof) is True
    assert rr["verify"] is True


def test_D_not_revoked():
    """未撤销 jti 返回 revoked=False。"""
    p = _new_platform("D")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    rr = p.verify_revocation(r["jti"])
    assert rr["ok"] and rr["revoked"] is False and rr["proof"] is None


def test_E_tenant_isolation():
    """跨租户撤销隔离：tenant A 撤销不影响 tenant B 的累加器。"""
    p_a = _new_platform("A")
    p_b = _new_platform("B")
    for p, name in ((p_a, "A"), (p_b, "B")):
        p.register_identity("agent://%s/iss" % name, org=name,
                            agent_type="issuance")
        p.register_identity("agent://%s/sub" % name, org=name,
                            agent_type="worker")
    r_a = p_a.issue_credential("agent://A/iss", "agent://A/sub",
                               "aud", ["s"], ttl=300)
    p_a.revoke(r_a["jti"])
    # tenant B 的累加器不受影响
    assert p_b._acc.version == 0
    assert p_b._acc.snapshot()["current_root"] is None
    snap_b = p_b.revocation_snapshot()
    assert snap_b["acc_version"] == 0
    assert snap_b["acc_current_root"] is None


def test_F_compat_with_verify():
    """凭证校验仍走 jti 黑名单，验证被撤销凭证失败。"""
    p = _new_platform("F")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    cred = r["cred"]
    # 撤销前：验证通过
    v1 = p.verify_credential(cred, record_nonce=False)
    assert v1["ok"] is True
    # 撤销
    p.revoke(cred["jti"])
    # 撤销后：验证失败
    v2 = p.verify_credential(cred, record_nonce=False)
    assert v2["ok"] is False
    assert v2["reason"] == "revoked"


def test_G_tamper_detection():
    """证明三处篡改均应被拒。"""
    p = _new_platform("G")
    p.register_identity("agent://iss", org="x", agent_type="issuance")
    p.register_identity("agent://sub", org="x", agent_type="worker")
    r = p.issue_credential("agent://iss", "agent://sub", "aud",
                           ["s"], ttl=300)
    jti = r["jti"]
    p.revoke(jti)
    proof = p._acc.proof(jti)

    # 篡改 leaf_hash
    bad = dict(proof)
    bad["leaf_hash"] = bytes(32).hex()
    assert not RevokeAccumulator.verify_proof(bad)

    # 篡改 sibling_path
    bad = dict(proof)
    path = list(proof["sibling_path"])
    path[0] = bytes(32).hex()
    bad["sibling_path"] = path
    assert not RevokeAccumulator.verify_proof(bad)

    # 篡改 root
    bad = dict(proof)
    bad["root"] = bytes(32).hex()
    assert not RevokeAccumulator.verify_proof(bad)

    # 篡改 jti（证明张冠李戴）
    bad = dict(proof)
    bad["jti"] = "some-other-jti"
    assert not RevokeAccumulator.verify_revocation(bad, jti)


def test_H_persistence_roundtrip():
    """撤销持久化后仍可拿到一致的快照元数据。"""
    from persistence import SQLiteBackend
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "_v2_persist_test.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    try:
        pers = SQLiteBackend(db_path)
        p = _new_platform("H", pers=pers)
        p.register_identity("agent://iss", org="x", agent_type="issuance")
        p.register_identity("agent://sub", org="x", agent_type="worker")
        r = p.issue_credential("agent://iss", "agent://sub", "aud",
                               ["s"], ttl=300)
        p.revoke(r["jti"], reason="persist test")
        snap = p.revocation_snapshot()
        assert snap["acc_version"] == 1
        assert snap["total_revoked"] == 1

        # 新 Platform 载入持久化：累加器是空的（v2.1 未持久化累加器本身），
        # 但快照能反映当前租户的 jti 撤销状态
        p2 = _new_platform("H", pers=pers)
        snap2 = p2.revocation_snapshot()
        assert snap2["total_revoked"] >= 1
        # v2.1.1：累加器按持久化顺序 replay 后应恢复状态
        assert snap2["acc_version"] == 1, \
            "累加器 replay 后 version 应为 1，实际 %s" % snap2["acc_version"]
        assert snap2["acc_current_root"] is not None, \
            "累加器 replay 后 root 应非空"
        assert snap2["ok"] is True
        p._pers.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_I_acc_recovery_full_chain():
    """多次撤销后重启，累加器根与每条证明都应可验证。"""
    from persistence import SQLiteBackend
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "_v2_acc_recover.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    try:
        pers = SQLiteBackend(db_path)
        p = _new_platform("I", pers=pers)
        p.register_identity("agent://I/iss", org="I", agent_type="issuance")
        p.register_identity("agent://I/sub", org="I", agent_type="worker")

        # 撤销 3 条凭证
        jtis = []
        for i in range(3):
            r = p.issue_credential("agent://I/iss", "agent://I/sub",
                                    "aud-%d" % i, ["s"], ttl=300)
            jtis.append(r["jti"])
            p.revoke(r["jti"], reason="batch-%d" % i)

        # 重启 Platform，用同一 SQLite 后端
        p.close() if hasattr(p, "close") else None
        pers.close() if hasattr(pers, "close") else None
        pers2 = SQLiteBackend(db_path)
        p2 = _new_platform("I", pers=pers2)

        # 累加器应恢复
        snap2 = p2.revocation_snapshot()
        assert snap2["acc_version"] == 3, \
            "累加器 version 应恢复为 3，实际 %s" % snap2["acc_version"]
        assert snap2["acc_current_root"] is not None

        # 每条撤销都能拿到可验证的证明
        for jti in jtis:
            proof = p2._acc.proof(jti)
            assert proof is not None, "jti %s 应能找到证明" % jti
            assert RevokeAccumulator.verify_proof(proof) is True
        pers2.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def run_all() -> list:
    tests = [
        ("A revoke 同步累加器", test_A_acc_sync),
        ("B 快照含累加器根", test_B_snapshot_has_root),
        ("C 证明可独立验证", test_C_verify_revocation),
        ("D 未撤销返回 False", test_D_not_revoked),
        ("E 跨租户隔离", test_E_tenant_isolation),
        ("F 凭证校验兼容", test_F_compat_with_verify),
        ("G 证明篡改检测", test_G_tamper_detection),
        ("H 持久化往返", test_H_persistence_roundtrip),
        ("I 累加器重启恢复", test_I_acc_recovery_full_chain),
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
                               "check_v2_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
