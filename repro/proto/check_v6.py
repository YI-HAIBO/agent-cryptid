# -*- coding: utf-8 -*-
"""v2.4 撤销累加器状态持久化集成测试。

覆盖：
  AA 重启后累加器从 revocation_state 直接恢复（root 一致、proof 可验证）
  AB 重启后 jti 索引完整（verify_revocation 仍返回 True）
  AC 多租户累加器状态隔离（各自 root 独立）
  AD 状态表被清空时退化为 replay 重建，结果等价
  AE 冻结树场景下状态可恢复（frozen_roots 保留）

注意：Windows 下沙箱可能拦截 os.remove，清理统一 try/except 静默。
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform  # noqa: E402
from persistence import SQLiteBackend  # noqa: E402


def _register_basic(p, name):
    p.register_identity("agent://%s/iss" % name, org=name,
                        agent_type="issuance")
    p.register_identity("agent://%s/sub" % name, org=name,
                        agent_type="worker")


def _new_db():
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "_v6_%s.db" % uuid.uuid4().hex[:12],
    )
    return path, SQLiteBackend(path)


def _cleanup(path, *pers_list):
    for pers in pers_list:
        if pers is not None:
            try:
                pers.close()
            except Exception:
                pass
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def test_AA_state_restore():
    """重启后累加器从 revocation_state 直接恢复。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="AA", persistence=pers)
        _register_basic(p, "AA")
        jtis = []
        for i in range(3):
            r = p.issue_credential("agent://AA/iss", "agent://AA/sub",
                                   "aud-%d" % i, ["s"], ttl=300)
            jtis.append(r["jti"])
            p.revoke(r["jti"])
        root_before = p._acc.snapshot()["current_root"]
        ver_before = p._acc.snapshot()["version"]
        # 确认状态确实写进了 SQLite
        assert pers.get_revocation_state("AA") is not None

        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="AA", persistence=pers2)
        snap2 = p2._acc.snapshot()
        assert snap2["version"] == ver_before
        assert snap2["current_root"] == root_before
        for j in jtis:
            assert p2.verify_revocation(j)["ok"] is True
    finally:
        _cleanup(path, pers2, pers)


def test_AB_jti_index_restored():
    """重启后 jti 索引完整（否则 proof 返回 None）。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="AB", persistence=pers)
        _register_basic(p, "AB")
        jtis = []
        for i in range(4):
            r = p.issue_credential("agent://AB/iss", "agent://AB/sub",
                                   "aud-%d" % i, ["s"], ttl=300)
            jtis.append(r["jti"])
            p.revoke(r["jti"])
        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="AB", persistence=pers2)
        # 每个 jti 都能拿到证明且验证通过
        for j in jtis:
            r = p2.verify_revocation(j)
            assert r["ok"] is True and r["revoked"] is True, \
                "jti %s 证明不可用" % j[:12]
        # 未撤销的 jti 不返回证明（ok 表示 API 成功，revoked 表示是否撤销）
        r_other = p.issue_credential("agent://AB/iss", "agent://AB/sub",
                                     "aud-other", ["s"], ttl=300)
        assert p2.verify_revocation(r_other["jti"])["revoked"] is False
    finally:
        _cleanup(path, pers2, pers)


def test_AC_tenant_isolation():
    """多租户累加器状态隔离。"""
    path, pers = _new_db()
    pers2 = None
    try:
        pa = Platform(tenant="ACa", persistence=pers)
        pb = Platform(tenant="ACb", persistence=pers)
        _register_basic(pa, "ACa")
        _register_basic(pb, "ACb")
        ra = pa.issue_credential("agent://ACa/iss", "agent://ACa/sub",
                                 "aud", ["s"], ttl=300)
        pa.revoke(ra["jti"])
        rb = pb.issue_credential("agent://ACb/iss", "agent://ACb/sub",
                                 "aud", ["s"], ttl=300)
        rb2 = pb.issue_credential("agent://ACb/iss", "agent://ACb/sub",
                                  "aud-2", ["s"], ttl=300)
        pb.revoke(rb["jti"])
        pb.revoke(rb2["jti"])
        ver_a = pa._acc.snapshot()["version"]
        ver_b = pb._acc.snapshot()["version"]
        assert ver_a == 1 and ver_b == 2

        pers.close()
        pers2 = SQLiteBackend(path)
        pa2 = Platform(tenant="ACa", persistence=pers2)
        pb2 = Platform(tenant="ACb", persistence=pers2)
        assert pa2._acc.snapshot()["version"] == 1
        assert pb2._acc.snapshot()["version"] == 2
        # 租户 A 只见自己的撤销（revoked 字段才是"是否已撤销"）
        assert pa2.verify_revocation(ra["jti"])["revoked"] is True
        assert pa2.verify_revocation(rb["jti"])["revoked"] is False
        assert pb2.verify_revocation(rb["jti"])["revoked"] is True
        assert pb2.verify_revocation(ra["jti"])["revoked"] is False
    finally:
        _cleanup(path, pers2, pers)


def test_AD_fallback_to_replay():
    """状态表被删时退化为 replay 重建，结果与直接恢复等价。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="AD", persistence=pers)
        _register_basic(p, "AD")
        for i in range(3):
            r = p.issue_credential("agent://AD/iss", "agent://AD/sub",
                                   "aud-%d" % i, ["s"], ttl=300)
            p.revoke(r["jti"])
        root_before = p._acc.snapshot()["current_root"]
        ver_before = p._acc.snapshot()["version"]
        # 手工清掉状态表，模拟"首次升级到 v2.4"的老库
        import sqlite3
        c = sqlite3.connect(path)
        c.execute("DELETE FROM revocation_state WHERE tenant_id='AD'")
        c.commit()
        c.close()
        assert pers.get_revocation_state("AD") is None

        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="AD", persistence=pers2)
        snap2 = p2._acc.snapshot()
        # replay 重建后根与版本必须一致
        assert snap2["version"] == ver_before
        assert snap2["current_root"] == root_before
        # 重建后应顺手补写状态表
        assert pers2.get_revocation_state("AD") is not None
    finally:
        _cleanup(path, pers2, pers)


def test_AE_frozen_roots_restored():
    """冻结树场景下状态可恢复（frozen_roots 保留）。"""
    path, pers = _new_db()
    pers2 = None
    try:
        # 用小容量累加器触发冻结（capacity=8，第 9 次撤销冻结）
        p = Platform(tenant="AE", persistence=pers, acc_capacity=8)
        _register_basic(p, "AE")
        for i in range(9):  # 第 9 次触发冻结
            r = p.issue_credential("agent://AE/iss", "agent://AE/sub",
                                   "aud-%d" % i, ["s"], ttl=300)
            p.revoke(r["jti"])
        snap_before = p._acc.snapshot()
        assert len(snap_before["frozen_roots"]) == 1
        state_ver = pers.get_revocation_state("AE")["version"]

        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="AE", persistence=pers2, acc_capacity=8)
        snap2 = p2._acc.snapshot()
        assert snap2["version"] == snap_before["version"]
        assert len(snap2["frozen_roots"]) == 1
        assert snap2["frozen_roots"] == snap_before["frozen_roots"]
        assert snap2["current_root"] == snap_before["current_root"]
        assert pers2.get_revocation_state("AE")["version"] == state_ver
    finally:
        _cleanup(path, pers2, pers)


def run_all() -> list:
    tests = [
        ("AA 状态直接恢复", test_AA_state_restore),
        ("AB jti 索引完整", test_AB_jti_index_restored),
        ("AC 多租户状态隔离", test_AC_tenant_isolation),
        ("AD 退化 replay 等价", test_AD_fallback_to_replay),
        ("AE 冻结树状态恢复", test_AE_frozen_roots_restored),
    ]
    out = []
    for name, fn in tests:
        try:
            fn()
            out.append((name, True))
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("  ! %s  FAIL: %r" % (name, e))
            out.append((name, False))
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
                               "check_v6_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
