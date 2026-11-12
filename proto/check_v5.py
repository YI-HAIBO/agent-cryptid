# -*- coding: utf-8 -*-
"""v2.3 审计锚点持久化集成测试。

覆盖：
  V  锚点持久化：写入 pers 后重启仍能查到
  W  重启后 anchor_id 连续递增（不重复、不跳号）
  X  重启后 latest / list 语义正确
  Y  多租户锚点持久化隔离
  Z  重启后签名仍可验证

注意：Windows 下沙箱可能拦截 os.remove（safe-delete / PermissionError），
清理逻辑统一走 _new_db + _cleanup，失败静默不阻断测试判定。
"""
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform  # noqa: E402
from persistence import SQLiteBackend  # noqa: E402


def _register_basic(p, name="V"):
    p.register_identity("agent://%s/iss" % name, org=name, agent_type="issuance")
    p.register_identity("agent://%s/sub" % name, org=name, agent_type="worker")


def _new_db():
    """创建带唯一 UUID 的 sqlite 文件路径。"""
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "_v5_%s.db" % uuid.uuid4().hex[:12],
    )
    return path, SQLiteBackend(path)


def _cleanup(*pers_list):
    """先关所有连接，再尽力删除残留文件；异常静默。"""
    for pers in pers_list:
        if pers is not None:
            try:
                pers.close()
            except Exception:
                pass
    for pers in pers_list:
        try:
            path = getattr(pers, "path", None)
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def test_V_persist_and_reload():
    """锚点持久化：写入后重启 Platform，锚点仍能查到。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="V", persistence=pers)
        _register_basic(p, "V")
        p.issue_credential("agent://V/iss", "agent://V/sub", "aud",
                           ["s"], ttl=300)
        ar = p.anchor_audit("agent://V/iss", reason="persist test")
        assert ar["ok"] is True
        anchor_id = ar["anchor"]["anchor_id"]
        root_before = ar["anchor"]["root_hash"]
        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="V", persistence=pers2)
        lst = p2.list_audit_anchors()
        assert lst["total"] == 1
        assert lst["anchors"][0]["anchor_id"] == anchor_id
        assert lst["anchors"][0]["root_hash"] == root_before
    finally:
        _cleanup(pers2, pers)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def test_W_anchor_id_continuity():
    """重启后新增锚点的 anchor_id 连续递增。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="W", persistence=pers)
        _register_basic(p, "W")
        p.issue_credential("agent://W/iss", "agent://W/sub", "aud",
                           ["s"], ttl=300)
        a1 = p.anchor_audit("agent://W/iss")["anchor"]
        assert a1["anchor_id"] == 1

        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="W", persistence=pers2)
        p2.issue_credential("agent://W/iss", "agent://W/sub", "aud-2",
                            ["s"], ttl=300)
        a2 = p2.anchor_audit("agent://W/iss")["anchor"]
        assert a2["anchor_id"] == 2
        lst = p2.list_audit_anchors()
        ids = [a["anchor_id"] for a in lst["anchors"]]
        assert ids == [2, 1]
    finally:
        _cleanup(pers2, pers)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def test_X_latest_after_reload():
    """重启后 latest_audit_anchor 仍返回最新锚点。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="X", persistence=pers)
        _register_basic(p, "X")
        for i in range(3):
            p.issue_credential("agent://X/iss", "agent://X/sub",
                               "aud-%d" % i, ["s"], ttl=300)
            p.anchor_audit("agent://X/iss")
            if i < 2:
                time.sleep(0.01)
        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="X", persistence=pers2)
        latest = p2.latest_audit_anchor()["anchor"]
        assert latest is not None
        assert latest["anchor_id"] == 3
    finally:
        _cleanup(pers2, pers)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def test_Y_tenant_isolation_persisted():
    """多租户锚点持久化隔离。"""
    path, pers = _new_db()
    pers2 = None
    try:
        pa = Platform(tenant="Ya", persistence=pers)
        pb = Platform(tenant="Yb", persistence=pers)
        _register_basic(pa, "Ya")
        _register_basic(pb, "Yb")
        pa.issue_credential("agent://Ya/iss", "agent://Ya/sub",
                            "aud", ["s"], ttl=300)
        pb.issue_credential("agent://Yb/iss", "agent://Yb/sub",
                            "aud", ["s"], ttl=300)
        pa.anchor_audit("agent://Ya/iss")
        pb.anchor_audit("agent://Yb/iss")
        pers.close()
        pers2 = SQLiteBackend(path)
        pa2 = Platform(tenant="Ya", persistence=pers2)
        pb2 = Platform(tenant="Yb", persistence=pers2)
        lst_a = pa2.list_audit_anchors()
        lst_b = pb2.list_audit_anchors()
        assert lst_a["total"] == 1
        assert lst_b["total"] == 1
        assert lst_a["anchors"][0]["issuer_idn"] == "agent://Ya/iss"
        assert lst_b["anchors"][0]["issuer_idn"] == "agent://Yb/iss"
        assert lst_a["anchors"][0]["anchor_id"] == 1
        assert lst_b["anchors"][0]["anchor_id"] == 1
    finally:
        _cleanup(pers2, pers)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def test_Z_anchor_still_verifiable_after_reload():
    """重启后锚点签名仍可验证。"""
    path, pers = _new_db()
    pers2 = None
    try:
        p = Platform(tenant="Z", persistence=pers)
        _register_basic(p, "Z")
        p.issue_credential("agent://Z/iss", "agent://Z/sub", "aud",
                           ["s"], ttl=300)
        ar = p.anchor_audit("agent://Z/iss")["anchor"]
        assert ar["anchor_id"] is not None
        pers.close()
        pers2 = SQLiteBackend(path)
        p2 = Platform(tenant="Z", persistence=pers2)
        lst = p2.list_audit_anchors()
        r = p2.verify_audit_anchor(lst["anchors"][0])
        assert r["ok"] is True
        assert r["verify_reason"] == "ok"
    finally:
        _cleanup(pers2, pers)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def run_all() -> list:
    tests = [
        ("V 持久化+重启恢复", test_V_persist_and_reload),
        ("W anchor_id 连续", test_W_anchor_id_continuity),
        ("X latest 重启后正确", test_X_latest_after_reload),
        ("Y 多租户持久化隔离", test_Y_tenant_isolation_persisted),
        ("Z 重启后签名可验证", test_Z_anchor_still_verifiable_after_reload),
    ]
    out = []
    for name, fn in tests:
        try:
            fn()
            out.append((name, True))
        except Exception as e:
            out.append((name, False))
            import traceback
            traceback.print_exc()
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
                               "check_v5_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
