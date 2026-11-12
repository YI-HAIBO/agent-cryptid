# -*- coding: utf-8 -*-
"""v2.2 审计锚点集成测试。

覆盖：
  O  anchor_audit 生成签名锚点，签名自洽
  P  多次锚点：链增长 + 时间递增
  Q  离线验证：篡改 ts / chain_len / root_hash 均失败
  R  锚点验证：issuer 未知时正确报错
  S  多租户锚点隔离
  T  未签名锚点验证失败
  U  list_audit_anchors / latest_audit_anchor 语义正确
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform  # noqa: E402
from audit_anchor import AuditAnchor  # noqa: E402


def _register_basic(p, name="O"):
    p.register_identity("agent://%s/iss" % name, org=name, agent_type="issuance")
    p.register_identity("agent://%s/sub" % name, org=name, agent_type="worker")


def test_O_anchor_create():
    """anchor_audit 生成签名锚点，签名自洽。"""
    p = Platform(tenant="O")
    _register_basic(p, "O")
    # 先做几次操作让审计链非空
    r = p.issue_credential("agent://O/iss", "agent://O/sub", "aud",
                           ["s"], ttl=300)
    r2 = p.revoke(r["jti"])
    # 生成锚点
    ar = p.anchor_audit("agent://O/iss", reason="test anchor")
    assert ar["ok"] is True
    assert ar["anchor"]["sig_r"] is not None
    assert ar["anchor"]["sig_s"] is not None
    assert ar["verify_reason"] == "ok"
    # 锚点内容与实际审计链一致
    assert ar["anchor"]["chain_len"] == p.audit.count()
    assert ar["anchor"]["root_hash"] == p.audit.root_hash


def test_P_multiple_anchors():
    """多次锚点：链增长 + 时间递增 + id 递增。"""
    p = Platform(tenant="P")
    _register_basic(p, "P")
    a1 = p.anchor_audit("agent://P/iss")["anchor"]
    time.sleep(1.01)
    # 增加一条审计事件让链增长
    p.issue_credential("agent://P/iss", "agent://P/sub", "aud",
                       ["s"], ttl=300)
    a2 = p.anchor_audit("agent://P/iss")["anchor"]
    assert a1["chain_len"] < a2["chain_len"]
    assert a1["ts"] < a2["ts"]
    assert a1["anchor_id"] < a2["anchor_id"]


def test_Q_tamper_detection():
    """篡改锚点三个字段任一 → 验证失败。"""
    p = Platform(tenant="Q")
    _register_basic(p, "Q")
    p.issue_credential("agent://Q/iss", "agent://Q/sub", "aud",
                       ["s"], ttl=300)
    ar = p.anchor_audit("agent://Q/iss")
    a = ar["anchor"]

    # 篡改 ts
    bad = dict(a)
    bad["ts"] = a["ts"] + 1
    r = p.verify_audit_anchor(bad)
    assert r["ok"] is False

    # 篡改 chain_len
    bad = dict(a)
    bad["chain_len"] = a["chain_len"] + 1
    r = p.verify_audit_anchor(bad)
    assert r["ok"] is False

    # 篡改 root_hash
    bad = dict(a)
    bad["root_hash"] = "ff" * 32
    r = p.verify_audit_anchor(bad)
    assert r["ok"] is False


def test_R_unknown_issuer():
    """未知 issuer 无法生成锚点，也无法验证。"""
    p = Platform(tenant="R")
    # 未注册任何标识
    r = p.anchor_audit("agent://nonexistent")
    assert r["ok"] is False
    assert r["reason"] == "unknown issuer"

    # 验证不存在的 issuer 的锚点
    fake_anchor = {
        "ts": 1000, "chain_len": 5, "root_hash": "ab" * 32,
        "issuer_idn": "agent://fake/ia",
        "sig_r": 123, "sig_s": 456,
    }
    r = p.verify_audit_anchor(fake_anchor)
    assert r["ok"] is False
    assert r["reason"] == "unknown issuer"


def test_S_tenant_isolation():
    """多租户锚点隔离：不同租户的锚点各自独立。"""
    p_a = Platform(tenant="Sa")
    p_b = Platform(tenant="Sb")
    _register_basic(p_a, "Sa")
    _register_basic(p_b, "Sb")
    p_a.issue_credential("agent://Sa/iss", "agent://Sa/sub",
                         "aud", ["s"], ttl=300)
    p_b.issue_credential("agent://Sb/iss", "agent://Sb/sub",
                         "aud", ["s"], ttl=300)
    ar_a = p_a.anchor_audit("agent://Sa/iss")["anchor"]
    ar_b = p_b.anchor_audit("agent://Sb/iss")["anchor"]
    # 各自只能看到自己的锚点
    lst_a = p_a.list_audit_anchors()
    lst_b = p_b.list_audit_anchors()
    assert len(lst_a["anchors"]) == 1
    assert len(lst_b["anchors"]) == 1
    assert lst_a["anchors"][0]["issuer_idn"] == "agent://Sa/iss"
    assert lst_b["anchors"][0]["issuer_idn"] == "agent://Sb/iss"


def test_T_unsigned_anchor():
    """未签名锚点验证失败。"""
    p = Platform(tenant="T")
    _register_basic(p, "T")
    p.issue_credential("agent://T/iss", "agent://T/sub", "aud",
                       ["s"], ttl=300)
    # 手工构造一个未签名锚点（用当前审计链根）
    unsigned = {
        "ts": int(time.time()), "chain_len": p.audit.count(),
        "root_hash": p.audit.root_hash,
        "issuer_idn": "agent://T/iss",
        "sig_r": None, "sig_s": None,
    }
    r = p.verify_audit_anchor(unsigned)
    assert r["ok"] is False
    assert r["verify_reason"] == "no signature"


def test_U_list_and_latest():
    """list_audit_anchors 和 latest_audit_anchor 语义。"""
    p = Platform(tenant="U")
    _register_basic(p, "U")
    # 空时 latest 返回 None
    r = p.latest_audit_anchor()
    assert r["ok"] is True and r["anchor"] is None

    # 生成 3 个锚点
    for i in range(3):
        p.issue_credential("agent://U/iss", "agent://U/sub",
                           "aud-%d" % i, ["s"], ttl=300)
        p.anchor_audit("agent://U/iss")
        if i < 2:
            time.sleep(0.01)

    # latest 是最新
    latest = p.latest_audit_anchor()["anchor"]
    assert latest is not None
    assert latest["anchor_id"] == 3

    # list 默认倒序
    lst = p.list_audit_anchors()
    assert lst["total"] == 3
    assert lst["anchors"][0]["anchor_id"] == 3
    assert lst["anchors"][-1]["anchor_id"] == 1

    # list 按 limit 截断
    lst = p.list_audit_anchors(limit=2)
    assert lst["total"] == 2


def run_all() -> list:
    tests = [
        ("O anchor 创建自洽", test_O_anchor_create),
        ("P 多次锚点递增", test_P_multiple_anchors),
        ("Q 篡改检测", test_Q_tamper_detection),
        ("R 未知 issuer 拒绝", test_R_unknown_issuer),
        ("S 多租户隔离", test_S_tenant_isolation),
        ("T 未签名验证失败", test_T_unsigned_anchor),
        ("U list/latest 语义", test_U_list_and_latest),
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
                               "check_v4_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
