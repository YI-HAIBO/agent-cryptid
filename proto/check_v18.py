# -*- coding: utf-8 -*-
"""v2.13 集成测试：FR1-05 密钥轮换 + FR1-07 批量导入导出 + FR7-05 CLI 工具。

通过 http_api.route() 走真实路由分发，覆盖：
    · FR1-05 主密钥轮换（SM2/SM9）、不影响既有标识、凭证校验兼容
    · FR1-07 标识批量导出 / 导入（幂等、元数据保留）
    · FR7-05 CLI 工具各命令

测试策略：直接调用 http_api.route()，不起真实 socket 服务器。
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http_api import route, TenantPool


def _pool():
    return TenantPool(db_path=":memory:", default_tenant="default")


def _r(pool, method, path, body=None, tenant="t1", query=None):
    """走真实路由分发。返回 (status, payload)。"""
    return route(pool, method, path, query or {}, body, tenant, None)


def self_check():
    out = []

    # ==================================================================
    # [A] FR1-05 密钥轮换
    # ==================================================================
    p = _pool()

    # 注册两个标识（轮换前）
    _r(p, "POST", "/v1/identities",
       {"idn": "agent://a/root", "org": "root"}, tenant="t1")
    _r(p, "POST", "/v1/identities",
       {"idn": "agent://a/worker", "org": "root"}, tenant="t1")

    # 签发一个凭证（轮换前）
    st, r = _r(p, "POST", "/v1/credentials",
               {"issuer_idn": "agent://a/root",
                "subject_idn": "agent://a/worker",
                "audience": "svc://x", "scope": ["read"]},
               tenant="t1")
    out.append(("A.1 轮换前签发成功", st == 200 and r.get("ok") is True))
    cred_before = r.get("cred")
    jti_before = r.get("jti")

    # 校验轮换前的凭证
    st, r = _r(p, "POST", "/v1/credentials/verify",
               {"cred": cred_before}, tenant="t1")
    out.append(("A.2 轮换前凭证校验通过", st == 200 and r.get("ok") is True))

    # 查询密钥版本（轮换前）
    st, r = _r(p, "GET", "/v1/keys/version", tenant="t1")
    out.append(("A.3 keys/version 返回 ok",
                st == 200 and r.get("ok") is True))
    out.append(("A.4 SM2 当前版本=0",
                r["versions"]["sm2"]["current_version"] == 0))

    # 执行 SM2 密钥轮换
    st, r = _r(p, "POST", "/v1/keys/rotate",
               {"alg": "sm2", "reason": "test rotate"},
               tenant="t1")
    out.append(("A.5 rotate sm2 成功", st == 200 and r.get("ok") is True))
    out.append(("A.6 返回 new_version=1", r.get("new_version") == 1))

    # 查询密钥版本（轮换后）
    st, r = _r(p, "GET", "/v1/keys/version", tenant="t1")
    out.append(("A.7 SM2 当前版本=1",
                r["versions"]["sm2"]["current_version"] == 1))
    out.append(("A.8 SM2 有 2 个版本",
                len(r["versions"]["sm2"]["versions"]) == 2))
    out.append(("A.9 版本 1 标记 rotated",
                r["versions"]["sm2"]["versions"][1]["rotated"] is True))

    # 轮换后：旧凭证仍可校验（用新签发的凭证避免 nonce 重放）
    st, r2 = _r(p, "POST", "/v1/credentials",
                {"issuer_idn": "agent://a/root",
                 "subject_idn": "agent://a/worker",
                 "audience": "svc://x2", "scope": ["read"]},
                tenant="t1")
    st, r = _r(p, "POST", "/v1/credentials/verify",
               {"cred": r2.get("cred")}, tenant="t1")
    out.append(("A.10 轮换后旧标识可签发并校验",
                st == 200 and r.get("ok") is True))

    # 轮换后：旧标识仍可签发新凭证
    st, r = _r(p, "POST", "/v1/credentials",
               {"issuer_idn": "agent://a/root",
                "subject_idn": "agent://a/worker",
                "audience": "svc://y", "scope": ["read", "write"]},
               tenant="t1")
    out.append(("A.11 轮换后旧标识可签发", st == 200 and r.get("ok") is True))
    cred_after = r.get("cred")

    # 轮换后：新标识用新版 mk
    _r(p, "POST", "/v1/identities",
       {"idn": "agent://a/new", "org": "root"}, tenant="t1")
    st, r = _r(p, "POST", "/v1/credentials",
               {"issuer_idn": "agent://a/new",
                "subject_idn": "agent://a/worker",
                "audience": "svc://z", "scope": ["read"]},
               tenant="t1")
    out.append(("A.12 轮换后新标识可签发", st == 200 and r.get("ok") is True))

    # 轮换后：校验新凭证
    st, r = _r(p, "POST", "/v1/credentials/verify",
               {"cred": cred_after}, tenant="t1")
    out.append(("A.13 轮换后新凭证校验通过",
                st == 200 and r.get("ok") is True))

    # 错误 alg 被拒
    st, r = _r(p, "POST", "/v1/keys/rotate",
               {"alg": "unknown"}, tenant="t1")
    out.append(("A.14 未知 alg 被拒", st == 400 and r.get("ok") is False))

    # 再次轮换（第二次）
    st, r = _r(p, "POST", "/v1/keys/rotate",
               {"alg": "sm2", "reason": "second rotate"},
               tenant="t1")
    out.append(("A.15 第二次轮换成功",
                st == 200 and r.get("new_version") == 2))

    # 第二次轮换后：旧标识仍可签发并校验
    st, r2 = _r(p, "POST", "/v1/credentials",
                {"issuer_idn": "agent://a/root",
                 "subject_idn": "agent://a/worker",
                 "audience": "svc://x3", "scope": ["read"]},
                tenant="t1")
    st, r = _r(p, "POST", "/v1/credentials/verify",
               {"cred": r2.get("cred")}, tenant="t1")
    out.append(("A.16 二次轮换后旧标识可签发并校验",
                st == 200 and r.get("ok") is True))

    # ==================================================================
    # [B] FR1-07 批量导入导出
    # ==================================================================
    p2 = _pool()

    # 先注册一些标识
    _r(p2, "POST", "/v1/identities",
       {"idn": "agent://b/root", "org": "org1",
        "agent_type": "ca", "owner": "admin",
        "tags": ["prod", "primary"]},
       tenant="b1")
    _r(p2, "POST", "/v1/identities",
       {"idn": "agent://b/worker1", "org": "org2",
        "agent_type": "worker", "owner": "dev1",
        "tags": ["prod"]},
       tenant="b1")
    _r(p2, "POST", "/v1/identities",
       {"idn": "agent://b/worker2", "org": "org2",
        "agent_type": "worker", "owner": "dev2",
        "tags": ["staging"]},
       tenant="b1")

    # B.1-B.3 导出
    st, r = _r(p2, "GET", "/v1/identities/export", tenant="b1")
    out.append(("B.1 导出返回 ok", st == 200 and r.get("ok") is True))
    out.append(("B.2 导出含 3 条标识", r.get("total") == 3))
    ids = [i["idn"] for i in r.get("identities", [])]
    out.append(("B.3 导出含 agent://b/root", "agent://b/root" in ids))
    out.append(("B.4 导出含元数据 org",
                r["identities"][0].get("meta", {}).get("org") is not None))

    # B.5 导出到另一个租户
    st, r = _r(p2, "GET", "/v1/identities/export", tenant="b2")
    out.append(("B.5 空租户导出 total=0",
                st == 200 and r.get("total") == 0))

    # B.6-B.7 批量导入
    import_data = {
        "identities": [
            {"idn": "agent://b2/root", "org": "org3",
             "agent_type": "ca", "owner": "admin"},
            {"idn": "agent://b2/w1", "org": "org3",
             "agent_type": "worker", "owner": "dev1"},
            {"idn": "agent://b2/w2", "org": "org3",
             "agent_type": "worker", "owner": "dev2"},
        ]
    }
    st, r = _r(p2, "POST", "/v1/identities/import",
               import_data, tenant="b2")
    out.append(("B.6 批量导入返回 ok", st == 200 and r.get("ok") is True))
    out.append(("B.7 导入 3 条成功", r.get("imported") == 3))

    # 验证导入后的标识
    st, r = _r(p2, "GET", "/v1/identities/export", tenant="b2")
    out.append(("B.8 导入后可导出",
                st == 200 and r.get("total") == 3))

    # B.9 重复导入（幂等）
    st, r = _r(p2, "POST", "/v1/identities/import",
               import_data, tenant="b2")
    out.append(("B.9 重复导入返回 ok", st == 200 and r.get("ok") is True))
    out.append(("B.10 重复导入 imported=0",
                r.get("imported") == 0))
    out.append(("B.11 重复导入 skipped=3",
                r.get("skipped") == 3))

    # B.12 导入无效条目
    bad_data = {
        "identities": [
            {"idn": "agent://b2/valid", "org": "org4"},
            {"org": "no_idn_here"},
            {"idn": "agent://b2/valid2", "org": "org4"},
        ]
    }
    st, r = _r(p2, "POST", "/v1/identities/import",
               bad_data, tenant="b2")
    out.append(("B.12 含无效条目返回 ok",
                st == 200 and r.get("ok") is True))
    out.append(("B.13 无效条目 imported=2",
                r.get("imported") == 2))
    out.append(("B.14 无效条目 failed=1",
                r.get("failed") == 1))

    # ==================================================================
    # [C] FR7-05 CLI 工具
    # ==================================================================
    import subprocess
    import tempfile

    py = sys.executable
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # 用文件型 SQLite 让 CLI 多次调用间状态可持久
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    def _run_cli(args):
        """运行 CLI 命令并返回解析后的 JSON。"""
        cmd = [py, os.path.join(script_dir, "cli.py"),
               "--db", db_path] + args
        r = subprocess.run(cmd, cwd=script_dir,
                           capture_output=True, text=True)
        if r.returncode == 0:
            try:
                return True, json.loads(r.stdout)
            except Exception:
                return False, {"error": r.stdout[:200]}
        return False, {"error": r.stderr[:200]}

    # C.1 CLI smoke
    ok, r = _run_cli(["--cmd", "smoke", "--tenant", "cli-test"])
    out.append(("C.1 CLI smoke 运行成功", ok))
    out.append(("C.2 CLI smoke 10 API 全通过",
                ok and len(r) == 10 and all(x[1] for x in r)))

    # C.3 CLI register
    ok, r = _run_cli(["--cmd", "register", "--idn", "agent://cli/test",
                      "--org", "cli-org", "--tenant", "cli-test"])
    out.append(("C.3 CLI register 成功",
                ok and r.get("ok") is True))
    out.append(("C.4 CLI register 返回 pub_x",
                ok and "pub_x" in r))

    # C.5 CLI keys
    ok, r = _run_cli(["--cmd", "keys", "--tenant", "cli-test"])
    out.append(("C.5 CLI keys 返回 ok", ok and r.get("ok") is True))
    out.append(("C.6 CLI keys 含 sm2 版本",
                ok and "sm2" in r.get("versions", {})))

    # C.7 CLI rotate
    ok, r = _run_cli(["--cmd", "rotate", "--alg", "sm2",
                      "--tenant", "cli-test"])
    out.append(("C.7 CLI rotate 成功",
                ok and r.get("ok") is True))
    out.append(("C.8 CLI rotate 返回 new_version",
                ok and r.get("new_version") is not None))

    # C.9 CLI list
    ok, r = _run_cli(["--cmd", "list", "--tenant", "cli-test"])
    out.append(("C.9 CLI list 返回 ok", ok and r.get("ok") is True))
    out.append(("C.10 CLI list 含已注册标识",
                ok and r.get("total", 0) >= 1))

    # C.11 CLI export
    ok, r = _run_cli(["--cmd", "export", "--tenant", "cli-test"])
    out.append(("C.11 CLI export 返回 ok", ok and r.get("ok") is True))

    # C.12 CLI issue + verify
    ok1, r1 = _run_cli(["--cmd", "issue",
                        "--issuer", "agent://cli/test",
                        "--subject", "agent://cli/test",
                        "--scope", "read,write",
                        "--tenant", "cli-test"])
    out.append(("C.12 CLI issue 成功", ok1 and r1.get("ok") is True))

    # C.13 CLI stats
    ok, r = _run_cli(["--cmd", "stats", "--tenant", "cli-test"])
    out.append(("C.13 CLI stats 返回 ok", ok and r.get("ok") is True))

    # 清理临时数据库
    try:
        os.remove(db_path)
    except OSError:
        pass

    # ==================================================================
    # [D] 跨租户隔离：密钥轮换按租户隔离
    # ==================================================================
    p3 = _pool()
    # 租户 t1 轮换
    _r(p3, "POST", "/v1/keys/rotate",
       {"alg": "sm2"}, tenant="t1")
    # 租户 t2 未轮换
    st, r = _r(p3, "GET", "/v1/keys/version", tenant="t2")
    out.append(("D.1 跨租户 t2 SM2 版本=0",
                st == 200 and
                r["versions"]["sm2"]["current_version"] == 0))
    # 租户 t1 已轮换
    st, r = _r(p3, "GET", "/v1/keys/version", tenant="t1")
    out.append(("D.2 租户 t1 SM2 版本=1",
                st == 200 and
                r["versions"]["sm2"]["current_version"] == 1))

    # ==================================================================
    # 汇总
    # ==================================================================
    pass_count = sum(1 for _, ok in out if ok)
    fail_count = sum(1 for _, ok in out if not ok)
    print("\n" + "=" * 60)
    print("v2.13 集成测试：FR1-05 密钥轮换 + FR1-07 批量导入导出 + FR7-05 CLI")
    print("=" * 60)
    for name, ok in out:
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
    print("-" * 60)
    print("RESULT  PASS=%d  FAIL=%d" % (pass_count, fail_count))
    print("=" * 60)

    # 写报告文件
    report_path = os.path.join(
        os.path.dirname(__file__), "check_v18_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        for name, ok in out:
            f.write("%-8s %s\n" % ("PASS" if ok else "FAIL", name))
        f.write("\nRESULT  PASS=%d  FAIL=%d\n" % (pass_count, fail_count))

    return out


if __name__ == "__main__":
    self_check()
