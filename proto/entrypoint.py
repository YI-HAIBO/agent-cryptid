# -*- coding: utf-8 -*-
"""入口脚本：加载配置 → 跑演示 → 打印结果。

用法：
    python entrypoint.py                       # 跑端到端 demo
    python entrypoint.py --config config.json  # 用指定配置
    python entrypoint.py --smoke               # 跑 10 API 烟测
    python entrypoint.py --check               # 跑完整验证（sm2 + v0.1）
"""
import argparse
import importlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_demo(cfg=None):
    import demo
    demo.main()


def run_smoke():
    from agent_platform import self_check as smoke
    ok = 0
    for name, passed in smoke():
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            ok += 1
    print("SUMMARY  smoke PASS=%d / %d" % (ok, len(smoke())))
    return ok


def _parse_result(text):
    """从文本中提取最后一个 RESULT 行的 PASS/FAIL 计数。"""
    import re
    mm = None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"RESULT\s+PASS=(\d+)\s+FAIL=(\d+)", line)
        if m:
            mm = m
    if mm:
        return int(mm.group(1)), int(mm.group(2))
    return None


def _count_from_file(f, base_pass, base_fail):
    """从 report 文件读取第一个 RESULT 行。
    返回 (found: bool, new_pass, new_fail)。
    """
    import re
    for line in f:
        line = line.strip()
        if line.startswith("RESULT"):
            print(line)
            m = re.match(r"RESULT\s+PASS=(\d+)\s+FAIL=(\d+)", line)
            if m:
                return True, base_pass + int(m.group(1)), base_fail + int(m.group(2))
            return True, base_pass, base_fail
    return False, base_pass, base_fail


def run_full_check():
    """跑全部验证模块，返回总 PASS/FAIL 计数。"""
    import io
    import contextlib
    total_pass = 0
    total_fail = 0
    modules = [
        "check_sm2", "check_v01", "check_v1", "sm2_fast",
        "revocation", "check_v2", "nonce_store", "check_v3", "asgi_app",
        "audit_anchor", "check_v4", "check_v5", "check_v6", "auth",
        "sm9", "check_v7", "check_v8", "check_v9", "check_v10",
        "check_v11", "check_v12", "check_v13", "check_v14",
        "check_v15", "check_v16", "check_v17", "check_v18", "check_v19",
        "check_v20",
        # v2.16 抗量子档位：KECCAK/SHA3/SHAKE 地基 + ML-DSA + SLH-DSA + 专项
        "shake", "mldsa", "slhdsa", "credential", "check_v21",
        # v3.0 future-work 落实：跨域撤销联邦 / 硬件根接入闭合 / 链式锚定 / 国密符合性
        "secure_key", "federation", "chain_ledger", "gm_compliance",
    ]
    for mod in modules:
        print("\n=== %s ===" % mod)
        try:
            m = importlib.import_module(mod)
            # 用 StringIO 捕获 m.main() 的输出，同时 print 到终端。
            # 无 main() 的模块直接驱动其 self_check()（这些模块仅在
            # __main__ 守卫下执行自检，import 不写报告；这里显式驱动，
            # 保证干净 artifact 上 --check 不因"无 main() 且无报告文件"漏计）。
            buf = io.StringIO()
            retval = None
            with contextlib.redirect_stdout(buf):
                if hasattr(m, "main"):
                    m.main()
                elif hasattr(m, "self_check"):
                    retval = m.self_check()
            captured = buf.getvalue()
            # 先打印到终端
            if captured:
                sys.stdout.write(captured)
            # 优先从 report 文件读取计数（更可靠）
            report = os.path.join(os.path.dirname(__file__),
                                  "%s_report.txt" % mod)
            counted = False
            if os.path.exists(report):
                with open(report, encoding="utf-8") as f:
                    found, total_pass, total_fail = _count_from_file(
                        f, total_pass, total_fail)
                    counted = found
            # 无 main() 且 self_check() 仅返回 (name, ok) 列表、不写报告文件
            # （shake/mldsa/slhdsa/credential），直接从返回值计数
            if not counted and isinstance(retval, (list, tuple)) and retval:
                sp = sum(1 for x in retval if bool(x[1]))
                sf = len(retval) - sp
                total_pass += sp
                total_fail += sf
                counted = True
                print("RESULT  PASS=%d  FAIL=%d  (from self_check return)"
                      % (sp, sf))
            # 若仍未被计数，从 stdout 捕获解析
            if not counted:
                parsed = _parse_result(captured)
                if parsed:
                    total_pass += parsed[0]
                    total_fail += parsed[1]
                    # 打印解析结果
                    print("RESULT  PASS=%d  FAIL=%d  (from stdout)"
                          % (parsed[0], parsed[1]))
        except Exception as e:
            print("RUN ERROR %s: %s" % (mod, e))
            total_fail += 1

    # Platform 10 API 烟测（进程内）
    print("\n=== platform smoke ===")
    try:
        from agent_platform import self_check as smoke
        ok = sum(1 for _, x in smoke() if x)
        tot = len(smoke())
        print("RESULT  PASS=%d  FAIL=%d" % (ok, tot - ok))
        total_pass += ok
        total_fail += tot - ok
    except Exception as e:
        print("RUN ERROR platform smoke: %s" % e)
        total_fail += 1

    # stdlib HTTP API 烟测
    print("\n=== http_api smoke ===")
    try:
        from http_api import self_check as http_smoke
        res = http_smoke()
        ok = sum(1 for _, x in res if x)
        print("RESULT  PASS=%d  FAIL=%d" % (ok, len(res) - ok))
        total_pass += ok
        total_fail += len(res) - ok
    except Exception as e:
        print("RUN ERROR http_api smoke: %s" % e)
        total_fail += 1

    print("\n" + "=" * 60)
    print("GRAND TOTAL  PASS=%d  FAIL=%d" % (total_pass, total_fail))
    print("=" * 60)
    return total_pass, total_fail


def run_http_smoke():
    """跑 HTTP API 端到端烟测。"""
    from http_api import self_check as http_smoke
    results = http_smoke()
    ok = 0
    for name, passed in results:
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            ok += 1
    print("SUMMARY  http_api smoke PASS=%d / %d" % (ok, len(results)))
    return ok


def main():
    parser = argparse.ArgumentParser(description="agent-cryptid v1.0 入口")
    parser.add_argument("--config", default="config.example.json",
                        help="配置文件路径")
    parser.add_argument("--smoke", action="store_true",
                        help="跑 10 API 烟测（进程内）")
    parser.add_argument("--check", action="store_true",
                        help="跑完整验证（SM2 + v0.1 + v1.0 持久化/多租户）")
    parser.add_argument("--http", action="store_true",
                        help="跑 HTTP API 端到端烟测")
    parser.add_argument("--demo", action="store_true", default=True,
                        help="跑端到端 demo（默认）")
    args = parser.parse_args()

    cfg = None
    if os.path.exists(args.config):
        cfg = load_config(args.config)
        print("加载配置：%s" % args.config)

    if args.smoke:
        run_smoke()
    elif args.check:
        run_full_check()
    elif args.http:
        run_http_smoke()
    else:
        run_demo(cfg)


if __name__ == "__main__":
    main()
