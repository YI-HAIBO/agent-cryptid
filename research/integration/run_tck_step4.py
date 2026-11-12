# -*- coding: utf-8 -*-
"""Step 4 驱动：用**官方 A2A TCK** 实测 cryptid-guarded A2A 服务的规范合规度。

跑什么
------
    官方 TCK (a2aproject/a2a-tck, commit 5daf014)
        run_tck.py --sut-host http://127.0.0.1:<port> --transport jsonrpc
        run_tck.py --sut-host http://127.0.0.1:<port> --transport jsonrpc --level must

TCK 自己会：无鉴权拉 ``/.well-known/agent-card.json`` → 按 supportedInterfaces
建 JSONRPC transport client → 跑 RFC 2119 MUST/SHOULD/MAY 分层用例 → 报告**恒定**
写到 TCK 的 cwd 下 ``reports/compatibility.{json,html}`` + ``tck_report.html`` +
``junitreport.xml``（没有 --compatibility-report 开关，本脚本跑完归档到
``tck_reports/<mode>/``）。本脚本只负责编排与解读。

三种形态对照（结论的诚实性所在）
-------------------------------
  baseline     无鉴权、不声明 cryptid  —— 测「底层 A2A 实现」本身是否合规
  gated        卡片公开 + 操作受 cryptid 保护 —— **推荐形态**
  card-gated   连卡片一起锁 —— 反例，应导致 TCK 无法发现服务

用法
----
    python run_tck_step4.py                 # 三种形态都跑
    python run_tck_step4.py --mode baseline # 只跑基线
"""
import argparse
import json
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))          # agent-cryptid
_TCK = os.path.join(_REPO, "research", "tck")                     # 官方 TCK 克隆
_PY_SUT = r"C:/Users/Yi/.workbuddy/binaries/python/envs/a2amcp/Scripts/python.exe"
_PY_TCK = r"C:/Users/Yi/.workbuddy/binaries/python/envs/tck/Scripts/python.exe"
_PORT = 9999


def _wait_card(base_url, timeout=25.0):
    """轮询 agent-card 直到可访问；返回 (ok, status, snippet)。"""
    import urllib.request
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url.rstrip("/") +
                                        "/.well-known/agent-card.json",
                                        timeout=3) as r:
                body = r.read(200).decode("utf-8", "replace")
                return True, r.status, body
        except Exception as e:                                    # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, e)
            time.sleep(0.5)
    return False, None, last


def run_tck(base_url, outdir, *, level="all", timeout=900):
    """在官方 TCK 目录里跑一次 run_tck.py，返回 (rc, stdout_tail)。

    两个 CLI 事实（踩出来的）：
      · --level 只接受 must/should/may；「全部」必须**省略**该参数。
      · 没有 --compatibility-report 开关——报告**恒定**写到 TCK 的 cwd
        下 ``reports/compatibility.{json,html}`` + ``tck_report.html`` +
        ``junitreport.xml``。所以出报告只需跑完，不用传路径。
    rc 语义：0=全过，1=有 requirement 未过（**这不是脚本错误**），
    2=用法错误，5=无用例被执行。
    """
    cmd = [_PY_TCK, "run_tck.py",
           "--sut-host", base_url,
           "--transport", "jsonrpc"]
    if level != "all":
        cmd += ["--level", level]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run(cmd, cwd=_TCK, env=env, capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def copy_reports(mode):
    """把 TCK 恒定的 reports/ 目录按形态归档到 tck_reports/<mode>/。"""
    src = os.path.join(_TCK, "reports")
    dst = os.path.join(_HERE, "tck_reports", mode)
    os.makedirs(dst, exist_ok=True)
    copied = []
    if os.path.isdir(src):
        for f in os.listdir(src):
            if f.lower().endswith((".json", ".html", ".xml")):
                with open(os.path.join(src, f), "rb") as fh:
                    data = fh.read()
                with open(os.path.join(dst, f), "wb") as fh:
                    fh.write(data)
                copied.append(f)
    return copied


def summarize(mode, base_url, outdir, *, level):
    """解析 compatibility.json，打印一张合规矩阵。"""
    rp = os.path.join(outdir, "compatibility.json")
    if not os.path.exists(rp):
        print("  [!] 无 compatibility.json（TCK 未产出报告）")
        return None
    with open(rp, encoding="utf-8") as f:
        rep = json.load(f)
    s = rep.get("summary", {})
    print("\n  summary:")
    for k in ("sut_url", "overall_compatibility", "must_compatibility",
              "should_compatibility", "may_compatibility"):
        if k in s:
            print("    %-24s %s" % (k, s[k]))

    per_req = rep.get("per_requirement", {})
    if per_req:
        from collections import Counter
        cnt = Counter(r.get("status", "?") for r in per_req.values())
        print("  per_requirement: %d 条 (%s)" % (
            len(per_req), ", ".join("%s=%d" % (k, v) for k, v in sorted(cnt.items()))))
        fails = [(rid, r) for rid, r in per_req.items()
                 if r.get("status") not in ("PASS", "PASSED")]
        if fails:
            print("  未通过（前 12 条）:")
            for rid, r in fails[:12]:
                err = (r.get("errors") or [""])[0]
                err = err.replace("\n", " ")[:110]
                print("    %-22s %-6s %s" % (rid, r.get("level"), err))
    pt = rep.get("per_transport", {})
    for t, v in pt.items():
        print("  transport[%s] total=%s passed=%s failed=%s skipped=%s" % (
            t, v.get("total"), v.get("passed"), v.get("failed"), v.get("skipped")))
    return rep


def try_mode(mode, level):
    print("\n" + "=" * 74)
    print("  SUT mode = %s" % mode)
    print("=" * 74)
    base_url = "http://127.0.0.1:%d/" % _PORT
    outdir = os.path.join(_HERE, "tck_reports", mode)
    os.makedirs(outdir, exist_ok=True)

    cmd = [_PY_SUT, os.path.join(_HERE, "sut_a2a_server.py"),
           "--mode", mode, "--port", str(_PORT),
           "--host", "127.0.0.1"]
    proc = subprocess.Popen(cmd, cwd=_HERE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace")
    try:
        ok, st, snip = _wait_card(base_url)
        if not ok:
            print("  [!] SUT 未就绪：%s" % snip)
            return None
        print("  SUT 就绪：GET agent-card → %s" % st)
        rc, out = run_tck(base_url, outdir, level=level)
        copied = copy_reports(mode)
        print("  TCK rc=%d（0=全过 1=有 requirement 未过 2=用法错 5=无用例）" % rc)
        print("  报告归档: %s (%s)" % (
            outdir, ", ".join(copied) if copied else "无"))
        # 只回显控制台合规摘要那一段
        tail = "\n".join(l for l in out.splitlines()
                         if "compatibility" in l.lower() or "%" in l
                         or "Requirement" in l or "requirement" in l
                         or "passed" in l.lower() or "failed" in l.lower())
        print("  " + "\n  ".join(tail.splitlines()[-20:]))
        return summarize(mode, base_url, outdir, level=level)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="all",
                    choices=["all", "baseline", "gated", "card-gated"])
    ap.add_argument("--level", default="all",
                    choices=["all", "must", "should", "may"])
    ap.add_argument("--port", type=int, default=9999)
    args = ap.parse_args()
    global _PORT
    _PORT = args.port

    if not os.path.isdir(_TCK):
        print("缺官方 TCK：%s\n  请先 git clone https://github.com/a2aproject/a2a-tck.git"
              % _TCK)
        return 2
    if not os.path.exists(_PY_TCK):
        print("缺 TCK venv：%s" % _PY_TCK)
        return 2

    print("TCK 仓库: %s" % _TCK)

    modes = (["baseline", "gated", "card-gated"] if args.mode == "all"
             else [args.mode])
    results = {}
    for m in modes:
        results[m] = try_mode(m, args.level)

    print("\n" + "=" * 74)
    print("  Step 4 TCK 汇总")
    print("=" * 74)
    for m, rep in results.items():
        s = (rep or {}).get("summary", {})
        print("  %-12s overall=%-8s must=%-8s should=%-8s may=%-8s" % (
            m, s.get("overall_compatibility", "-"),
            s.get("must_compatibility", "-"),
            s.get("should_compatibility", "-"),
            s.get("may_compatibility", "-")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
