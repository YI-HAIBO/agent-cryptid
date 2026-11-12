# -*- coding: utf-8 -*-
"""Step 4 决定性实验：cryptid 认证补齐后，A2A 合规度是否回到基线水平。

回答的问题
----------
`gated` 形态跑官方 TCK 时合规率从 32.9% 掉到 18.2%（-14.7pp）。
掉分**是因为 cryptid 破坏了 A2A 语义**，还是**因为 TCK 不会带凭证**？

本脚本用 TCK 自带的 auth 缺口（见 ``tck_auth_plugin.py`` docstring）补上
凭证后再跑一遍。若合规度与 ``baseline`` 等价，则证明：

    cryptid 的授权层与 A2A 合规度是**正交**的 ——
    加了认证，A2A 功能一项不减；减掉的是「不会认证的测试器能测到的量」。

被测形态
--------
本脚本**自建** SUT，形态为 ``gated`` + ``declare_cryptid=True``：
卡片公开（A2A §8.2 发现不被破坏）+ 操作受 cryptid 保护 + **卡片正式声明
cryptid 安全方案**（``security_schemes["cryptid-bearer"]`` +
``capabilities.extensions``），即一个配置自洽的受保护服务。

注意这与 ``run_tck_step4.py --mode gated`` 不同：那个跑的是默认 SUT
（``declare_cryptid=False``），即"卡片没说需认证、服务端却强制认证"的
**配置不一致反例**，它掉分掉得更多（18.2%），正是为了暴露这个缺口。

用法
----
    python run_tck_authenticated.py                  # 自带 SUT
    python run_tck_authenticated.py --external http://127.0.0.1:9999/ \
                                     --token <cryptid wire>
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))
_TCK = os.path.join(_REPO, "research", "tck")
_PY_SUT = r"C:/Users/Yi/.workbuddy/binaries/python/envs/a2amcp/Scripts/python.exe"
_PY_TCK = r"C:/Users/Yi/.workbuddy/binaries/python/envs/tck/Scripts/python.exe"
_PORT = 9999
_OUT_AUTH = os.path.join(_HERE, "tck_reports", "gated-authenticated")
_OUT_CTRL = os.path.join(_HERE, "tck_reports", "gated-noplugin")


# ---------------------------------------------------------------------------
# 自带 SUT
# ---------------------------------------------------------------------------
_SUT_MAIN = r'''
# -*- coding: utf-8 -*-
# gated + declare_cryptid=True 的受保护 A2A SUT（供官方 TCK 测试）。
import sys, uvicorn
from cryptid_bridge import CryptidAuthority
from sut_a2a_server import build_sut_app, CARD_URL

auth = CryptidAuthority()
auth.register("agent://sut/issuer", agent_type="issuance")
auth.register("agent://sut/worker", agent_type="worker")
tok, _ = auth.issue("agent://sut/issuer", "agent://sut/worker",
                    "service://a2a-agent", ["agent:invoke"], ttl=3600)
app, meta = build_sut_app("http://127.0.0.1:9999/", mode="gated",
                          declare_cryptid=True, platform=auth.platform)
print("[SUT-DECL] mode=gated declare_cryptid=True card=%s" % CARD_URL,
      flush=True)
print("[SUT-DECL] card_security_schemes=%s" % list(
    (meta["card"].security_schemes or {}).keys()), flush=True)
print("[SUT-DECL] DEMO_TOKEN=%s" % tok, flush=True)
uvicorn.run(app, host="127.0.0.1", port=9999, log_level="warning",
            lifespan="off")
'''


def _find_token(out):
    for line in out.splitlines():
        if "DEMO_TOKEN=" in line:
            return line.split("DEMO_TOKEN=", 1)[1].strip()
    return None


def _spawn_declared_sut():
    """起一个"卡片公开+操作受保护+卡片正式声明 cryptid"的 SUT，返回 token。"""
    proc = subprocess.Popen(
        [_PY_SUT, "-c", _SUT_MAIN], cwd=_HERE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace")
    deadline = time.time() + 30.0
    buf = ""
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.2)
            continue
        buf += line
        if "DEMO_TOKEN=" in line:
            return proc, _find_token(buf), buf
    proc.terminate()
    raise RuntimeError("SUT 未就绪：\n%s" % buf)


def _wait_card(base_url, timeout=15.0):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url.rstrip("/") +
                                        "/.well-known/agent-card.json",
                                        timeout=3) as r:
                return r.status, r.read(300).decode("utf-8", "replace")
        except Exception:                                       # noqa: BLE001
            time.sleep(0.4)
    return None, None


# ---------------------------------------------------------------------------
# 跑 TCK（带 cryptid 凭证）
# ---------------------------------------------------------------------------
def run_tck(base_url, token, *, with_plugin=True):
    """跑官方 TCK。``with_plugin=True`` 时插件把 Bearer 注入全部出站请求。

    ``with_plugin=False`` 是控制组：同一 SUT、同一 token，但 TCK 不带凭证，
    用来隔离「掉分到底是 A2A 语义回退还是不会带凭证」这个变量。
    """
    cmd = [_PY_TCK, "-m", "pytest", "tests/compatibility/"]
    if with_plugin:
        cmd += ["-p", "tck_auth_plugin"]
    cmd += ["--sut-host", base_url,
            "--transport", "jsonrpc",
            "--tb", "short", "-q",
            "--compatibility-report=reports/compatibility",
            "--html=reports/tck_report.html", "--self-contained-html",
            "--junitxml=reports/junitreport.xml"]
    env = dict(os.environ,
               PYTHONPATH=_HERE + os.pathsep +
               os.environ.get("PYTHONPATH", ""),
               CRYPTID_TOKEN=token if with_plugin else "",
               CRYPTID_SCHEME="bearer",
               PYTHONIOENCODING="utf-8")
    p = subprocess.run(cmd, cwd=_TCK, env=env, capture_output=True,
                       text=True, timeout=900)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def summarize(tag, base_url, outdir=_OUT_AUTH):
    """解析 compatibility.json，打印合规摘要。"""
    rp = os.path.join(outdir, "compatibility.json")
    if not os.path.exists(rp):
        print("  [!] 无 compatibility.json（TCK 未产出报告）")
        return None
    with open(rp, encoding="utf-8") as f:
        rep = json.load(f)
    s = rep.get("summary", {})
    print("\n  [%s] summary:" % tag)
    for k in ("sut_url", "overall_compatibility", "must_compatibility",
              "should_compatibility", "may_compatibility"):
        if k in s:
            print("    %-24s %s" % (k, s[k]))
    pr = rep.get("per_requirement", {})
    from collections import Counter
    cnt = Counter(r.get("status", "?") for r in pr.values())
    print("  per_requirement: %d 条 (%s)" % (
        len(pr), ", ".join("%s=%d" % (k, v) for k, v in sorted(cnt.items()))))
    pt = rep.get("per_transport", {})
    for t, v in pt.items():
        print("  transport[%s] total=%s passed=%s failed=%s skipped=%s" % (
            t, v.get("total"), v.get("passed"), v.get("failed"),
            v.get("skipped")))
    return rep


def compare(mode_a, mode_b, rep_a, rep_b):
    """逐 requirement 对比两个形态，输出正交性证据。"""
    a = (rep_a or {}).get("per_requirement", {})
    b = (rep_b or {}).get("per_requirement", {})
    both = sorted(set(a) & set(b))
    same = sum(1 for k in both if a[k]["status"] == b[k]["status"])
    only_a = [(k, a[k]["status"], b[k]["status"]) for k in both
              if a[k]["status"] != b[k]["status"]]
    print("\n  逐条对比 %s vs %s：" % (mode_a, mode_b))
    print("    可比 requirement = %d，状态完全一致 = %d (%.1f%%)" % (
        len(both), same, 100.0 * same / max(1, len(both))))
    if only_a:
        print("    状态不同的 %d 条：" % len(only_a))
        for rid, sa, sb in only_a[:20]:
            print("      %-24s %-11s → %-11s" % (rid, sa, sb))
    else:
        print("    → 无任何一条 requirement 发生变化")
    return same, len(both)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--external", default=None,
                    help="复用外部已启动的 SUT（须 gated + 声明 cryptid）")
    ap.add_argument("--token", default=None, help="配 --external 使用")
    ap.add_argument("--no-plugin", action="store_true",
                    help="控制组：同一 SUT 但 TCK 不带凭证（隔离变量）")
    args = ap.parse_args()
    outdir = _OUT_CTRL if args.no_plugin else _OUT_AUTH

    if not os.path.isdir(_TCK):
        print("缺官方 TCK：%s" % _TCK)
        return 2
    if not os.path.exists(_PY_TCK):
        print("缺 TCK venv：%s" % _PY_TCK)
        return 2

    global _PORT
    _PORT = args.port
    base_url = "http://127.0.0.1:%d/" % _PORT
    proc = None
    try:
        if args.external:
            print("用外部 SUT：%s" % args.external)
            if not args.token:
                print("  [!] --external 必须配 --token")
                return 2
            base_url = args.external
            if not base_url.endswith("/"):
                base_url += "/"
            token = args.token
            st, _ = _wait_card(base_url)
            print("  卡片可达：%s" % st)
        else:
            print("启动 gated + declare_cryptid=True 的 SUT ...")
            proc, token, buf = _spawn_declared_sut()
            st, _ = _wait_card(base_url)
            print("  SUT 就绪，GET agent-card → %s" % st)

        rc, out = run_tck(base_url, token, with_plugin=not args.no_plugin)
        os.makedirs(outdir, exist_ok=True)
        for f in ("compatibility.html", "compatibility.json",
                  "junitreport.xml", "tck_report.html"):
            src = os.path.join(_TCK, "reports", f)
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(outdir, f))
        print("\n  TCK rc=%d（0=全过 1=有 requirement 未过 2=用法错 5=无用例）"
              % rc)
        print("  报告归档：%s" % outdir)

        lines = [l for l in out.splitlines()
                 if "cryptid-auth" in l or "passed" in l.lower()
                 or "failed" in l.lower() or "%" in l]
        print("  " + "\n  ".join(lines[-14:]))

        tag = "gated, 无凭证" if args.no_plugin else "gated+cryptid-auth"
        rep = summarize(tag, base_url, outdir)
        bl = os.path.join(_HERE, "tck_reports", "baseline",
                          "compatibility.json")
        if os.path.exists(bl):
            with open(bl, encoding="utf-8") as f:
                base = json.load(f)
            compare("baseline(无鉴权)", tag, base, rep)
        return 0
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
