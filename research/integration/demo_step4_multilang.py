# -*- coding: utf-8 -*-
"""Step 4 / 多语言互操作：让 cryptid 保护的 A2A 服务被**两类异构客户端**驱动。

被测 SUT
--------
``gated`` 模式 + ``declare_cryptid=True``（卡片公开可发现、JSON-RPC 操作受
cryptid 保护、卡片正式声明 cryptid 安全方案）。与 Step 4 TCK 实验用的是
**同一个 SUT**，只是这次由客户端来打，而不是 TCK。

两类客户端（这就是"多语言"的全部含义）
--------------------------------------
1. **纯 HTTP 客户端**（`http_only_client.py`，Python 标准库，零 SDK）
   —— 证明 cryptid 只占用了 A2A 已定义好的两个标准位置（服务发现 +
   JSON-RPC SendMessage + 标准 Authorization 头），不引入任何 SDK 绑定成本。
   换成 curl / Java / Go / Rust 都是同一份协议面。
2. **官方 Node.js SDK 客户端**（`jsclient/multilang_client.mjs`，
   `@a2a-js/sdk` 1.3.0）—— 证明 Python 端签发的凭证可被另一个语言的官方
   SDK 直接消费，服务端零改动。

两者共享同一张凭证、同一个 SUT，各自独立发请求。任何一侧放行伪造/篡改/
受众不符的凭证，实验即判失败。

用法
----
    python demo_step4_multilang.py                # 自带 SUT
    python demo_step4_multilang.py --external http://127.0.0.1:9999/ \
                                     --token <wire>
    python demo_step4_multilang.py --node /path/to/node
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PY = sys.executable
_NODE = shutil.which("node") or shutil.which("nodejs")

sys.path.insert(0, _HERE)
from run_tck_authenticated import (  # noqa: E402
    _PY_SUT, _PORT, _find_token, _spawn_declared_sut, _wait_card)

JSC = os.path.join(_HERE, "jsclient", "multilang_client.mjs")
HTT = os.path.join(_HERE, "http_only_client.py")


def _run(cmd, env=None, timeout=180, tag=""):
    """跑一条命令，返回 (rc, stdout)。"""
    print("\n" + "·" * 72)
    print("  ▶ %s" % tag)
    print("·" * 72)
    p = subprocess.run(cmd, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout,
                       cwd=_HERE)
    out = (p.stdout or "") + (p.stderr or "")
    print(out.rstrip() or "  (无输出)")
    return p.returncode, out


def _n_pass_fail(out):
    """从客户端输出里抠出 PASS/FAIL 计数。"""
    npass = out.count("[PASS]")
    nfail = out.count("[FAIL]")
    return npass, nfail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--external", default=None,
                    help="复用外部已启动的 SUT（须 gated + 声明 cryptid）")
    ap.add_argument("--token", default=None, help="配 --external 使用")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--node", default=_NODE, help="node 可执行文件路径")
    args = ap.parse_args()

    base = "http://127.0.0.1:%d/" % args.port
    proc = None

    print("=" * 72)
    print("  Step 4 / 多语言互操作：cryptid-guarded A2A SUT × 两类异构客户端")
    print("=" * 72)

    try:
        # ---------- 1. 起 SUT ----------
        if args.external:
            base = args.external if args.external.endswith("/") \
                else args.external + "/"
            tok = args.token
            if not tok:
                print("  [!] --external 必须配 --token")
                return 2
            st, _ = _wait_card(base)
            print("  外部 SUT 卡片可达：%s" % st)
        else:
            print("  启动 gated + declare_cryptid=True 的 SUT ...")
            proc, tok, _buf = _spawn_declared_sut()
            if not tok:
                print("  [!] 未取得 DEMO_TOKEN")
                return 1
            st, _ = _wait_card(base, timeout=25.0)
            if st != 200:
                print("  [!] SUT 未就绪（卡片 %s）" % st)
                return 1
            print("  SUT 就绪：GET agent-card → %s" % st)
        print("  凭证就绪：%d 字符（base64url wire）" % len(tok))

        env = dict(os.environ, CRYPTID_TOKEN=tok, SUT_URL=base)
        env["PYTHONIOENCODING"] = "utf-8"

        summary = []

        # ---------- 2. 纯 HTTP 客户端 ----------
        rc, out = _run([_PY, HTT, "--url", base, "--token", tok], env=env,
                       tag="客户端 1/2：纯 HTTP（Python 标准库，零 A2A SDK）")
        npass, nfail = _n_pass_fail(out)
        summary.append(("纯 HTTP 客户端（无 SDK）", rc, npass, nfail))

        # ---------- 3. Node.js 官方 SDK 客户端 ----------
        if not args.node:
            print("\n  [!] 未找到 node，跳过客户端 2/2")
            summary.append(("@a2a-js/sdk 1.3.0（Node）", None, 0, 0))
        elif not os.path.exists(JSC):
            print("\n  [!] 缺 %s" % JSC)
            summary.append(("@a2a-js/sdk 1.3.0（Node）", None, 0, 0))
        else:
            rc, out = _run([args.node, JSC, base], env=env,
                           tag="客户端 2/2：官方 @a2a-js/sdk 1.3.0（Node.js）")
            npass, nfail = _n_pass_fail(out)
            summary.append(("@a2a-js/sdk 1.3.0（Node）", rc, npass, nfail))

        # ---------- 4. 汇总 ----------
        print("\n" + "=" * 72)
        print("  汇总")
        print("=" * 72)
        print("  %-28s %-8s %s" % ("客户端", "退出码", "PASS/FAIL"))
        for name, rc, npass, nfail in summary:
            print("  %-28s %-8s %s" % (
                name, (rc if rc is not None else "跳过"),
                "%d/%d" % (npass, nfail)))
        total_pass = sum(s[2] for s in summary)
        total_fail = sum(s[3] for s in summary)
        ok = total_fail == 0 and all(s[1] in (0, None) for s in summary)
        print("\n  合计 %d PASS / %d FAIL" % (total_pass, total_fail))
        print("  → 多语言互操作%s" % ("通过" if ok else "未通过"))
        return 0 if ok else 1
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:                      # noqa: BLE001
                try:
                    proc.kill()
                except Exception:                 # noqa: BLE001
                    pass


if __name__ == "__main__":
    sys.exit(main())
