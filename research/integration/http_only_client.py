# -*- coding: utf-8 -*-
"""纯 HTTP 客户端：**不用任何 A2A SDK**，只用 Python 标准库打 cryptid 保护的 A2A 服务。

目的
----
证明 cryptid 的接入面是**协议级**而非 SDK 级的：一个只懂 HTTP + JSON 的客户端
（可以是 curl、可以是 Java/Go/Rust 里几十行代码）就能完成 A2A 的服务发现与
SendMessage 调用，只要它带对了 cryptid Bearer。

对论文的意义
------------
这补上了「多语言互操作」里最弱的一环——不是「换个语言调 SDK」，而是
**根本不依赖 SDK**。cryptid 不引入任何 SDK 绑定成本，因为它只占用了
A2A 早已定义好的两个标准位置：

  · 服务发现：``GET /.well-known/agent-card.json``（A2A §8.2，无鉴权）
  · 操作调用：``POST /``，JSON-RPC 2.0，``method: "SendMessage"``，
    外加 ``Authorization: Bearer <cryptid wire>`` 与 ``A2A-Version: 1.0``

用法
----
    python http_only_client.py                 # 只跑无凭证负向对照
    python http_only_client.py --token <wire> --url http://127.0.0.1:9999/
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

CARD_PATH = "/.well-known/agent-card.json"
A2A_VERSION = "1.0"


class Result(object):
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, ok, detail=""):
        tag = "PASS" if ok else "FAIL"
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        print("  [%s] %s%s" % (tag, name, (" — " + detail) if detail else ""))
        return ok


def http_call(url, *, method="POST", headers=None, body=None, timeout=15.0):
    """返回 (status, body_text, error_or_None)。永不抛异常。"""
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            txt = e.read().decode("utf-8", "replace")
        except Exception:
            txt = ""
        return e.code, txt, "%s" % e
    except Exception as e:                                       # noqa: BLE001
        return None, "", "%s: %s" % (type(e).__name__, e)


def fetch_card(base_url, res, result):
    """服务发现（A2A §8.2，无鉴权）。返回 card dict 或 None。"""
    st, txt, err = http_call(base_url.rstrip("/") + CARD_PATH, method="GET")
    if st != 200:
        res.check("Agent Card 可公开发现（无鉴权）", False,
                  "HTTP %s %s" % (st, err or txt[:60]))
        return None
    try:
        card = json.loads(txt)
    except ValueError as e:
        res.check("Agent Card 可公开发现（无鉴权）", False, "非 JSON：%s" % e)
        return None
    res.check("Agent Card 可公开发现（无鉴权）", True, "HTTP 200")
    result["card"] = card
    return card


def discover_interface(card):
    """从 supportedInterfaces 里挑出 JSON-RPC 接口的 url。"""
    for iface in card.get("supportedInterfaces") or []:
        if (iface.get("protocolBinding") or "").upper() == "JSONRPC":
            url = iface.get("url") or ""
            if not url.endswith("/"):
                url += "/"
            return url
    return None


def send_message(rpc_url, text, token=None, mid=None):
    """用裸 JSON-RPC 2.0 调 SendMessage。返回 (status, parsed_or_None, err)。"""
    headers = {"A2A-Version": A2A_VERSION}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = {
        "jsonrpc": "2.0",
        "id": mid or str(uuid.uuid4()),
        "method": "SendMessage",
        "params": {
            "message": {
                "kind": "message",
                "messageId": "msg-" + uuid.uuid4().hex[:16],
                "role": "ROLE_USER",
                "parts": [{"kind": "text", "text": text}],
            },
            "configuration": {"acceptedOutputModes": ["text"]},
        },
    }
    st, txt, err = http_call(rpc_url.rstrip("/") + "/", headers=headers, body=body)
    parsed = None
    if txt:
        try:
            parsed = json.loads(txt)
        except ValueError:
            pass
    return st, parsed, err


def _swap_aud(token, new_aud):
    """把 wire 凭证的 aud 改成别处（MCP 域），再压回 base64url。

    重编码会同时破坏签名，因此这条对照同时覆盖了「受众不符」与「签名失效」
    两个拒绝点——任何一个触发都应返回 401。
    """
    import base64
    try:
        pad = "=" * (-len(token) % 4)
        d = json.loads(base64.urlsafe_b64decode(token + pad).decode("utf-8"))
        d["aud"] = new_aud
        raw = json.dumps(d, separators=(",", ":"), sort_keys=True,
                         ensure_ascii=False).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    except Exception:                                       # noqa: BLE001
        return token[:len(token) - 20]                      # 退化为截断


def reply_text(parsed):
    """从 SendMessage 响应里抽回复文本；拿不到返回空串。"""
    if not isinstance(parsed, dict):
        return ""
    res = parsed.get("result") or {}
    msg = res.get("message") or {}
    parts = msg.get("parts") or []
    out = []
    for p in parts:
        if isinstance(p, dict) and isinstance(p.get("text"), str):
            out.append(p["text"])
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="纯 HTTP 客户端（无 A2A SDK）")
    ap.add_argument("--url", default="http://127.0.0.1:9999/",
                    help="SUT 基址")
    ap.add_argument("--token", default=None, help="cryptid wire 凭证")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    res = Result()
    ctx = {}

    print("=" * 72)
    print("  纯 HTTP 客户端（Python 标准库，零 A2A SDK 依赖）")
    print("=" * 72)
    print("  SUT   : %s/" % base)
    print("  TOKEN : %s" % ("已提供（%d 字符）" % len(args.token)
                            if args.token else "未提供（仅跑负向对照）"))
    print()

    card = fetch_card(base, res, ctx)
    if not card:
        print("\n卡片不可达，终止。")
        return 1

    print("       name           = %s" % card.get("name"))
    print("       version        = %s" % card.get("version"))
    print("       securitySchemes = %s"
          % list((card.get("securitySchemes") or {}).keys()))
    exts = (card.get("capabilities") or {}).get("extensions") or \
        card.get("extensions") or []
    print("       extensions     = %s"
          % [e.get("uri") for e in exts])
    res.check("卡片正式声明 cryptid 安全方案",
              "cryptid-bearer" in (card.get("securitySchemes") or {}),
              "securitySchemes=%s" % list(
                  (card.get("securitySchemes") or {}).keys()))

    rpc_url = discover_interface(card)
    res.check("卡片给出 JSON-RPC 接口地址", bool(rpc_url), str(rpc_url))
    if not rpc_url:
        rpc_url = base + "/"

    # ---- 正向 ----
    if args.token:
        print("\n[2] 正向：裸 JSON-RPC + cryptid Bearer")
        st, parsed, err = send_message(rpc_url, "hello via pure http",
                                       token=args.token)
        txt = reply_text(parsed)
        ok = st == 200 and bool(txt)
        res.check("带 cryptid 凭证 → SendMessage 成功", ok,
                  "HTTP %s reply=%r" % (st, txt))
        if parsed and "error" in parsed:
            print("       JSON-RPC error: %s" % parsed["error"])

    # ---- 负向对照 A：无凭证 ----
    print("\n[3] 负向对照 A：不带 Authorization")
    st, parsed, err = send_message(rpc_url, "should be rejected")
    res.check("无凭证被拒", st == 401,
              "HTTP %s %s" % (st, (parsed or {}).get("error") or ""))

    # ---- 负向对照 B：伪造 Bearer ----
    print("\n[4] 负向对照 B：伪造 Bearer")
    st, parsed, err = send_message(rpc_url, "forged", token="DEADBEEF")
    res.check("伪造 Bearer 被拒", st == 401,
              "HTTP %s %s" % (st, (parsed or {}).get("error") or ""))

    # ---- 负向对照 C：篡改凭证（破坏签名覆盖） ----
    if args.token:
        print("\n[5] 负向对照 C：篡改凭证尾部（破坏签名）")
        tam = args.token[:-20]
        st, parsed, err = send_message(rpc_url, "tampered", token=tam)
        res.check("篡改凭证被拒", st == 401,
                  "HTTP %s %s" % (st, (parsed or {}).get("error") or ""))

    # ---- 负向对照 D：跨协议挪用（MCP 域 token 打到 A2A 端） ----
    if args.token:
        print("\n[6] 负向对照 D：aud 改写为 MCP 域（跨协议挪用）")
        swapped = _swap_aud(args.token, "resource://mcp-tool")
        st, parsed, err = send_message(rpc_url, "audience swap", token=swapped)
        res.check("受众不符/签名失效被拒", st == 401,
                  "HTTP %s %s" % (st, (parsed or {}).get("error") or ""))

    print("\n" + "=" * 72)
    print("  结果：%d PASS / %d FAIL" % (res.passed, res.failed))
    print("=" * 72)
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
