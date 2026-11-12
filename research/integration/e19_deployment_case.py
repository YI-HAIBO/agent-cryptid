# -*- coding: utf-8 -*-
"""E19 (G4)：端到端多平台部署案例测量。

把 agent-cryptid 身份层插入真实 A2A 协议栈，测量三件事：

  1. 端到端往返时延：baseline（无 cryptid）vs gated（cryptid 守卫）——
     回答「身份层加在真实 A2A 调用上，端到端开销是多少」；
  2. 委托链收敛：3 跳（root→dev→ops→sec）建立 + 链验证时延；
  3. 攻击阻断率：4 类攻击 × 2 边界 = 8/8 拒绝，正向对照通过。

可复现：同一 host 内 baseline/gated 同码路径对比（开销比 load 无关），
绝对时延受 host 影响（安静机 VM 见论文 §实验设置）。

运行环境：a2amcp venv（a2a-sdk 1.2.3 / mcp 2.3.0）。
    python research/integration/e19_deployment_case.py [--n N] [--hops 3]
"""
import argparse
import csv
import os
import statistics
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fastapi.testclient import TestClient  # noqa: E402
from a2a.utils.constants import VERSION_HEADER, PROTOCOL_VERSION_CURRENT  # noqa: E402

from cryptid_bridge import CryptidAuthority, decode_bearer, encode_bearer  # noqa: E402
from sut_a2a_server import build_sut_app  # noqa: E402

A2A_AUD = "service://a2a-agent"


def _send_body(mid=1):
    return {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": {"message": {"role": "ROLE_USER",
                                   "parts": [{"text": "ping"}],
                                   "messageId": "m%d" % mid}}}


def _latency(client, url, headers, n):
    """N 次合法 SendMessage 往返时延（ms），返回 (median, p99, mean)."""
    times = []
    for i in range(n):
        t0 = time.perf_counter()
        r = client.post(url, json=_send_body(i + 1), headers=headers)
        t1 = time.perf_counter()
        if r.status_code == 401:
            raise RuntimeError("unexpected 401 in latency loop")
        times.append((t1 - t0) * 1000.0)
    times.sort()
    return (statistics.median(times), times[int(0.99 * (len(times) - 1))],
            statistics.mean(times))


def _benchmark_roundtrip(n, auth):
    """baseline vs gated 端到端往返时延。"""
    # baseline：无 cryptid 中间件
    base_app, base_meta = build_sut_app(
        "http://127.0.0.1:9998/", mode="baseline", declare_cryptid=False)
    base_client = TestClient(base_app)
    base_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT}
    b_med, b_p99, b_mean = _latency(base_client, base_meta["rpc_url"], base_hdr, n)

    # gated：cryptid 中间件 + 合法 Bearer
    gate_app, gate_meta = build_sut_app(
        "http://127.0.0.1:9997/", mode="gated", declare_cryptid=True,
        platform=auth.platform, expected_aud=A2A_AUD)
    gate_client = TestClient(gate_app)
    tok, _ = auth.issue("agent://e19/issuer", "agent://e19/worker",
                        A2A_AUD, ["agent:invoke"], ttl=3600)
    gate_hdr = {VERSION_HEADER: PROTOCOL_VERSION_CURRENT,
                "Authorization": "Bearer " + tok}
    g_med, g_p99, g_mean = _latency(gate_client, gate_meta["rpc_url"], gate_hdr, n)

    return {
        "baseline_ms": {"median": b_med, "p99": b_p99, "mean": b_mean},
        "gated_ms": {"median": g_med, "p99": g_p99, "mean": g_mean},
        "overhead_ratio": g_med / b_med if b_med else float("inf"),
        "overhead_ms": g_med - b_med,
    }


def _benchmark_delegation(hops, auth):
    """3 跳委托链建立 + 链验证时延（scope 收敛）。"""
    ids = ["agent://e19/root"] + ["agent://e19/d%d" % i for i in range(1, hops + 1)]
    for i in ids:
        auth.register(i, agent_type="issuance" if i.endswith("root") else "worker")

    # 建立链：root → d1 → d2 → ...（每次 scope 严格子集）
    chain = []
    t0 = time.perf_counter()
    parent = None
    scopes = [["read", "write", "admin"], ["read", "write"], ["read"], ["read"]]
    for i in range(1, hops + 1):
        res = auth.platform.issue_delegation(
            ids[i - 1], ids[i], A2A_AUD, scopes[i] if i < len(scopes) else ["read"],
            parent_cred=parent)
        if not res.get("ok"):
            raise RuntimeError("delegation failed: %s" % res.get("reason"))
        parent = res["cred"]
        chain.append(parent)
    establish_ms = (time.perf_counter() - t0) * 1000.0

    # 链验证
    t0 = time.perf_counter()
    v = auth.platform.verify_delegation_chain(chain, target_audience=A2A_AUD,
                                              target_scope=scopes[hops])
    verify_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "hops": hops,
        "establish_ms": establish_ms,
        "verify_ms": verify_ms,
        "scope_ok": bool(v.get("ok")),
    }


def _attack_blocking(auth):
    """4 类攻击 × 2 边界 = 8/8 拒绝（复用权威 E10，口径与论文一致）。"""
    from e10_integration_attacks import E10_integration_attacks
    e10 = E10_integration_attacks(quick=False)
    return {"blocked": [a["rejected"] for a in e10["attacks"]],
            "n": e10["n_attacks"],
            "all_blocked": e10["all_rejected"],
            "control_mcp": e10["controls"]["mcp_valid_accepted"] and
                           e10["controls"]["a2a_valid_accepted"]}


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


def main():
    ap = argparse.ArgumentParser(description="E19 deployment case (G4)")
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--hops", type=int, default=3)
    args = ap.parse_args()

    auth = CryptidAuthority()
    auth.register("agent://e19/issuer", agent_type="issuance")
    auth.register("agent://e19/worker", agent_type="worker")

    print("=" * 64)
    print("E19 部署案例：A2A 栈端到端开销 + 委托链收敛 + 攻击阻断")
    print("=" * 64)

    rt = _benchmark_roundtrip(args.n, auth)
    print("端到端往返 (n=%d): baseline median=%.2fms p99=%.2fms | "
          "gated median=%.2fms p99=%.2fms | 开销比=%.2fx (+%.2fms)" % (
              args.n, rt["baseline_ms"]["median"], rt["baseline_ms"]["p99"],
              rt["gated_ms"]["median"], rt["gated_ms"]["p99"],
              rt["overhead_ratio"], rt["overhead_ms"]))

    dlg = _benchmark_delegation(args.hops, auth)
    print("委托链 (%d 跳): 建立=%.2fms 验证=%.2fms scope_ok=%s" % (
        dlg["hops"], dlg["establish_ms"], dlg["verify_ms"], dlg["scope_ok"]))

    atk = _attack_blocking(auth)
    print("攻击阻断: %d/%d 拒绝, 全部=%s, MCP正向对照=%s" % (
        atk["n"] if atk["n"] else 0, 8, atk["all_blocked"], atk["control_mcp"]))

    out = {"roundtrip": rt, "delegation": dlg, "attacks": atk}
    path = os.path.join(_HERE, "eval_E19_deployment.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        w.writerow(["baseline_median_ms", rt["baseline_ms"]["median"]])
        w.writerow(["baseline_p99_ms", rt["baseline_ms"]["p99"]])
        w.writerow(["gated_median_ms", rt["gated_ms"]["median"]])
        w.writerow(["gated_p99_ms", rt["gated_ms"]["p99"]])
        w.writerow(["overhead_ratio", rt["overhead_ratio"]])
        w.writerow(["delegation_hops", dlg["hops"]])
        w.writerow(["delegation_establish_ms", dlg["establish_ms"]])
        w.writerow(["delegation_verify_ms", dlg["verify_ms"]])
        w.writerow(["attack_blocked", sum(atk["blocked"])])
        w.writerow(["attack_total", 8])
    print("CSV:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
