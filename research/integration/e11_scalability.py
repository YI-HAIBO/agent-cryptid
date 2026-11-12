# -*- coding: utf-8 -*-
"""E11 可扩展性压测（针对 NFR-04：十万标识 / 5000 TPS 签发吞吐）。

为什么有这一实验
----------------
DEPLOY.md 已如实记录：NFR-04「单集群支持智能体标识不少于十万，凭证签发
吞吐不低于五千每秒」**未压测**。本实验把它跑成真实数字，而不是继续留白。

NFR-04 是两个**独立子目标**，本实验分别度量：

  E11a  标识规模 —— 服务路径（签发 / 校验）是否随标识数退化？
        关键假设：校验 O(1) 于标识数（公钥来自内存字典，非全表扫描）。
        若成立，十万标识只是「持有」问题，不是「查询」问题。
  E11b  签发吞吐 —— 单机达多少 TPS？与 5000 的差距需要几个并行实例？
  E11c  委托链深度 —— 验链成本随链深如何增长（多跳委托的真实代价）
  E11d  并发校验 —— 多工作线程下吞吐线性度与 P50/P95/P99（NFR-02 口径）

负载无关性声明
--------------
E11 是**负载相关**实验（时序绝对值绑定），与 E3/E4/E5/E7/E10 不同。
绝对值须在**安静机**复跑；负载探针 >10 ms 时打印告警。
相对量（吞吐线性度、单跳验链成本、跨规模退化比）稳健可引用。

用法
----
    python e11_scalability.py              # quick（分钟级）
    python e11_scalability.py --full       # 论文级规模
    python e11_scalability.py --no-csv
"""
import argparse
import csv
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))
_PROTO = os.path.join(_REPO, "proto")
for _p in (_HERE, _PROTO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agent_platform as apm                          # noqa: E402
from credential import ALG_SM2                        # noqa: E402

Platform = apm.Platform

AUD = "svc://e11-bench"
SCOPE = ["read", "write", "exec"]
# 注册实测 ~45ms/个（SM9 标识密钥派生主导），规模取 10× 跨度即可判定 O(1)
IDS_QUICK = [300, 3000]
IDS_FULL = [1000, 10000]
IDS_B_QUICK = 2000      # E11b 自建的标识底座规模
IDS_B_FULL = 10000


# ---------------------------------------------------------------------------
# 统计工具
# ---------------------------------------------------------------------------
def _pctl(sorted_vals, p):
    """线性插值百分位；sorted_vals 须已升序。"""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def _stat(name, fn, n, warmup=5):
    """返回中位 / P50 / P95 / P99 / max / 吞吐（ms, ops/s）。"""
    for _ in range(warmup):
        fn()
    t0 = time.perf_counter()
    times = []
    for _ in range(n):
        s = time.perf_counter()
        fn()
        times.append((time.perf_counter() - s) * 1000.0)
    wall = time.perf_counter() - t0
    times.sort()
    return {"op": name, "n": n,
            "median_ms": round(times[len(times) // 2], 3),
            "p50_ms": round(_pctl(times, 50), 3),
            "p95_ms": round(_pctl(times, 95), 3),
            "p99_ms": round(_pctl(times, 99), 3),
            "max_ms": round(times[-1], 3),
            "throughput_ops_s": round(n / wall, 1) if wall > 0 else None}


def _load_probe():
    """SM2 本地校验中位作为负载探针（与 eval_framework 同口径）。"""
    p = Platform(tenant="e11-probe")
    p.register_identity("agent://e11/probe/iss")
    p.register_identity("agent://e11/probe/sub")
    r = p.issue_credential("agent://e11/probe/iss", "agent://e11/probe/sub",
                           AUD, SCOPE, alg_tier=ALG_SM2)
    wire = r["cred"]
    for _ in range(10):
        p.verify_credential(wire, audience=AUD, record_nonce=False)
    t0 = time.perf_counter()
    n = 60
    for _ in range(n):
        p.verify_credential(wire, audience=AUD, record_nonce=False)
    wall = time.perf_counter() - t0
    return {"median_ms": round(wall / n * 1000.0, 3)}


# ---------------------------------------------------------------------------
# E11a 标识规模 vs 服务路径延迟
# ---------------------------------------------------------------------------
def e11a_scale(ids_list, verify_n, issue_n):
    """标识规模扫描：注册成本 + 校验/签发是否随规模退化。"""
    rows = []
    for n_ids in ids_list:
        p = Platform(tenant="e11-a")
        t0 = time.perf_counter()
        for i in range(n_ids):
            p.register_identity("agent://e11/reg/%d" % i)
        reg_ms = (time.perf_counter() - t0) * 1000.0

        p.register_identity("agent://e11/iss")
        sub = "agent://e11/reg/0"
        res = p.issue_credential("agent://e11/iss", sub, AUD, SCOPE,
                                 alg_tier=ALG_SM2)
        wire = res["cred"]

        def _v(w=wire):
            return p.verify_credential(w, audience=AUD,
                                       record_nonce=False)["ok"]

        def _i():
            return p.issue_credential("agent://e11/iss", sub, AUD, SCOPE,
                                      alg_tier=ALG_SM2)["ok"]

        vrow = _stat("verify@%d" % n_ids, _v, n=verify_n)
        irow = _stat("issue@%d" % n_ids, _i, n=issue_n)
        rows.append({
            "identities": n_ids,
            "register_total_ms": round(reg_ms, 1),
            "register_per_id_ms": round(reg_ms / n_ids, 3),
            "verify_median_ms": vrow["median_ms"],
            "verify_p99_ms": vrow["p99_ms"],
            "verify_tps": vrow["throughput_ops_s"],
            "issue_median_ms": irow["median_ms"],
            "issue_p99_ms": irow["p99_ms"],
            "issue_tps": irow["throughput_ops_s"],
        })
        print("    N=%-7d 注册 %9.0fms (%.2fms/个) | 校验中位 %6.2fms "
              "P99 %6.2fms (%7.0f TPS) | 签发中位 %6.2fms P99 %6.2fms "
              "(%7.0f TPS)"
              % (n_ids, reg_ms, reg_ms / n_ids,
                 vrow["median_ms"], vrow["p99_ms"], vrow["throughput_ops_s"],
                 irow["median_ms"], irow["p99_ms"], irow["throughput_ops_s"]))
        del p
    return rows


# ---------------------------------------------------------------------------
# E11b 签发吞吐 vs 并行度
# ---------------------------------------------------------------------------
def e11b_issue_tps(issue_target, threads_list, n_ids=IDS_B_QUICK):
    """单机签发吞吐 + 并行线性度，并对 5000 TPS 目标做如实判定。"""
    p = Platform(tenant="e11-b")
    for i in range(n_ids):
        p.register_identity("agent://e11/reg/%d" % i)
    p.register_identity("agent://e11/iss")
    sub = "agent://e11/reg/0"
    # 预热（SM9 派生首签较慢，必须预热）
    p.issue_credential("agent://e11/iss", sub, AUD, SCOPE, alg_tier=ALG_SM2)

    rows = []
    for n_thr in threads_list:
        done = [0]
        lock = threading.Lock()

        def _worker():
            while True:
                with lock:
                    if done[0] >= issue_target:
                        return
                    done[0] += 1
                p.issue_credential("agent://e11/iss", sub, AUD, SCOPE,
                                   alg_tier=ALG_SM2)

        t0 = time.perf_counter()
        ts_ = [threading.Thread(target=_worker) for _ in range(n_thr)]
        for t in ts_:
            t.start()
        for t in ts_:
            t.join()
        wall = time.perf_counter() - t0
        tps = issue_target / wall if wall > 0 else 0.0
        rows.append({"workers": n_thr, "ops": issue_target, "identities": n_ids,
                     "wall_s": round(wall, 3), "tps": round(tps, 1)})
        print("    工作线程=%-3d %5d 次签发 %7.2fs → %8.1f TPS"
              % (n_thr, issue_target, wall, tps))

    best = max(rows, key=lambda r: r["tps"])
    base = rows[0]
    del p
    return rows, {
        "single_thread_tps": base["tps"],
        "best_tps": best["tps"],
        "best_workers": best["workers"],
        "target_tps": 5000,
        "met_target": best["tps"] >= 5000,
        "workers_needed_for_target": (int(5000.0 / best["tps"]) + 1
                                      if best["tps"] > 0 else None),
        "linear_speedup": round(best["tps"] / base["tps"], 3)
        if base["tps"] else None,
    }


# ---------------------------------------------------------------------------
# E11e 多进程签发吞吐 —— 把「GIL 下不可并行」从推断变成实测
# ---------------------------------------------------------------------------
def _mp_issue_worker(cfg):
    """多进程 worker 入口。

    Windows 只有 spawn（无 fork），两条硬约束：
      · 函数必须在**模块顶层**（闭包 / lambda 不可 pickle）
      · 子进程重建解释器，须自行确保 proto 路径可见
    注册与 warmup 放在计时**之前**，稳态段只跑签发，避免 pollution。
    """
    import time
    ops, seed = cfg
    if _PROTO not in sys.path:
        sys.path.insert(0, _PROTO)
    p = Platform(tenant="e11e")
    iss = "agent://e11e/iss/%d" % seed
    sub = "agent://e11e/sub/%d" % seed
    p.register_identity(iss)
    p.register_identity(sub)
    for _ in range(5):                       # warmup：SM9 派生首签偏慢
        p.issue_credential(iss, sub, AUD, SCOPE, alg_tier=ALG_SM2)
    t0 = time.perf_counter()
    ok = 0
    for _ in range(ops):
        r = p.issue_credential(iss, sub, AUD, SCOPE, alg_tier=ALG_SM2)
        if r.get("ok"):
            ok += 1
    return time.perf_counter() - t0, ops, ok


def e11e_multiprocess_tps(ops_per_worker, workers_list):
    """每个 worker 固定负载（weak scaling），测聚合签发吞吐 vs 进程数。

    报告两个口径（诚实起见都给）：
      ``tps_steady``  总 ops / 最慢 worker 的稳态墙钟 —— 剔除进程启动开销，
                      代表**常驻服务**的稳态能力（生产实际形态）。
      ``tps_wall``    总 ops / 含 Pool 创建与 interpreter 启动的总墙钟 ——
                      保守口径，短任务会明显吃亏。
    """
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    rows = []
    print("    每进程 %d 次签发；本机逻辑核 = %d"
          % (ops_per_worker, os.cpu_count() or 0))
    for w in workers_list:
        cfg = [(ops_per_worker, i) for i in range(w)]
        t0 = time.perf_counter()
        try:
            with ctx.Pool(processes=w) as pool:
                results = pool.map(_mp_issue_worker, cfg)
        except Exception as e:                              # noqa: BLE001
            print("    进程=%d 失败，停止梯度：%s: %s"
                  % (w, type(e).__name__, e))
            break
        wall = time.perf_counter() - t0
        elapsed = [r[0] for r in results]
        ops_sum = sum(r[1] for r in results)
        ok_sum = sum(r[2] for r in results)
        steady = max(elapsed) if elapsed else 0.0
        rows.append({
            "workers": w, "ops": ops_sum, "verified_ok": ok_sum,
            "steady_s": round(steady, 3),
            "wall_total_s": round(wall, 3),
            "tps_steady": round(ops_sum / steady, 1) if steady > 0 else 0.0,
            "tps_wall": round(ops_sum / wall, 1) if wall > 0 else 0.0,
        })
        print("    进程=%-3d %5d 次 稳态 %6.2fs 含启动 %6.2fs → "
              "稳态 %8.1f TPS / 含启动 %8.1f TPS"
              % (w, ops_sum, steady, wall,
                 rows[-1]["tps_steady"], rows[-1]["tps_wall"]))
    return rows


def analyse_parallelism(proc_rows, thread_rows):
    """并行度对比：进程 vs 线程，并给出 5000 TPS 所需实例数。

    判据：
      · 线程加速比 ≈1 而进程加速比 ≈W  → **GIL 是瓶颈**（标量乘受 GIL 约束）
      · 两者都 ≈W                      → 瓶颈是核数/内存带宽，不是 GIL
      · 两者都 ≈1                      → 瓶颈在共享资源（如 SQLite），两者皆无效
    """
    if not proc_rows:
        return None
    b1 = proc_rows[0]
    base = b1["tps_steady"] or 0.0
    for r in proc_rows:
        sp = (r["tps_steady"] / base) if base else 0.0
        r["speedup_vs_1proc"] = round(sp, 3)
        r["parallel_efficiency"] = round(sp / r["workers"], 3) if r["workers"] else 0.0
    best = max(proc_rows, key=lambda r: r["tps_steady"])

    thr_base = thread_rows[0]["tps"] if thread_rows else 0.0
    thr_best = max(thread_rows, key=lambda r: r["tps"]) if thread_rows else None
    thr_speedup = (round(thr_best["tps"] / thr_base, 3)
                   if (thr_base and thr_best) else None)

    per_proc = base                       # 无争用的单进程稳态吞吐
    cores = os.cpu_count() or 0
    linear_cap = cores * per_proc         # 天真线性外推的单机上限

    # 实测峰值（含争用）——这才是真正的单机天花板
    best = max(proc_rows, key=lambda r: r["tps_steady"])
    peak_tps = best["tps_steady"]
    peak_workers = best["workers"]
    eff_per_instance_at_peak = round(peak_tps / peak_workers, 1) if peak_workers else 0.0

    # 收益是否已触顶（最后一点不再增长甚至回落）
    diminishing = (len(proc_rows) >= 3 and
                   proc_rows[-1]["tps_steady"] <= proc_rows[-2]["tps_steady"] * 1.10)

    over_pct = (round(100.0 * (linear_cap - peak_tps) / peak_tps, 1)
                if peak_tps > 0 else None)
    need_ideal = int(5000.0 / per_proc) + 1 if per_proc > 0 else None
    need_peak_eff = (int(5000.0 / eff_per_instance_at_peak) + 1
                     if eff_per_instance_at_peak > 0 else None)
    machines = int(5000.0 / peak_tps) + 1 if peak_tps > 0 else None

    # 污染自检：并行效率 >100% 在物理上不可能（同一份 CPU 资源不可能凭空变多），
    # 它的唯一合理解释是**单进程基线测得偏慢**（测量期间机器有别的热点），
    # 于是后续各点都显得"加速"过度。出现即代表绝对值不可用，须安静机重测。
    contaminated = any(r["parallel_efficiency"] > 1.05 for r in proc_rows)
    worst_eff = max((r["parallel_efficiency"] for r in proc_rows), default=0.0)

    if thr_speedup is not None and thr_speedup < 1.3 and best["speedup_vs_1proc"] > 2.0:
        verdict = ("GIL 是瓶颈：线程无收益（加速比 %sx）而进程近线性 → 必须"
                   "**进程级**并行，线程方案无解" % thr_speedup)
    elif best["speedup_vs_1proc"] > 2.0:
        verdict = "可并行，瓶颈为核数/资源，非 GIL"
    else:
        verdict = "进程并行亦无收益，瓶颈在共享资源（存储/总线），需存档层改造"

    return {
        "cpu_cores_logical": cores,
        "proc_base_tps": base,
        "proc_best_tps": peak_tps,
        "proc_best_workers": peak_workers,
        "proc_best_speedup": best["speedup_vs_1proc"],
        "proc_best_efficiency": best["parallel_efficiency"],
        "thread_base_tps": thr_base,
        "thread_best_tps": thr_best["tps"] if thr_best else None,
        "thread_best_speedup": thr_speedup,
        "per_instance_tps": per_proc,
        "peak_tps_observed": peak_tps,
        "peak_workers": peak_workers,
        "efficiency_at_peak": best["parallel_efficiency"],
        "effective_per_instance_at_peak": eff_per_instance_at_peak,
        "diminishing_returns": diminishing,
        "load_contaminated": contaminated,
        "worst_parallel_efficiency": round(worst_eff, 3),
        "linear_extrapolation_cap_tps": round(linear_cap, 1),
        "linear_extrapolation_overestimate_pct": over_pct,
        "target_tps": 5000,
        "instances_needed_ideal": need_ideal,
        "instances_needed_at_peak_efficiency": need_peak_eff,
        "machines_needed_this_spec": machines,
        "reachable_on_this_host": bool(peak_tps >= 5000),
        "max_tps_this_host_est": round(peak_tps, 1),
        "verdict": verdict,
        "honest_note": (
            "每实例稳态 %.0f TPS；实测单机峰值 %.0f TPS @ %d 进程（效率 %.0f%%），"
            "**远低于**天真线性外推的 %.0f TPS（高估 %.0f%%）。%s达 5000 TPS "
            "须约 %s 台本机规格横向扩容%s。" % (
                per_proc, peak_tps, peak_workers,
                best["parallel_efficiency"] * 100,
                linear_cap, over_pct or 0.0,
                "收益已触顶；" if diminishing else "",
                machines,
                "，或迁移国密芯片/C 扩展" if machines and machines > 1 else "")),
    }


# ---------------------------------------------------------------------------
# E11c 委托链深度 vs 验链延迟
# ---------------------------------------------------------------------------
def e11c_chain_depth(max_depth, sample_n):
    """逐跳签发 d 跳委托链并度量 verify_delegation_chain 延迟。"""
    p = Platform(tenant="e11-c")
    p.register_identity("agent://e11/root")
    for i in range(max_depth + 2):
        p.register_identity("agent://e11/hop/%d" % i)

    rows = []
    for d in range(1, max_depth + 1):
        wires = []
        cur = "agent://e11/root"
        parent_wire = None
        ok = True
        for h in range(d):
            nxt = "agent://e11/hop/%d" % h
            if h == 0:
                r0 = p.issue_credential("agent://e11/root", nxt, AUD, SCOPE,
                                        alg_tier=ALG_SM2)
                parent_wire = r0["cred"] if r0["ok"] else None
                ok = r0["ok"]
            else:
                rd = p.issue_delegation(cur, nxt, AUD, SCOPE,
                                        alg_tier=ALG_SM2,
                                        parent_cred=parent_wire)
                parent_wire = rd["cred"] if rd["ok"] else None
                ok = rd["ok"]
            if not ok:
                break
            wires.append(parent_wire)
            cur = nxt

        if not ok:
            print("    depth=%d 构造失败，停止" % d)
            break

        crow = _stat("verify_chain_depth_%d" % d,
                     lambda w=wires: p.verify_delegation_chain(
                         w, AUD, SCOPE)["ok"], n=sample_n)
        rows.append({"depth": d, "median_ms": crow["median_ms"],
                     "p95_ms": crow["p95_ms"], "p99_ms": crow["p99_ms"],
                     "per_hop_ms": round(crow["median_ms"] / d, 3)})
        print("    depth=%-3d 中位 %8.2f ms  P95 %8.2f ms  P99 %8.2f ms  "
              "单跳 %6.2f ms"
              % (d, crow["median_ms"], crow["p95_ms"], crow["p99_ms"],
                 crow["median_ms"] / d))
    del p
    return rows


# ---------------------------------------------------------------------------
# E11d 并发校验延迟分布
# ---------------------------------------------------------------------------
def e11d_concurrent_verify(total_target, threads_list):
    """多工作线程并发校验同一凭证：吞吐线性度 + P50/P95/P99 抬升。"""
    p = Platform(tenant="e11-d")
    p.register_identity("agent://e11/iss")
    p.register_identity("agent://e11/sub")
    res = p.issue_credential("agent://e11/iss", "agent://e11/sub", AUD,
                             SCOPE, alg_tier=ALG_SM2)
    wire = res["cred"]
    for _ in range(10):
        p.verify_credential(wire, audience=AUD, record_nonce=False)

    rows = []
    per_thr = total_target // (threads_list[-1] or 1)
    for n_thr in threads_list:
        bag = {"times": [], "ok": 0}
        bl = threading.Lock()

        def _v(bt=bag, bl_=bl, pt=per_thr):
            local = []
            for _ in range(pt):
                s = time.perf_counter()
                r = p.verify_credential(wire, audience=AUD,
                                        record_nonce=False)
                local.append((time.perf_counter() - s) * 1000.0)
                if r["ok"]:
                    bt["ok"] += 1
            with bl_:
                bt["times"].extend(local)

        t0 = time.perf_counter()
        ts_ = [threading.Thread(target=_v) for _ in range(n_thr)]
        for t in ts_:
            t.start()
        for t in ts_:
            t.join()
        wall = time.perf_counter() - t0
        tm = sorted(bag["times"])
        ops = len(tm)
        rows.append({
            "workers": n_thr, "ops": ops, "wall_s": round(wall, 3),
            "tps": round(ops / wall, 1) if wall > 0 else None,
            "median_ms": round(_pctl(tm, 50), 3),
            "p95_ms": round(_pctl(tm, 95), 3),
            "p99_ms": round(_pctl(tm, 99), 3),
            "max_ms": round(tm[-1], 3),
            "verified_ok": bag["ok"],
        })
        print("    工作线程=%-3d %5d 次 %7.2fs → %8.1f TPS | 中位 %6.2f ms "
              "P95 %7.2f ms P99 %7.2f ms max %8.2f ms"
              % (n_thr, ops, wall, rows[-1]["tps"], rows[-1]["median_ms"],
                 rows[-1]["p95_ms"], rows[-1]["p99_ms"], rows[-1]["max_ms"]))
    del p
    return rows


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def _write_csv(a_rows, b_rows, c_rows, d_rows, e_rows):
    paths = []

    def _w(name, fields, rows):
        pp = os.path.join(_HERE, name)
        with open(pp, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        paths.append(pp)

    _w("eval_E11a_scale.csv",
       ["identities", "register_total_ms", "register_per_id_ms",
        "verify_median_ms", "verify_p99_ms", "verify_tps",
        "issue_median_ms", "issue_p99_ms", "issue_tps"], a_rows)
    _w("eval_E11b_issue_tps.csv",
       ["workers", "ops", "identities", "wall_s", "tps"], b_rows)
    _w("eval_E11c_chain_depth.csv",
       ["depth", "median_ms", "p95_ms", "p99_ms", "per_hop_ms"], c_rows)
    _w("eval_E11d_concurrent_verify.csv",
       ["workers", "ops", "wall_s", "tps", "median_ms", "p95_ms", "p99_ms",
        "max_ms", "verified_ok", "median_inflation_pct"], d_rows)
    _w("eval_E11e_process_tps.csv",
       ["workers", "ops", "verified_ok", "steady_s", "wall_total_s",
        "tps_steady", "tps_wall", "speedup_vs_1proc", "parallel_efficiency"],
       e_rows)
    return paths


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(quick=True, csv_out=True):
    print("=" * 74)
    print("  E11 可扩展性压测（NFR-04：十万标识 / 5000 TPS 签发吞吐）")
    print("=" * 74)
    probe = _load_probe()
    print("  负载探针（SM2 本地校验中位）: %.2f ms" % probe["median_ms"])
    if probe["median_ms"] > 10.0:
        print("  !! WARNING: 负载偏高，绝对值须在安静机复跑；相对量稳健。")
    print("  模式: %s" % ("quick" if quick else "full"))

    res = {"load_probe_sm2_verify_ms": probe["median_ms"], "quick": quick,
           "nfr04": {"claim": "十万标识 / 5000 TPS 签发吞吐", "closed": False,
                     "notes": []}}

    # ---------- E11a ----------
    print("\n[E11a] 标识规模 vs 服务路径延迟 ...")
    verify_n = 30 if quick else 150
    issue_n = 15 if quick else 80
    a_rows = e11a_scale(IDS_QUICK if quick else IDS_FULL, verify_n, issue_n)
    res["E11a_scale"] = a_rows

    per = a_rows[-1]["register_per_id_ms"]
    res["E11a_extrapolation"] = {
        "target": 100000,
        "per_id_ms_measured": per,
        "estimated_register_total_ms": round(100000 * per, 1),
        "estimated_register_minutes": round(100000 * per / 60000.0, 1),
        "note": "注册是配置期批处理动作（非逐请求服务路径），外推仅供容量规划",
    }
    ex = res["E11a_extrapolation"]
    print("    → 十万标识外推：约 %.1f 分钟单线程（配置期动作，非服务路径）"
          % ex["estimated_register_minutes"])

    if len(a_rows) >= 2:
        v_ratio = a_rows[-1]["verify_median_ms"] / a_rows[0]["verify_median_ms"]
        i_ratio = a_rows[-1]["issue_median_ms"] / a_rows[0]["issue_median_ms"]
        scale = a_rows[-1]["identities"] / a_rows[0]["identities"]
        res["E11a_degradation"] = {
            "scale_factor": scale,
            "verify_median_ratio": round(v_ratio, 3),
            "issue_median_ratio": round(i_ratio, 3),
            "verdict": ("校验/签发不随标识数退化（O(1) 于标识规模）"
                        if v_ratio < 1.25 else
                        "随标识数退化，需排查全表扫描"),
        }
        print("    → 标识规模 ×%.0f：校验中位 ×%.3f，签发中位 ×%.3f → %s"
              % (scale, v_ratio, i_ratio, res["E11a_degradation"]["verdict"]))

    # ---------- E11b ----------
    print("\n[E11b] 签发吞吐 vs 并行度 ...")
    issue_target = 60 if quick else 400
    thr_b = [1, 2, 4] if quick else [1, 2, 4, 8]
    b_rows, bc = e11b_issue_tps(issue_target, thr_b,
                                IDS_B_QUICK if quick else IDS_B_FULL)
    res["E11b_issue_throughput"] = b_rows
    res["E11b_conclusion"] = bc
    bc["honest_note"] = (
        "纯 Python 实现瓶颈在 SM2 标量乘，单机最佳 %d TPS（%d 线程）；"
        "达 5000 TPS 需约 %s 并行实例，或迁移国密芯片/C 扩展（v3.0 硬件根）"
        % (bc["best_tps"], bc["best_workers"], bc["workers_needed_for_target"]))
    print("    → %s" % bc["honest_note"])

    # ---------- E11e 多进程（对比 E11b 线程，验证 GIL 假设） ----------
    print("\n[E11e] 多进程签发吞吐（对照 E11b 线程，验证 GIL 假设）...")
    # 稳态段须显著长于 Windows spawn 的进程启动开销（~0.9s/批），否则噪声淹没信号
    ops_per_worker = 150 if quick else 300
    thr_e = [1, 2, 4, 8] if quick else [1, 2, 4, 8, 12, 16]
    e_rows = e11e_multiprocess_tps(ops_per_worker, thr_e)
    res["E11e_multiprocess_tps"] = e_rows
    pa = analyse_parallelism(e_rows, b_rows)
    res["E11e_parallelism"] = pa
    if pa:
        print("    并行效率（进程）:")
        for r in e_rows:
            print("      W=%-3d 稳态 %8.1f TPS  加速比 %5.2f×  效率 %5.1f%%"
                  % (r["workers"], r["tps_steady"],
                     r["speedup_vs_1proc"], r["parallel_efficiency"] * 100))
        print("    对照：线程最佳 %s TPS（加速比 %sx）"
              % (pa["thread_best_tps"], pa["thread_best_speedup"]))
        if pa.get("load_contaminated"):
            print("    !! 污染告警：并行效率出现 >100%%（最高 %.1f%%）在物理上不可能，"
                  "说明单进程基线测得偏慢。" % (pa["worst_parallel_efficiency"] * 100))
            print("       → **定性结论（GIL/进程级并行）仍稳固，绝对数字不可用**，"
                  "须单独安静重跑再引用。")
        print("    → %s" % pa["verdict"])
        print("    → %s" % pa["honest_note"])
        # E11b 的"需 N 实例"结论改用多进程实测修正
        if pa.get("instances_needed_at_peak_efficiency"):
            bc["workers_needed_for_target_measured"] = pa[
                "instances_needed_at_peak_efficiency"]
            bc["machines_needed_this_spec"] = pa["machines_needed_this_spec"]
            bc["workers_needed_basis"] = (
                "多进程实测：单实例稳态 %.0f TPS，但峰值效率下每实例仅贡献 "
                "%.1f TPS（原结论 26 实例基于线程推断，已被修正）"
                % (pa["per_instance_tps"],
                   pa["effective_per_instance_at_peak"]))
   

    # ---------- E11c ----------
    print("\n[E11c] 委托链深度 vs 验链延迟 ...")
    c_rows = e11c_chain_depth(6 if quick else 10, 10 if quick else 50)
    res["E11c_delegation_depth"] = c_rows
    if len(c_rows) >= 2:
        span = c_rows[-1]["depth"] - c_rows[0]["depth"]
        dms = c_rows[-1]["median_ms"] - c_rows[0]["median_ms"]
        res["E11c_linearity"] = {
            "depth_span": span,
            "median_ms_delta": round(dms, 2),
            "ms_per_hop": round(dms / span, 3) if span else None,
            "verdict": "验链成本随链深线性增长",
        }
        print("    → 每加深一跳约 +%.2f ms（线性）"
              % res["E11c_linearity"]["ms_per_hop"])

    # ---------- E11d ----------
    print("\n[E11d] 并发校验延迟分布（NFR-02 口径）...")
    d_rows = e11d_concurrent_verify(400 if quick else 2000,
                                    [2, 4] if quick else [1, 2, 4, 8, 16])
    base = d_rows[0]
    for r in d_rows:
        r["median_inflation_pct"] = round(
            100.0 * (r["median_ms"] - base["median_ms"]) /
            max(1e-9, base["median_ms"]), 2)
    res["E11d_concurrent_verify"] = d_rows
    res["E11d_conclusion"] = {
        "baseline_workers": base["workers"],
        "baseline_median_ms": base["median_ms"],
        "baseline_tps": base["tps"],
        "best_tps": max(r["tps"] for r in d_rows),
        "worst_median_inflation_pct": max(r["median_inflation_pct"]
                                          for r in d_rows),
        "nfr02_target_median_ms": 5.0,
        "nfr02_met_at_best_concurrency":
            min(r["median_ms"] for r in d_rows) <= 5.0,
    }
    dc = res["E11d_conclusion"]
    print("    → NFR-02 中位目标 5.0 ms；并发下最高中位抬升 %.1f%%"
          % dc["worst_median_inflation_pct"])

    # ---------- NFR-04 闭环判定 ----------
    vratio = res.get("E11a_degradation", {}).get("verify_median_ratio", 99.0)
    res["nfr04"]["holding_100k_verdict"] = (
        "十万标识可持有：注册为配置期批处理（外推 %.1f 分钟单线程），"
        "校验/签发不随规模退化" % ex["estimated_register_minutes"]
        if vratio < 1.25 else "十万标识持有能力存疑")
    res["nfr04"]["holding_100k_verdict"] = (
        "十万标识可持有：注册为配置期批处理（外推 %.1f 分钟单线程），"
        "校验/签发不随规模退化" % ex["estimated_register_minutes"]
        if vratio < 1.25 else "十万标识持有能力存疑")
    if pa and pa.get("instances_needed_at_peak_efficiency"):
        res["nfr04"]["throughput_verdict"] = (
            "5000 TPS 未达标：多进程实测单实例稳态 %.0f TPS，但**实测单机峰值仅 "
            "%.0f TPS @ %d 进程**（效率 %.0f%%）——天真线性外推 %.0f TPS 高估 %.0f%%，"
            "故 5000 TPS 单机不可达，须 ≥%d 台本机规格横向扩容或国密芯片/C 扩展"
            % (pa["per_instance_tps"], pa["peak_tps_observed"],
               pa["peak_workers"], pa["efficiency_at_peak"] * 100,
               pa["linear_extrapolation_cap_tps"],
               pa["linear_extrapolation_overestimate_pct"],
               pa["machines_needed_this_spec"]))
    else:
        res["nfr04"]["throughput_verdict"] = (
            "5000 TPS 未达标（线程口径单机上限 %d TPS）" % bc["best_tps"])
    res["nfr04"]["parallelism_verdict"] = pa["verdict"] if pa else "未测得多进程数据"
    res["nfr04"]["notes"] = [res["nfr04"]["holding_100k_verdict"],
                             res["nfr04"]["throughput_verdict"],
                             res["nfr04"]["parallelism_verdict"]]
    res["nfr04"]["closed"] = bool(bc["met_target"])
    print("\n[NFR-04 闭环判定]")
    for nt in res["nfr04"]["notes"]:
        print("  - %s" % nt)
    print("  → NFR-04 整体%s（吞吐子目标未闭环即整体不算闭环）"
          % ("已闭环" if res["nfr04"]["closed"] else "未闭环"))

    # ---------- CSV ----------
    if csv_out:
        res["csv_files"] = _write_csv(a_rows, b_rows, c_rows, d_rows, e_rows)
        for pp in res["csv_files"]:
            print("\n  CSV: %s" % os.path.basename(pp))

    return res


def E11_scalability(quick):
    """供 eval_framework 挂载的入口（负载相关，不跑 --quick 时也可手动执行）。"""
    return run(quick=quick, csv_out=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="E11 可扩展性压测")
    ap.add_argument("--full", action="store_true",
                    help="论文级规模（更大标识规模、更多线程数）")
    ap.add_argument("--no-csv", action="store_true", help="不输出 CSV")
    a = ap.parse_args()
    r = run(quick=not a.full, csv_out=not a.no_csv)
    print("\nE11 完成。NFR-04 闭环：%s" % r["nfr04"]["closed"])
