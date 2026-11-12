# -*- coding: utf-8 -*-
"""E11-e'/e''：并行瓶颈归因的**独立干净测量**（避免串行full的负载污染）。

为什么要独立跑
--------------
`e11_scalability.py --full` 串行的 E11a（注册 1.1 万个标识、GC 压力大）会把后续
E11b/E11e 的基线压低，表现为**并行效率 >100%**（物理不可能），即超线性加速这一
明确的污染信号。那时绝对值不可用。

本脚本只做两件轻量测量，**不带任何前置大负载**：

  E11e''  线程梯度（共享同一 Platform，同一解释器 → 受 GIL 约束）
  E11e'   进程梯度（每进程独立 Platform + 独立解释器 → 绕开 GIL）

两者在同一轮、同一台机器、同一 warmup 口径下对照，直接回答：
「5000 TPS 达不到的瓶颈到底是 GIL，还是核数，还是共享资源？」

用法
----
    python e11_clean_parallelism.py                  # 默认 medium 规模
    python e11_clean_parallelism.py --ops 300 --procs 1,2,4,8,12,16
    python e11_clean_parallelism.py --csv            # 输出 CSV

产物 CSV：`eval_E11e_clean_parallelism.csv`
"""
import argparse
import csv
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROTO = os.path.abspath(os.path.join(_HERE, "..", "..", "proto"))
for _p in (_HERE, _PROTO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import e11_scalability as E                            # noqa: E402

Platform = E.Platform
ALG_SM2 = E.ALG_SM2
AUD = E.AUD
SCOPE = E.SCOPE

CSV_PATH = os.path.join(_HERE, "eval_E11e_clean_parallelism.csv")


def _load_probe(n=80):
    """SM2 本地校验中位（与 eval_framework 同口径），>10ms 视为不安静。"""
    p = Platform(tenant="probe-clean")
    p.register_identity("agent://clean/iss")
    p.register_identity("agent://clean/sub")
    w = p.issue_credential("agent://clean/iss", "agent://clean/sub",
                           AUD, SCOPE, alg_tier=ALG_SM2)["cred"]
    for _ in range(15):
        p.verify_credential(w, audience=AUD, record_nonce=False)
    t0 = time.perf_counter()
    for _ in range(n):
        p.verify_credential(w, audience=AUD, record_nonce=False)
    return (time.perf_counter() - t0) / n * 1000.0


def _thread_rows(total_ops, threads_list):
    """线程梯度：固定总负载，复用 E11b 的共享 Platform 实现。"""
    rows, _bc = E.e11b_issue_tps(total_ops, threads_list, n_ids=2)
    return rows


def main():
    ap = argparse.ArgumentParser(description="E11 并行瓶颈干净测量")
    ap.add_argument("--ops", type=int, default=300,
                    help="每进程签发次数（进程组）；线程组用同样总量")
    ap.add_argument("--procs", default="1,2,4,8,12,16",
                    help="进程梯度，逗号分隔")
    ap.add_argument("--threads", default="1,2,4,8",
                    help="线程梯度，逗号分隔")
    ap.add_argument("--csv", action="store_true", help="输出 CSV")
    args = ap.parse_args()

    procs = [int(x) for x in args.procs.split(",") if x.strip()]
    threads = [int(x) for x in args.threads.split(",") if x.strip()]

    print("=" * 74)
    print("  E11 并行瓶颈归因（独立干净测量，无前置大负载）")
    print("=" * 74)
    probe = _load_probe()
    print("  负载探针（SM2 本地校验中位）: %.2f ms" % probe)
    if probe > 10.0:
        print("  !! 本机不安静（>10ms），绝对值须再复跑；相对结论仍可用。")
    else:
        print("  本机相对安静，绝对值可引用。")
    print("  本机逻辑核 = %d" % (os.cpu_count() or 0))

    print("\n[线程组] 共享 Platform（同一解释器，受 GIL 约束）")
    t_rows = _thread_rows(args.ops, threads)
    for r in t_rows:
        print("    线程=%-3d %5d 次 %6.2fs → %8.1f TPS"
              % (r["workers"], r["ops"], r["wall_s"], r["tps"]))

    print("\n[进程组] 每进程独立 Platform + 解释器（绕开 GIL）")
    p_rows = E.e11e_multiprocess_tps(args.ops, procs)

    print("\n[归因分析]")
    pa = E.analyse_parallelism(p_rows, t_rows)
    for k in ("cpu_cores_logical", "per_instance_tps", "peak_tps_observed",
              "peak_workers", "efficiency_at_peak", "proc_best_speedup",
              "thread_best_speedup", "diminishing_returns",
              "linear_extrapolation_cap_tps",
              "linear_extrapolation_overestimate_pct",
              "instances_needed_ideal",
              "instances_needed_at_peak_efficiency",
              "machines_needed_this_spec", "load_contaminated",
              "worst_parallel_efficiency"):
        print("  %-38s %s" % (k, pa.get(k)))
    print("  %-38s %s" % ("verdict", pa["verdict"]))
    print("  %-38s %s" % ("honest_note", pa["honest_note"]))
    if pa.get("load_contaminated"):
        print("\n  !! 仍检出污染（效率 >100%），请换更安静的时机复跑。")
    else:
        print("\n  未检出超线性污染，说明本轮数据自洽，绝对值可引用。")

    if args.csv:
        with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["kind", "workers", "ops", "steady_or_wall_s",
                        "tps", "note"])
            for r in t_rows:
                w.writerow(["thread", r["workers"], r["ops"], r["wall_s"],
                            r["tps"], "共享解释器，受 GIL 约束"])
            for r in p_rows:
                w.writerow(["process", r["workers"], r["ops"],
                            r["steady_s"], r["tps_steady"],
                            "独立解释器，绕开 GIL（稳态口径）"])
        print("\n  CSV: %s" % CSV_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
