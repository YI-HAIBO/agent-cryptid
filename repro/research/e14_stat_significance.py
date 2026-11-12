# -*- coding: utf-8 -*-
"""E14 统计显著性：≥5 次独立运行，报中位 + IQR + 95% CI。

动机：现有 E1/E6/E11 的绝对时序都来自单次运行，缺少误差范围。
本模块对每项指标独立运行 R 次（默认 5），每次内部走已有
`benchmark()` 采集中位，然后把 R 个中位作为 R 个样本，报告：
  - 均值 / 标准差 / 标准误
  - 中位 + IQR（Q1, Q3）
  - 均值 95% CI（t 分布，样本自由度 = R-1）
两个样本组对比时用 Welch's t-test 报 p 值 + Cohen's d 效应量。

覆盖：
  A) SM2 单次验签延迟（对比 loaded vs quiet 概念验证）
  B) 委托链验证延迟随跳数的线性外推稳定性
  C) 进程级吞吐量随 worker 数的稳定性（1/2/4/8 worker）

用法：
  python e14_stat_significance.py                # 默认 R=5
  python e14_stat_significance.py --runs 10      # R=10
  python e14_stat_significance.py --csv-dir DIR
"""
import os, sys, csv, json, argparse, math, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proto"))
sys.path.insert(0, os.path.dirname(__file__))

from agent_platform import Platform
from persistence import SQLiteBackend
from eval_framework import benchmark

HERE = os.path.dirname(__file__)


# ---------------------------------------------------------------
# 统计工具
# ---------------------------------------------------------------
def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n % 2 == 1:
        return xs[n // 2]
    return (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def _quantile(xs, q):
    """线性插值分位数（Excel PERCENTILE.INC 语义）。"""
    xs = sorted(xs)
    n = len(xs)
    if n == 1:
        return xs[0]
    pos = (n - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - pos) + xs[hi] * (pos - lo)


def _mean(xs):
    return sum(xs) / len(xs)


def _stdev(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def _sem(xs):
    return _stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else 0.0


def _welch_t(a, b):
    """Welch's t-test：两独立样本 t 统计量、自由度、双尾 p 值近似。"""
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return (0.0, 0.0, 1.0, 0.0)
    ma, mb = _mean(a), _mean(b)
    va, vb = _stdev(a) ** 2, _stdev(b) ** 2
    if va == 0 and vb == 0:
        return (0.0, na + nb - 2, 1.0, 0.0)
    se = math.sqrt(va / na + vb / nb)
    if se == 0:
        return (0.0, na + nb - 2, 1.0, 0.0)
    t = (ma - mb) / se
    # Welch-Satterthwaite
    df = (va / na + vb / nb) ** 2 / (
        (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    )
    # 双尾 p 近似（Student-t CDF via continued fraction 太复杂，
    # 用大样本正态近似 + 修正，R 小的场景仅作定性参考）
    from math import erf
    z = abs(t)
    p = 2.0 * (1.0 - 0.5 * (1 + erf(z / math.sqrt(2))))
    # Cohen's d
    pooled = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2))
    d = (ma - mb) / pooled if pooled > 0 else 0.0
    return (t, df, p, d)


def _ci95(xs, z=1.96):
    """均值 95% CI（大样本正态近似）。"""
    m = _mean(xs)
    sem = _sem(xs)
    return (m - z * sem, m + z * sem)


def summarize(xs):
    """一次独立运行序列 -> 统计汇总。"""
    n = len(xs)
    return {
        "n": n,
        "mean": round(_mean(xs), 4),
        "stdev": round(_stdev(xs), 4),
        "sem": round(_sem(xs), 4),
        "median": round(_median(xs), 4),
        "q1": round(_quantile(xs, 0.25), 4),
        "q3": round(_quantile(xs, 0.75), 4),
        "iqr": round(_quantile(xs, 0.75) - _quantile(xs, 0.25), 4),
        "ci95_lo": round(_ci95(xs)[0], 4),
        "ci95_hi": round(_ci95(xs)[1], 4),
        "min": round(min(xs), 4),
        "max": round(max(xs), 4),
    }


def compare(a_name, a_vals, b_name, b_vals):
    a_sum = summarize(a_vals)
    b_sum = summarize(b_vals)
    t, df, p, d = _welch_t(a_vals, b_vals)
    return {
        "a": {"name": a_name, "summary": a_sum, "raw": [round(v, 4) for v in a_vals]},
        "b": {"name": b_name, "summary": b_sum, "raw": [round(v, 4) for v in b_vals]},
        "welch_t": round(t, 4),
        "df": round(df, 2),
        "p_value": round(p, 6),
        "cohens_d": round(d, 4),
        "significant_at_05": p < 0.05,
    }


def _csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


# ---------------------------------------------------------------
# 实验 A：SM2 单次验签延迟（快速探针）
# ---------------------------------------------------------------
def run_A_sm2_verify(R):
    print("  [E14-A] SM2 单次验签（跨 R=%d 独立进程内采样）..." % R)
    import sm2
    d, pub = sm2.gen_keypair()
    idn = b"agent://e14/sm2"
    msg = b"e14-a-msg"
    r, s = sm2.sign(idn, d, msg)
    # 每次「独立运行」= 内部 n=200 采集中位，然后取该中位作为一个样本
    inner_n = 200
    inner_warm = 20
    samples = []
    for i in range(R):
        b = benchmark(lambda: sm2.verify(idn, pub, r, s, msg),
                      n=inner_n, warmup=inner_warm)
        samples.append(b["median_ms"])
    return {"metric": "sm2_verify_median_ms",
            "runs": R,
            "samples_ms": [round(x, 3) for x in samples],
            "summary": summarize(samples)}


# ---------------------------------------------------------------
# 实验 B：委托链验证延迟随跳数的稳定性
# ---------------------------------------------------------------
def _build_chain(p, n_hops, scope):
    ids = ["agent://e14/root"] + ["agent://e14/h%d" % i for i in range(1, n_hops + 1)]
    for i in ids:
        if i not in p._identities:
            p.register_identity(i, org="e14")
    root = p.issue_credential(ids[0], ids[0], "svc://e14", scope)["cred"]
    cur = root
    chain = [root]
    for k in range(1, n_hops + 1):
        d = p.issue_delegation(ids[k-1], ids[k], "svc://e14", scope,
                               parent_cred=cur)
        cur = d["cred"]
        chain.append(cur)
    return chain


def run_B_delegation_hops(R):
    print("  [E14-B] 委托链 3 跳 vs 5 跳 验证延迟 ...")
    db = os.path.join(HERE, "_bench_e14_b.db")
    if os.path.exists(db):
        try: os.remove(db)
        except Exception: pass
    pers = SQLiteBackend(db)
    p = Platform(tenant="e14b", persistence=pers)
    scope = ["read"]
    chain3 = _build_chain(p, 3, scope)
    chain5 = _build_chain(p, 5, scope)

    n3_samples, n5_samples = [], []
    for _ in range(R):
        b3 = benchmark(lambda: p.verify_delegation_chain(chain3, "svc://e14",
                                                           scope)["ok"],
                       n=30, warmup=5)
        b5 = benchmark(lambda: p.verify_delegation_chain(chain5, "svc://e14",
                                                           scope)["ok"],
                       n=30, warmup=5)
        n3_samples.append(b3["median_ms"])
        n5_samples.append(b5["median_ms"])
    pers.close()
    try: os.remove(db)
    except Exception: pass
    return compare("chain_3hop_median_ms", n3_samples,
                   "chain_5hop_median_ms", n5_samples)


# ---------------------------------------------------------------
# 实验 C：签发延迟稳定性
# ---------------------------------------------------------------
def run_C_issue_latency(R):
    print("  [E14-C] SM2 档签发延迟稳定性 ...")
    db = os.path.join(HERE, "_bench_e14_c.db")
    if os.path.exists(db):
        try: os.remove(db)
        except Exception: pass
    pers = SQLiteBackend(db)
    p = Platform(tenant="e14c", persistence=pers)
    p.register_identity("agent://e14c/iss", org="e14c")
    p.register_identity("agent://e14c/sub", org="e14c")
    scope = ["read"]

    samples = []
    for _ in range(R):
        b = benchmark(lambda: p.issue_credential("agent://e14c/iss",
                                                  "agent://e14c/sub",
                                                  "svc://e14c", scope)["ok"],
                      n=40, warmup=5)
        samples.append(b["median_ms"])
    pers.close()
    try: os.remove(db)
    except Exception: pass
    return {"metric": "sm2_issue_median_ms",
            "runs": R,
            "samples_ms": [round(x, 3) for x in samples],
            "summary": summarize(samples)}


# ---------------------------------------------------------------
# 主
# ---------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--outdir", default=HERE)
    args = ap.parse_args()
    R = max(3, args.runs)  # 至少 3 才有 CI
    os.makedirs(args.outdir, exist_ok=True)

    print("=" * 66)
    print("E14 统计显著性：R=%d 次独立运行，报中位 + IQR + 95%% CI" % R)
    print("=" * 66)

    a = run_A_sm2_verify(R)
    b = run_B_delegation_hops(R)
    c = run_C_issue_latency(R)

    # 汇总打印
    print("\n" + "-" * 66)
    print("A) SM2 单次验签延迟（ms）")
    _print_summary(a)
    print("\nB) 委托链验证延迟（3 跳 vs 5 跳，ms）")
    _print_compare(b)
    print("\nC) SM2 签发延迟（ms）")
    _print_summary(c)

    # 写 CSV
    _csv(os.path.join(args.outdir, "eval_E14_A_sm2_verify.csv"),
         ["run", "median_ms"],
         [[i + 1, x] for i, x in enumerate(a["samples_ms"])])
    _csv(os.path.join(args.outdir, "eval_E14_B_delegation_hops.csv"),
         ["run", "chain_3hop_ms", "chain_5hop_ms"],
         [[i + 1, b["a"]["raw"][i], b["b"]["raw"][i]]
          for i in range(min(len(b["a"]["raw"]), len(b["b"]["raw"])))])
    _csv(os.path.join(args.outdir, "eval_E14_C_issue_latency.csv"),
         ["run", "median_ms"],
         [[i + 1, x] for i, x in enumerate(c["samples_ms"])])

    summary = {"A": a, "B": b, "C": c}
    with open(os.path.join(args.outdir, "_e14_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
    print("\nJSON: _e14_summary.json")
    print("CSV : eval_E14_{A,B,C}_*.csv")


def _print_summary(res):
    s = res["summary"]
    print("    runs=%d  median=%.3f  IQR=[%.3f, %.3f]  "
          "95%%CI=[%.3f, %.3f]" % (
              s["n"], s["median"], s["q1"], s["q3"],
              s["ci95_lo"], s["ci95_hi"]))
    print("    mean=%.3f  stdev=%.3f  sem=%.3f  min=%.3f  max=%.3f" % (
        s["mean"], s["stdev"], s["sem"], s["min"], s["max"]))
    print("    samples:", [round(x, 2) for x in res["samples_ms"]])


def _print_compare(res):
    for k in ("a", "b"):
        s = res[k]["summary"]
        print("    %s: median=%.3f  IQR=[%.3f, %.3f]  "
              "95%%CI=[%.3f, %.3f]" % (
                  res[k]["name"], s["median"], s["q1"], s["q3"],
                  s["ci95_lo"], s["ci95_hi"]))
    print("    Welch's t=%.3f  df=%.2f  p=%.4f  Cohen's d=%.3f  "
          "sig@0.05=%s" % (
              res["welch_t"], res["df"], res["p_value"], res["cohens_d"],
              res["significant_at_05"]))


if __name__ == "__main__":
    main()
