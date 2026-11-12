# -*- coding: utf-8 -*-
"""E11-f：共享 SQLite 文件高并发瓶颈归因（NFR-04 未闭环子项）。

问题
----
E11e 的多进程梯度（`e11_scalability.py::_mp_issue_worker`）用
`Platform(tenant="e11e")` 且**不带 persistence**，即每个 worker 进程走默认
**内存存储**。因此 E11e 的 1008 TPS @ 16 进程**完全没有**共享 SQLite 文件，
隔离的是 CPU/GIL + 标量乘瓶颈。SQLite 单文件在高并发下是否成为**新瓶颈**
（记忆标注"仍未评估"）本脚本补齐。

方法
----
同一进程梯度 W∈{1,2,4,8,16}，每 worker 固定负载（weak scaling），三种后端：

  dict       纯内存 dict 后端（无 DB）——无持久化天花板，对应 E11e 口径
  sqlite     SQLiteBackend（默认 rollback journal）——真实代码路径
  sqlite_wal SQLiteBackend + PRAGMA journal_mode=WAL（与 SqliteNonceStore 同款）

三种负载（对应 issue 路径实际 DB 触达）：
  read   2×get_identity + 1×is_revoked     （读多，WAL 应并发读）
  write  1×append_audit                     （写多，SQLite 单写者瓶颈）
  mixed  1×get_identity + 1×is_revoked + 1×append_audit （真实签发路径）

读法：dict→sqlite 之差 = SQLite 成本；sqlite→sqlite_wal 之差 = WAL 收益；
      sqlite_wal@16 vs E11e 内存@16(≈1008 TPS) 之差 = 共享文件是否封顶。

产物：eval_E11f_sqlite_concurrency.csv

用法
----
    python e11f_sqlite_concurrency.py            # 默认 ops=250
    python e11f_sqlite_concurrency.py --ops 500 --procs 1,2,4,8,16
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

from persistence import SQLiteBackend  # noqa: E402

CSV_PATH = os.path.join(_HERE, "eval_E11f_sqlite_concurrency.csv")
DB_PATH = os.path.join(_HERE, "_bench_e11f.db")
MODES = ("dict", "sqlite", "sqlite_wal")
WORKLOADS = ("read", "write", "mixed")


class DictBackend:
    """纯内存 dict 后端——无持久化天花板（E11e 内存口径的代理）。"""

    def __init__(self):
        self._d = {}

    def put_identity(self, tenant, idn, x, y, status, meta):
        self._d[("i", tenant, idn)] = (x, y, status)

    def get_identity(self, tenant, idn):
        return self._d.get(("i", tenant, idn))

    def is_revoked(self, tenant, jti):
        return ("r", tenant, jti) in self._d

    def append_audit(self, tenant, seq, ts, kind, h, prev, event):
        self._d[("a", tenant, seq)] = (h, event)

    def append_revocation(self, tenant, version, jti, reason, ts):
        self._d[("r", tenant, jti)] = version


def _make_backend(mode, db_path):
    if mode == "dict":
        return DictBackend(), None
    pers = SQLiteBackend(db_path)
    if mode == "sqlite_wal":
        try:
            pers._conn.execute("PRAGMA journal_mode=WAL")
            pers._conn.commit()
        except Exception:  # noqa: BLE001
            pass
    return pers, pers


def _worker(cfg):
    """worker 入口（模块顶层，Windows spawn 可 pickle）。"""
    mode, workload, ops, seed, db_path = cfg
    if _PROTO not in sys.path:
        sys.path.insert(0, _PROTO)
    pers, _ = _make_backend(mode, db_path)
    tenant = "t"
    a = "agent://f/a/%d" % seed
    b = "agent://f/b/%d" % seed
    pers.put_identity(tenant, a, "0x1", "0x2", "active", {})
    pers.put_identity(tenant, b, "0x3", "0x4", "active", {})
    for _ in range(40):                      # warmup
        pers.get_identity(tenant, a)
        pers.is_revoked(tenant, "n")
    t0 = time.perf_counter()
    for i in range(ops):
        if workload == "read":
            pers.get_identity(tenant, a)
            pers.get_identity(tenant, b)
            pers.is_revoked(tenant, "n%d" % (i % 1000))
        elif workload == "write":
            pers.append_audit(tenant, i, 1, "kind",
                              "h%d" % i, "p%d" % i, {"idn": a, "seq": i})
        else:                                # mixed：真实签发路径
            pers.get_identity(tenant, a)
            pers.is_revoked(tenant, "n%d" % (i % 1000))
            pers.append_audit(tenant, i, 1, "kind",
                              "h%d" % i, "p%d" % i, {"idn": a, "seq": i})
    dt = time.perf_counter() - t0
    if isinstance(pers, SQLiteBackend):
        pers.close()
    return dt, ops


def run_gradient(mode, workload, ops, procs_list, db_path):
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    rows = []
    for w in procs_list:
        cfg = [(mode, workload, ops, i, db_path) for i in range(w)]
        t0 = time.perf_counter()
        try:
            with ctx.Pool(processes=w) as pool:
                results = pool.map(_worker, cfg)
        except Exception as e:  # noqa: BLE001
            print("  %-9s/%-5s W=%-2d 失败 %s: %s"
                  % (mode, workload, w, type(e).__name__, e))
            break
        wall = time.perf_counter() - t0
        elapsed = [r[0] for r in results]
        ops_sum = sum(r[1] for r in results)
        steady = max(elapsed) if elapsed else 0.0
        rows.append({
            "mode": mode, "workload": workload, "workers": w,
            "ops": ops_sum, "steady_s": round(steady, 3),
            "wall_total_s": round(wall, 3),
            "tps_steady": round(ops_sum / steady, 1) if steady > 0 else 0.0,
            "tps_wall": round(ops_sum / wall, 1) if wall > 0 else 0.0,
        })
        print("  %-9s/%-5s W=%-2d %5d ops 稳态 %6.2fs → %8.1f TPS (含启动 %7.1f)"
              % (mode, workload, w, ops_sum, steady,
                 rows[-1]["tps_steady"], rows[-1]["tps_wall"]))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ops", type=int, default=250)
    ap.add_argument("--procs", default="1,2,4,8,16")
    args = ap.parse_args()
    procs = [int(x) for x in args.procs.split(",")]

    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:  # noqa: BLE001
            pass

    print("本机逻辑核 = %d；ops/worker = %d；db = %s"
          % (os.cpu_count() or 0, args.ops, DB_PATH))
    all_rows = []
    for mode in MODES:
        for workload in WORKLOADS:
            rows = run_gradient(mode, workload, args.ops, procs, DB_PATH)
            all_rows.extend(rows)
            # 每个后端/负载组用独立 db，避免跨组 WAL 遗留
            if mode != "dict" and os.path.exists(DB_PATH):
                try:
                    os.remove(DB_PATH)
                except Exception:  # noqa: BLE001
                    pass

    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=[
            "mode", "workload", "workers", "ops", "steady_s",
            "wall_total_s", "tps_steady", "tps_wall"])
        w.writeheader()
        w.writerows(all_rows)
    print("\n已写入 %s" % CSV_PATH)

    # 摘要：每负载的 1→16 加速比（steady 口径）
    print("\n== 加速比（W=16 vs W=1，tps_steady）==")
    for mode in MODES:
        for workload in WORKLOADS:
            g = {r["workers"]: r["tps_steady"]
                 for r in all_rows
                 if r["mode"] == mode and r["workload"] == workload}
            if 1 in g and 16 in g and g[1] > 0:
                print("  %-9s/%-5s  W1=%8.1f  W16=%8.1f  加速=%.2fx"
                      % (mode, workload, g[1], g[16], g[16] / g[1]))


if __name__ == "__main__":
    main()
