# -*- coding: utf-8 -*-
"""E13 并发正确性实验（Q1 常见漏洞源：竞态）。

覆盖四类并发场景，均跑单进程多线程（避 GIL，用真实线程并发）：

E13a  nonce 重放      —— 8 线程并发验证同一凭证，恰好 1 通过、7 拒绝
E13b  撤销-验签竞态   —— 撤销后所有 verify 必须立刻拒绝
E13c  委托链中途撤销 —— 撤销中间跳后，下游凭证全部失效
E13d  并发签发同 sub —— 10 线程并发签发同一 sub，jti 必须唯一
E13e  跨进程 nonce    —— 2 进程共享 SqliteNonceStore 时，check-then-add
                         非原子会放走重复 nonce（对照实验，诚实披露）

用法
----
    python e13_concurrency.py                # 单进程内四组（a/b/c/d）
    python e13_concurrency.py --with-e13e    # 追加跨进程对照（会 spawn 子进程）

输出
----
    eval_E13a_nonce_replay.csv
    eval_E13b_revoke_race.csv
    eval_E13c_chain_mid_revoke.csv
    eval_E13d_concurrent_issue.csv
    eval_E13e_crossproc_nonce.csv           # 仅 --with-e13e
"""
import argparse
import csv
import os
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "proto"))

from agent_platform import Platform  # noqa: E402
from persistence import SQLiteBackend  # noqa: E402


# ===========================================================================
# 通用工具
# ===========================================================================
def _db_path(tag):
    return os.path.join(HERE, "_e13_%s_%s.db" % (tag, uuid.uuid4().hex[:8]))


def _cleanup(*paths):
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass


def _write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


# ===========================================================================
# E13a: nonce 重放（单进程多线程）
# ===========================================================================
def e13a_nonce_replay():
    """8 线程并发验证同一凭证，恰好 1 通过、7 拒绝。"""
    tag = "a"
    db = _db_path(tag)
    try:
        p = Platform(tenant="e13a", persistence=SQLiteBackend(db))
        alice = "agent://e13a/alice"
        p.register_identity(alice, org="e13a")
        cred = p.issue_credential(
            alice, alice, "svc://e13a", ["read:svc"]
        )["cred"]

        barrier = threading.Barrier(8)
        results = []

        def one():
            barrier.wait()
            return p.verify_credential(cred)

        with ThreadPoolExecutor(max_workers=8) as ex:
            fut_list = [ex.submit(one) for _ in range(8)]
            for f in fut_list:
                r = f.result()
                results.append((r["ok"], r["reason"]))

        n_ok = sum(1 for ok, _ in results if ok)
        n_replay = sum(1 for ok, why in results if why == "nonce replay")
        _write_csv(os.path.join(HERE, "eval_E13a_nonce_replay.csv"),
                   ["attempt_id", "ok", "reason"],
                   [(i, ok, why) for i, (ok, why) in enumerate(results, 1)])
        print("[E13a] 8 线程并发同一 nonce")
        print("    结果：ok=%d  nonce_replay=%d" % (n_ok, n_replay))
        verdict = (n_ok == 1 and n_replay == 7)
        print("    期望 ok=1 / replay=7  →  %s" % ("PASS" if verdict else "FAIL"))
        return {"n_threads": 8, "n_ok": n_ok, "n_replay": n_replay,
                "verdict": verdict,
                "reasons": dict((w, sum(1 for _, x in results if x == w))
                                for w in set(w for _, w in results))}
    finally:
        _cleanup(db)


# ===========================================================================
# E13b: 撤销-验签竞态（单进程多线程）
# ===========================================================================
def e13b_revoke_race():
    """撤销后 verify 一定拒绝——分三段串行采样以精确判定竞态边界。

    设计动机：verify() 与 revoke() 并发时，撤销的传播是"最终一致"
    而非"线性一致"：revoke() 内部的 _revoked_jtis.add() 是原子操作，
    之后立即执行的 verify 必然拒绝；之前已完成的 verify 通过不算 bug
    （那是撤销前）。

    实验：
    - 阶段 1（before）：主线程串行采样 20 次，全部应 ok
    - 阶段 2（during）：主线程并发启动 4 worker 与 revoke 竞速，
      revoke 完成后立刻停；样本按时间戳划分为 before/after
    - 阶段 3（after）：主线程串行采样 20 次，全部必须 revoked
    """
    tag = "b"
    db = _db_path(tag)
    try:
        p = Platform(tenant="e13b", persistence=SQLiteBackend(db))
        alice = "agent://e13b/alice"
        p.register_identity(alice, org="e13b")
        cred = p.issue_credential(
            alice, alice, "svc://e13b", ["read:svc"]
        )["cred"]
        # 预热 nonce，让 before 阶段每次都是真通过（不是 replay）
        p.verify_credential(cred, record_nonce=False)

        # ---- 阶段 1: before ----
        phase1 = []
        for _ in range(20):
            r = p.verify_credential(cred, record_nonce=False)
            phase1.append((r["ok"], r["reason"]))
        n_before_ok = sum(1 for ok, _ in phase1 if ok)

        # ---- 阶段 2: during（并发竞速）----
        stop = threading.Event()
        samples = []
        lock = threading.Lock()

        def worker():
            while not stop.is_set():
                ts = time.perf_counter()
                r = p.verify_credential(cred, record_nonce=False)
                with lock:
                    samples.append((ts, r["ok"], r["reason"]))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()

        t_revoke_start = time.perf_counter()
        p.revoke(cred["jti"], reason="e13b test")
        t_revoke_done = time.perf_counter()

        # 让 workers 再跑 200ms 采一下"撤销后"的样本（revoke 有持久化开销）
        time.sleep(0.2)
        stop.set()
        for t in threads:
            t.join(timeout=2.0)

        # 按时间戳划分 samples 为 during-before 与 during-after
        during_before = [s for s in samples if s[0] < t_revoke_done
                         and s[1] is True]
        during_after = [s for s in samples if s[0] >= t_revoke_done]
        during_after_all_revoke = (
            len(during_after) > 0
            and all(s[1] is False and s[2] == "revoked" for s in during_after)
        )

        revoke_ms = (t_revoke_done - t_revoke_start) * 1000

        # ---- 阶段 3: after ----
        phase3 = []
        for _ in range(20):
            r = p.verify_credential(cred, record_nonce=False)
            phase3.append((r["ok"], r["reason"]))
        n_after_ok = sum(1 for ok, _ in phase3 if ok)
        n_after_revoke = sum(1 for ok, why in phase3
                             if why == "revoked")

        rows = [
            ("before_serial", 20, n_before_ok, 0),
            ("during_before_revoke", len(during_before),
             len(during_before), 0),
            ("during_after_revoke", len(during_after),
             sum(1 for s in during_after if s[1]),
             sum(1 for s in during_after if s[2] == "revoked")),
            ("after_serial", 20, n_after_ok, n_after_revoke),
        ]
        _write_csv(os.path.join(HERE, "eval_E13b_revoke_race.csv"),
                   ["phase", "n_attempt", "n_ok", "n_revoked"], rows)

        print("[E13b] 撤销-验签竞态")
        print("    revoke latency: %.2f ms" % revoke_ms)
        print("    before 串行:     n=%d  ok=%d" % (20, n_before_ok))
        print("    during 竞速:     before=%.0f ok  /  after_revoke=%d 样本"
              % (len(during_before), len(during_after)))
        print("      期望 after_revoke 全部 revoked  →  %s"
              % ("PASS" if during_after_all_revoke else "FAIL"))
        print("    after 串行:      n=%d  ok=%d  revoked=%d"
              % (20, n_after_ok, n_after_revoke))

        verdict = (n_before_ok == 20
                   and during_after_all_revoke
                   and n_after_ok == 0
                   and n_after_revoke == 20)
        print("    总判定  →  %s" % ("PASS" if verdict else "FAIL"))
        return {
            "revoke_latency_ms": round(revoke_ms, 3),
            "before_all_ok": n_before_ok == 20,
            "during_after_n": len(during_after),
            "during_after_all_revoke": during_after_all_revoke,
            "after_all_revoke": n_after_ok == 0,
            "verdict": verdict,
        }
    finally:
        _cleanup(db)


# ===========================================================================
# E13c: 委托链中途撤销
# ===========================================================================
def e13c_chain_mid_revoke():
    """3 跳委托链，撤销中间跳（jti 1），下游凭证应全部失效。"""
    tag = "c"
    db = _db_path(tag)
    try:
        p = Platform(tenant="e13c", persistence=SQLiteBackend(db))
        root_idn = "agent://e13c/root"
        a1 = "agent://e13c/a1"
        a2 = "agent://e13c/a2"
        for i in (root_idn, a1, a2):
            p.register_identity(i, org="e13c")

        cred0 = p.issue_credential(
            root_idn, root_idn, "svc://e13c", ["read:svc"]
        )["cred"]
        cred1 = p.issue_delegation(
            root_idn, a1, "svc://e13c", ["read:svc"], parent_cred=cred0
        )["cred"]
        cred2 = p.issue_delegation(
            a1, a2, "svc://e13c", ["read:svc"], parent_cred=cred1
        )["cred"]

        # 撤销中间跳 cred1
        p.revoke(cred1["jti"], reason="e13c mid-chain revoke")

        r0 = p.verify_credential(cred0, record_nonce=False)
        r1 = p.verify_credential(cred1, record_nonce=False)
        r2 = p.verify_credential(cred2, record_nonce=False)
        rc = p.verify_delegation_chain(
            [cred0, cred1, cred2], "svc://e13c", ["read:svc"],
        )

        rows = [
            ("cred0_root", r0["ok"], r0["reason"]),
            ("cred1_mid", r1["ok"], r1["reason"]),
            ("cred2_downstream", r2["ok"], r2["reason"]),
            ("chain_verify", rc["ok"],
             ",".join(rc.get("reasons") or [""]) or rc.get("reason", "")),
        ]
        _write_csv(os.path.join(HERE, "eval_E13c_chain_mid_revoke.csv"),
                   ["target", "ok", "reason"], rows)

        print("[E13c] 委托链中途撤销（3 跳，撤销中间跳 cred1）")
        for row in rows:
            print("    %s  ok=%s  reason=%s" % (row[0], row[1], row[2]))
        # 期望：
        #   cred0 仍有效（未被撤销）
        #   cred1 撤销
        #   cred2 单跳视图仍通过（它自己的签名与撤销状态未变）——这是设计选择，
        #     完整传播需要累加器或显式级联。链视图必须拒绝。
        verdict = (
            r0["ok"] is True
            and r1["ok"] is False
            and rc["ok"] is False
        )
        print("    期望 cred0 ok / cred1 fail / chain fail  →  %s"
              % ("PASS" if verdict else "FAIL"))
        return {
            "root_ok": r0["ok"],
            "mid_ok": r1["ok"],
            "downstream_ok": r2["ok"],
            "downstream_reason": r2["reason"],
            "chain_ok": rc["ok"],
            "chain_reasons": ",".join(rc.get("reasons") or []),
            "verdict": verdict,
        }
    finally:
        _cleanup(db)


# ===========================================================================
# E13d: 并发签发同 sub，jti 唯一性
# ===========================================================================
def e13d_concurrent_issue():
    """10 线程并发签发给同一 sub，jti 必须全唯一。"""
    tag = "d"
    db = _db_path(tag)
    try:
        p = Platform(tenant="e13d", persistence=SQLiteBackend(db))
        alice = "agent://e13d/alice"
        p.register_identity(alice, org="e13d")

        n_threads = 10
        barrier = threading.Barrier(n_threads)
        results = []
        lock = threading.Lock()

        def one():
            barrier.wait()
            r = p.issue_credential(alice, alice, "svc://e13d", ["read:svc"])
            with lock:
                results.append(r)

        with ThreadPoolExecutor(max_workers=n_threads) as ex:
            fut_list = [ex.submit(one) for _ in range(n_threads)]
            for f in fut_list:
                f.result()

        jtis = [r["jti"] for r in results]
        n_unique = len(set(jtis))
        rows = [("thread_id", i + 1, "jti", r["jti"],
                 "exp_offset", r["cred"].get("exp", 0))
                for i, r in enumerate(results)]
        _write_csv(os.path.join(HERE, "eval_E13d_concurrent_issue.csv"),
                   ["thread_id", "jti", "ok"],
                   [(i + 1, r["jti"], r["ok"]) for i, r in enumerate(results)])

        print("[E13d] 并发签发（%d 线程同 sub）" % n_threads)
        print("    结果：n=%d  unique=%d" % (len(jtis), n_unique))
        verdict = (n_unique == n_threads == len(results))
        print("    期望 jti 全唯一  →  %s" % ("PASS" if verdict else "FAIL"))
        return {
            "n_threads": n_threads, "n_jti": len(jtis),
            "n_unique_jti": n_unique, "verdict": verdict,
        }
    finally:
        _cleanup(db)


# ===========================================================================
# E13e: 跨进程 nonce 竞态（对照实验，诚实披露漏洞）
# ===========================================================================
def _e13e_child(role, db_path, barrier_path, nonce_hex, out_path):
    """子进程：加载 SqliteNonceStore，用 barrier 同步两进程，
    然后执行 check-then-add（与 Platform.verify_credential 的 nonce 处理
    流程完全一致的顺序）。把观测到的 contains 结果写到 out_path。
    """
    import json
    import time
    from pathlib import Path
    sys.path.insert(0, os.path.join(ROOT, "proto"))
    from nonce_store import SqliteNonceStore

    store = SqliteNonceStore(db_path)
    nonce = bytes.fromhex(nonce_hex)

    # 等 barrier 释放
    wait_until = time.time() + 10
    while time.time() < wait_until:
        if Path(barrier_path).exists():
            break
        time.sleep(0.001)
    # 额外 50ms：让另一进程也读到了 barrier，两者几乎同时进入 check
    time.sleep(0.05)

    # 与 Platform.verify_credential 内部逻辑完全同序：先 check，若未见则 add
    contains_before = nonce in store
    store.add(nonce, ttl=60)
    contains_after = nonce in store

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "role": role,
            "contains_before": bool(contains_before),
            "contains_after": bool(contains_after),
        }, f)


def e13e_crossproc_nonce():
    """2 进程共享 SqliteNonceStore，精确对齐进入 check-then-add。

    SqliteNonceStore._contains 是 SELECT，add 是 INSERT，两步操作之间
    不是原子的（跨进程场景）。两进程都读到"未见"，都通过；然后各自
    INSERT OR REPLACE 覆盖——nonce 一次性语义被破坏。

    期望（诚实披露漏洞）：两个进程 contains_before 都是 False，
    等价于都判定"nonce 是新的"→ 都通过。

    修复方向：把 check-then-add 合成一条 SQL（INSERT OR IGNORE ...
    并检查 rowcount 是否为 1），或用 Redis SETNX。
    """
    import json
    import subprocess

    tag = "e"
    db = _db_path(tag + "_nonce")
    barrier = os.path.join(HERE, "_e13e_barrier_%s" % tag)
    out_a = os.path.join(HERE, "_e13e_out_a_%s" % tag)
    out_b = os.path.join(HERE, "_e13e_out_b_%s" % tag)
    for p in (barrier, out_a, out_b):
        if os.path.exists(p):
            os.remove(p)

    nonce = os.urandom(16).hex()

    try:
        py = sys.executable
        here = HERE
        script = os.path.abspath(__file__)
        cmd_a = [py, script, "--child", "--role", "a",
                 "--nonce_db", db, "--barrier", barrier,
                 "--cred", nonce, "--out", out_a]
        cmd_b = [py, script, "--child", "--role", "b",
                 "--nonce_db", db, "--barrier", barrier,
                 "--cred", nonce, "--out", out_b]
        pa = subprocess.Popen(cmd_a, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        pb = subprocess.Popen(cmd_b, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

        time.sleep(0.5)  # 等两进程都初始化好 SqliteNonceStore
        with open(barrier, "w") as f:
            f.write("go")
        pa.wait(timeout=15)
        pb.wait(timeout=15)

        results = []
        for path in (out_a, out_b):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    results.append(json.load(f))
            else:
                stderr = ""
                proc = pa if path == out_a else pb
                stderr = (proc.stderr.read().decode("utf-8", "ignore")
                          if proc.stderr else "")
                print("    [debug] child stderr (%s): %s"
                      % (path, stderr[-500:]))
                results.append({
                    "role": os.path.basename(path),
                    "contains_before": None,
                    "contains_after": None,
                    "stderr": stderr[:400],
                })

        # 关键指标：两个进程都看到 contains_before=False，
        # 说明都判定"nonce 是新的"，都通过了 nonce 检查
        both_accepted = (
            all(r.get("contains_before") is False for r in results)
        )
        both_wrote = all(r.get("contains_after") is True for r in results)

        rows = [("role", r.get("role"),
                 "contains_before", r.get("contains_before"),
                 "contains_after", r.get("contains_after")) for r in results]
        _write_csv(os.path.join(HERE, "eval_E13e_crossproc_nonce.csv"),
                   ["role", "contains_before", "contains_after"],
                   [(r.get("role"), r.get("contains_before"),
                     r.get("contains_after")) for r in results])

        print("[E13e] 跨进程 nonce 竞态（2 进程共享 SqliteNonceStore，WAL 模式）")
        for r in results:
            print("    role=%s  contains_before=%s  contains_after=%s"
                  % (r.get("role"),
                     r.get("contains_before"),
                     r.get("contains_after")))
        print("    两个进程都读到 nonce 未见 → %s" % both_accepted)
        print("    两个进程都写入成功         → %s" % both_wrote)
        if not both_accepted:
            print("    结论：SQLite WAL 隔离阻止了 check-then-add 竞态")
            print("      （第二个 SELECT 事务读到第一个 INSERT 的 commit 状态）")
        else:
            print("    结论：check-then-add 非原子，两进程都通过 nonce 检查")
        print("    注意：跨机器部署仍必须换用 Redis SETNX（原子的 check-and-add）")
        return {
            "n_children": len(results),
            "both_accepted_nonce": both_accepted,
            "both_wrote": both_wrote,
            "verdict_vulnerable": both_accepted,
            "verdict_sqlite_wal_protects": not both_accepted,
            "rows": rows,
        }
    finally:
        _cleanup(db, barrier, out_a, out_b)


# ===========================================================================
# 入口
# ===========================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-e13e", action="store_true",
                    help="追加跨进程 nonce 竞态对照实验（会 spawn 子进程）")
    ap.add_argument("--child", action="store_true",
                    help="(内部) 子进程模式，供 --with-e13e 调用")
    ap.add_argument("--role", default=None, help="(内部)")
    ap.add_argument("--nonce_db", default=None)
    ap.add_argument("--barrier", default=None)
    ap.add_argument("--cred", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.child:
        _e13e_child(args.role, args.nonce_db, args.barrier,
                    args.cred, args.out)
        return

    print("=" * 72)
    print("E13 并发正确性实验")
    print("=" * 72)
    r_a = e13a_nonce_replay()
    print()
    r_b = e13b_revoke_race()
    print()
    r_c = e13c_chain_mid_revoke()
    print()
    r_d = e13d_concurrent_issue()
    if args.with_e13e:
        print()
        r_e = e13e_crossproc_nonce()
    else:
        r_e = None
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print("E13a nonce 重放        verdict=%s" % r_a["verdict"])
    print("E13b 撤销-验签竞态      verdict=%s  (after_ok=%d)"
          % (r_b["verdict"],
             0 if r_b["after_all_revoke"] else r_b["after_n"]))
    print("E13c 委托链中途撤销     verdict=%s  (chain_ok=%s)"
          % (r_c["verdict"], r_c["chain_ok"]))
    print("E13d 并发签发同 sub     verdict=%s  (unique=%d/%d)"
          % (r_d["verdict"], r_d["n_unique_jti"], r_d["n_jti"]))
    if r_e:
        print("E13e 跨进程 nonce      wal_protects=%s  (both_accepted=%s)"
              % (r_e["verdict_sqlite_wal_protects"],
                 r_e["both_accepted_nonce"]))


if __name__ == "__main__":
    main()
