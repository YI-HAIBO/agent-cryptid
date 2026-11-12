# -*- coding: utf-8 -*-
"""E17 真实场景 case study：软件交付流水线中的委托链。

回应 Q1 审稿人的根本质疑：「这些 benchmark 数字代表一个真实可部署的系统吗？」

设计一个具体工作负载——CI/CD 发布流水线，3 个协作智能体：
    CA（根信任锚）→ 研发(Dev) → 运维(Ops) → 安全(Sec)
构成一条 3 跳委托链（Dev/Ops/Sec 逐级委托，scope 逐级收敛）：
    CA→Dev  : scope = {build:read, artifact:push, deploy:approve}
    Dev→Ops : scope = {artifact:push, deploy:approve}         (子集)
    Ops→Sec : scope = {deploy:approve}                        (子集，最终权限)
端任务：Sec 要对其负责的 prod 服务执行 deploy:approve。

测量三类「用户可感知」指标：
  (1) 一次性委托建立成本（摊销到每次授权后可忽略）
  (2) 每次授权校验（资源服务端 verify）的端到端延迟
  (3) 中途撤销的级联失效 + 越权委托的实时拦截

并对比两种 baseline：
  (a) 无身份层（每次走完整认证）：每次授权都回根 CA 重新签发
  (b) 仅凭证层（无委托链）：CA 给每个智能体独立签发全量 scope 凭证，无 scope 收敛

输出：
    eval_E17_workflow.csv        真实工作负载时序分解
    eval_E17_baselines.csv       三种方案每授权延迟对比
    eval_E17_revocation.csv      中途撤销级联 + 越权拦截
"""
import os
import sys
import time
import csv

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "proto"))

from agent_platform import Platform          # noqa: E402
from persistence import SQLiteBackend        # noqa: E402
from eval_framework import benchmark         # noqa: E402

AUD = "svc://e17/prod"
SCOPE_ROOT = ["build:read", "artifact:push", "deploy:approve"]
SCOPE_OPS = ["artifact:push", "deploy:approve"]
SCOPE_SEC = ["deploy:approve"]


def _make_db(tag):
    p = os.path.join(HERE, "_e17_%s.db" % tag)
    if os.path.exists(p):
        try:
            os.remove(p)
        except Exception:
            pass
    return p


def _setup_chain(tag):
    """建立真实信任链：CA→Dev→Ops→Sec。返回 Platform 与各级 wire。"""
    db = _make_db(tag)
    pers = SQLiteBackend(db)
    p = Platform(tenant="e17_%s" % tag, persistence=pers)
    ca, dev, ops, sec = ("agent://e17/ca", "agent://e17/dev",
                         "agent://e17/ops", "agent://e17/sec")
    for i in (ca, dev, ops, sec):
        p.register_identity(i, org="e17")
    # CA→Dev 根凭证
    r_dev = p.issue_credential(ca, dev, AUD, SCOPE_ROOT)
    assert r_dev["ok"]
    # Dev→Ops 委托
    r_ops = p.issue_delegation(dev, ops, AUD, SCOPE_OPS, parent_cred=r_dev["cred"])
    assert r_ops["ok"]
    # Ops→Sec 委托
    r_sec = p.issue_delegation(ops, sec, AUD, SCOPE_SEC, parent_cred=r_ops["cred"])
    assert r_sec["ok"]
    return p, pers, db, r_dev["cred"], r_ops["cred"], r_sec["cred"], (ca, dev, ops, sec)


def _teardown(p, pers, db):
    """关闭连接并删除 DB（安全删除失败时回退强制删）。"""
    try:
        if pers is not None:
            pers.close()
    except Exception:
        pass
    try:
        if db and os.path.exists(db):
            os.remove(db)
    except Exception:
        pass


def _bench_verify_chain(p, chain):
    chain = [dict(c) for c in chain]  # 浅拷贝，避免 record_nonce 副作用

    def fn():
        return p.verify_delegation_chain(
            chain, target_audience=AUD, target_scope=SCOPE_SEC)

    return benchmark(fn, n=200, warmup=20)


def e17a_workflow():
    """真实工作负载时序分解 + 每授权摊销成本。"""
    p, pers, db, cdev, cops, csec, ids = _setup_chain("wf")
    chain = [cdev, cops, csec]
    try:
        # 一次性委托建立成本
        t0 = time.perf_counter()
        db2 = _make_db("wf2")
        pers2 = SQLiteBackend(db2)
        p2 = Platform(tenant="e17_wf2", persistence=pers2)
        for i in ids:
            p2.register_identity(i, org="e17")
        r_dev = p2.issue_credential(ids[0], ids[1], AUD, SCOPE_ROOT)
        r_ops = p2.issue_delegation(ids[1], ids[2], AUD, SCOPE_OPS,
                                    parent_cred=r_dev["cred"])
        r_sec = p2.issue_delegation(ids[2], ids[3], AUD, SCOPE_SEC,
                                    parent_cred=r_ops["cred"])
        t_setup = (time.perf_counter() - t0) * 1000
        _teardown(p2, pers2, db2)

        # 每次授权校验成本（资源服务端）
        b_verify = _bench_verify_chain(p, chain)

        # 摊销：假设一天内 Sec 授权 N 次
        rows = []
        for n in (100, 1000, 10000):
            amort = t_setup / n
            rows.append((n, round(amort, 4), b_verify["median_ms"],
                         round(amort + b_verify["median_ms"], 3),
                         round(amort + b_verify["p99_ms"], 3)))
        _write_csv("eval_E17_workflow.csv",
                   ["n_authorizations", "setup_amortized_ms",
                    "verify_median_ms", "peruse_median_ms", "peruse_p99_ms"],
                   rows)
        print("[E17a] 真实工作负载：CI/CD 发布流水线（3 跳委托链）")
        print("    一次性委托建立（CA→Dev→Ops→Sec）: %.2f ms" % t_setup)
        print("    每次授权校验（verify_delegation_chain, 3 跳）: "
              "median=%.2f p99=%.2f ms" % (b_verify["median_ms"],
                                           b_verify["p99_ms"]))
        for r in rows:
            print("    N=%6d 摊销后每授权=%.3f ms (median) / %.3f ms (p99)"
                  % (r[0], r[3], r[4]))
        return {"setup_ms": round(t_setup, 3),
                "verify_median_ms": b_verify["median_ms"],
                "verify_p99_ms": b_verify["p99_ms"]}
    finally:
        _teardown(p, pers, db)


def e17b_baselines():
    """两种 baseline 与 agent-cryptid 的每授权延迟对比。"""
    p, pers, db, cdev, cops, csec, ids = _setup_chain("bl")
    chain = [cdev, cops, csec]
    ca, dev, ops, sec = ids
    try:
        # (i) agent-cryptid：链校验（3 跳）
        b_ac = _bench_verify_chain(p, chain)

        # (ii) baseline A：无身份层——每次授权回 CA 重新签发给 Sec
        def fn_a():
            r = p.issue_credential(ca, sec, AUD, SCOPE_SEC)
            return p.verify_credential(r["cred"], audience=AUD,
                                       record_nonce=False)

        b_a = benchmark(fn_a, n=100, warmup=15)

        # (iii) baseline B：仅凭证层——CA 给 Sec 独立签发全量凭证，无委托链
        r_flat = p.issue_credential(ca, sec, AUD, SCOPE_ROOT)
        assert r_flat["ok"]

        def fn_b():
            return p.verify_credential(r_flat["cred"], audience=AUD,
                                       record_nonce=False)

        b_b = benchmark(fn_b, n=200, warmup=20)

        rows = [
            ("agent-cryptid (3-hop chain)", b_ac["median_ms"], b_ac["p95_ms"],
             b_ac["p99_ms"], "scope 收敛 + 委托链"),
            ("baseline A: 无身份层 (re-auth/use)", b_a["median_ms"],
             b_a["p95_ms"], b_a["p99_ms"], "每次回 CA 重签"),
            ("baseline B: 扁平凭证 (standalone)", b_b["median_ms"],
             b_b["p95_ms"], b_b["p99_ms"], "无 scope 收敛保障"),
        ]
        _write_csv("eval_E17_baselines.csv",
                   ["scheme", "verify_median_ms", "verify_p95_ms",
                    "verify_p99_ms", "note"], rows)
        print("[E17b] 每授权延迟对比（资源服务端 verify）")
        for r in rows:
            print("    %-38s median=%.2f p99=%.2f ms  [%s]"
                  % (r[0], r[1], r[3], r[4]))
        return {"ac_median": b_ac["median_ms"], "a_median": b_a["median_ms"],
                "b_median": b_b["median_ms"]}
    finally:
        _teardown(p, pers, db)


def e17c_revocation_and_escalation():
    """中途撤销的级联失效 + 越权委托的实时拦截。"""
    p, pers, db, cdev, cops, csec, ids = _setup_chain("rv")
    chain = [cdev, cops, csec]
    ca, dev, ops, sec = ids
    try:
        # 正常：链校验通过
        r_ok = p.verify_delegation_chain(chain, target_audience=AUD,
                                         target_scope=SCOPE_SEC)

        # 越权拦截（在撤销前测，保证父凭证未撤销）：
        # Dev 试图把 admin:wipe 委托给 Ops（超出 Dev 自身 scope）
        r_esc = p.issue_delegation(dev, ops, AUD,
                                   ["artifact:push", "admin:wipe"],
                                   parent_cred=cdev)

        # 撤销链根（Dev 的 root 被妥协）
        t0 = time.perf_counter()
        p.revoke(cdev["jti"], reason="Dev root compromised")
        t_revoke = (time.perf_counter() - t0) * 1000
        # 撤销后重校验 —— 应级联失败
        r_rev = p.verify_delegation_chain([dict(c) for c in chain],
                                         target_audience=AUD,
                                         target_scope=SCOPE_SEC)

        rows = [
            ("normal_chain_verify", bool(r_ok["ok"]), "", ""),
            ("escalation_attempt_ok", bool(r_esc.get("ok")),
             r_esc.get("reason", ""), "scope escalation blocked"),
            ("revoke_root_latency_ms", round(t_revoke, 3), "", ""),
            ("after_revoke_chain_verify", bool(r_rev["ok"]),
             ";".join(r_rev.get("reasons", [])), "cascade fail"),
        ]
        _write_csv("eval_E17_revocation.csv",
                   ["test", "result_bool", "reasons", "note"], rows)
        print("[E17c] 中途撤销级联 + 越权拦截")
        print("    正常链校验: ok=%s" % r_ok["ok"])
        print("    越权委托(admin:wipe): ok=%s  reason=%s"
              % (r_esc.get("ok"), r_esc.get("reason")))
        print("    撤销根延迟: %.2f ms" % t_revoke)
        print("    撤销后链校验: ok=%s  reasons=%s"
              % (r_rev["ok"], r_rev.get("reasons")))
        verdict = (r_ok["ok"] and not r_esc.get("ok")
                   and r_esc.get("reason") == "scope escalation"
                   and not r_rev["ok"])
        print("    结论: %s" % ("PASS" if verdict else "FAIL"))
        return {"normal_ok": bool(r_ok["ok"]), "after_revoke_ok": bool(r_rev["ok"]),
                "escalation_ok": bool(r_esc.get("ok")),
                "escalation_reason": r_esc.get("reason"),
                "verdict": verdict}
    finally:
        _teardown(p, pers, db)


def _write_csv(name, header, rows):
    path = os.path.join(HERE, name)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


if __name__ == "__main__":
    print("=" * 70)
    print("E17 真实场景 case study — CI/CD 发布流水线委托链")
    print("=" * 70)
    ra = e17a_workflow()
    print()
    rb = e17b_baselines()
    print()
    rc = e17c_revocation_and_escalation()
    print()
    print("=" * 70)
    print("E17 汇总")
    print("=" * 70)
    print("  workflow 建立: %.2f ms (一次性)" % ra["setup_ms"])
    print("  每授权(agent-cryptid): median=%.2f p99=%.2f ms"
          % (ra["verify_median_ms"], ra["verify_p99_ms"]))
    print("  每授权(baseline A 重签): %.2f ms" % rb["a_median"])
    print("  每授权(baseline B 扁平): %.2f ms" % rb["b_median"])
    print("  中途撤销级联: %s / 越权拦截: %s"
          % (not rc["after_revoke_ok"], not rc["escalation_ok"]))
