# -*- coding: utf-8 -*-
"""Minimal benchmark: E1 registration + credential issue/verify + delegation."""
import sys, os, time, json

BASE = r"C:\Users\Yi\WorkBuddy\2026-10-09-07-28-12\agent-cryptid"
sys.path.insert(0, os.path.join(BASE, "proto"))
os.chdir(os.path.join(BASE, "proto"))
sys.path.insert(0, os.path.join(BASE, "research"))

from agent_platform import Platform
from persistence import SQLiteBackend
from eval_framework import benchmark

db = os.path.join(BASE, "research", "_bench_mini.db")
if os.path.exists(db):
    os.remove(db)
pers = SQLiteBackend(db)
p = Platform(tenant="mini", persistence=pers)

# E1a: 100 identities
t0 = time.perf_counter()
for i in range(100):
    p.register_identity("agent://mini/reg/%d" % i, org="mini")
reg_wall = (time.perf_counter() - t0) * 1000
print("E1a: 100 identities in %.1fms (%.2fms/id)" % (reg_wall, reg_wall / 100))

# E1b: credential
p.register_identity("agent://mini/iss", org="mini")
p.register_identity("agent://mini/sub", org="mini")
scope = ["read", "write"]
res = p.issue_credential("agent://mini/iss", "agent://mini/sub", "svc://mini", scope)
wire = res["cred"]
cred_size = len(json.dumps(wire, ensure_ascii=False).encode("utf-8"))
print("E1b: credential size = %d bytes" % cred_size)

iss_b = benchmark(
    lambda: p.issue_credential("agent://mini/iss", "agent://mini/sub", "svc://mini", scope)["ok"],
    n=50, warmup=5)
print("E1b: issue median=%.2f p95=%.2f p99=%.2f ms" % (
    iss_b["median_ms"], iss_b["p95_ms"], iss_b["p99_ms"]))

ver_b = benchmark(
    lambda: p.verify_credential(wire, audience="svc://mini", record_nonce=False)["ok"],
    n=50, warmup=5)
print("E1b: verify median=%.2f p95=%.2f p99=%.2f ms" % (
    ver_b["median_ms"], ver_b["p95_ms"], ver_b["p99_ms"]))

# E1c: 3-hop delegation
p.register_identity("agent://mini/dep/root", org="mini")
p.register_identity("agent://mini/dep/a1", org="mini")
p.register_identity("agent://mini/dep/a2", org="mini")
root_cred = p.issue_credential("agent://mini/dep/root", "agent://mini/dep/root", "svc://mini", scope)["cred"]
d1 = p.issue_delegation("agent://mini/dep/root", "agent://mini/dep/a1", "svc://mini", scope, parent_cred=root_cred)
d2 = p.issue_delegation("agent://mini/dep/a1", "agent://mini/dep/a2", "svc://mini", scope, parent_cred=d1["cred"])
chain = [root_cred, d1["cred"], d2["cred"]]
dep_b = benchmark(
    lambda: p.verify_delegation_chain(chain, "svc://mini", ["read"])["ok"],
    n=30, warmup=5)
print("E1c: 3-hop delegation verify median=%.2f p95=%.2f ms" % (
    dep_b["median_ms"], dep_b["p95_ms"]))

pers.close()
try:
    os.remove(db)
except Exception:
    pass
print("MINI BENCHMARK DONE")