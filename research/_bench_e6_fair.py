# -*- coding: utf-8 -*-
"""同跳数对比：agent-cryptid vs UCAN，均为 4 跳链式验签。

E6 表中的对比是不公平的：agent-cryptid 跑的是单跳凭证，UCAN 跑的是 4 跳链。
本脚本补齐 agent-cryptid 的 4 跳验证数据，供论文 E6 表格诚实改写。
"""
import os, sys, json, time
sys.path.insert(0, r"C:\Users\Yi\WorkBuddy\2026-10-09-07-28-12\agent-cryptid\proto")
sys.path.insert(0, r"C:\Users\Yi\WorkBuddy\2026-10-09-07-28-12\agent-cryptid\research")

import sm2
from agent_platform import Platform
from persistence import SQLiteBackend
from eval_framework import benchmark

BASE = r"C:\Users\Yi\WorkBuddy\2026-10-09-07-28-12\agent-cryptid\research"

# ---- agent-cryptid 4-hop ----
db = os.path.join(BASE, "_bench_e6_fair.db")
if os.path.exists(db): os.remove(db)
pers = SQLiteBackend(db)
p = Platform(tenant="fair", persistence=pers)

scope = ["read", "write"]
ids = ["agent://fair/root"] + ["agent://fair/a%d" % i for i in range(4)]
for i in ids:
    p.register_identity(i, org="fair")

root = p.issue_credential(ids[0], ids[0], "svc://fair", scope)["cred"]
chain = [root]
for k in range(1, 5):
    d = p.issue_delegation(ids[k-1], ids[k], "svc://fair", scope, parent_cred=chain[-1])
    chain.append(d["cred"])

t_ver = benchmark(lambda: p.verify_delegation_chain(chain, "svc://fair", scope)["ok"],
                  n=100, warmup=10)

# issue 也测一次 4 跳
def build_ac():
    db2 = os.path.join(BASE, "_bench_e6_fair2.db")
    if os.path.exists(db2): os.remove(db2)
    pers2 = SQLiteBackend(db2)
    p2 = Platform(tenant="fair2", persistence=pers2)
    try:
        for i in ids: p2.register_identity(i, org="fair2")
        root = p2.issue_credential(ids[0], ids[0], "svc://fair", scope)["cred"]
        cur = root
        for k in range(1, 5):
            d = p2.issue_delegation(ids[k-1], ids[k], "svc://fair", scope, parent_cred=cur)
            cur = d["cred"]
        return cur
    finally:
        pers2.close()
t_issue = benchmark(build_ac, n=10, warmup=2)

pers.close()

# ---- UCAN 4-hop（同 E6 实现）----
def _hmac_sm3(key, msg):
    block = 64
    if len(key) > block:
        key = sm2.sm3(key)
    key = key + b"\x00" * (block - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sm2.sm3(opad + sm2.sm3(ipad + msg))

aud = "svc://e6"; sub = "agent://e6/sub"; iss = "agent://e6/iss"
exp = int(time.time()) + 3600
keys = [sm2.gen_keypair() for _ in range(4)]

def build_ucan():
    chain, parent = [], None
    for i in range(4):
        body = json.dumps({"sub": "agent://e6/u%d" % (i + 1), "aud": aud,
                           "scope": scope, "exp": exp, "parent": parent},
                          sort_keys=True, ensure_ascii=False).encode()
        rr, ss = sm2.sign(("agent://e6/u%d" % i).encode(), keys[i][0], body)
        proof = {"body": body.decode(), "sig": "%064x%064x" % (rr, ss)}
        parent = proof
        chain.append(proof)
    return chain

def verify_ucan(chain):
    for i, pf in enumerate(chain):
        body = pf["body"].encode()
        sh = pf["sig"]
        if not sm2.verify(("agent://e6/u%d" % i).encode(), keys[i][1],
                          int(sh[:64], 16), int(sh[64:], 16), body):
            return False
    return True

uchain = build_ucan()
t_ucan_ver = benchmark(lambda: verify_ucan(uchain), n=100, warmup=10)
t_ucan_issue = benchmark(build_ucan, n=10, warmup=2)

print("=== 同 4 跳对比（同一进程、同 sm2 实现、SM2 为签名代理）===")
print("agent-cryptid (4-hop chain):  issue=%7.2f ms   verify=%7.2f ms" % (t_issue['median_ms'], t_ver['median_ms']))
print("agent-cryptid (4-hop chain):  verify p95=%6.2f p99=%6.2f ms" % (t_ver['p95_ms'], t_ver['p99_ms']))
print("UCAN        (4-hop chain):    issue=%7.2f ms   verify=%7.2f ms" % (t_ucan_issue['median_ms'], t_ucan_ver['median_ms']))
print("UCAN        (4-hop chain):    verify p95=%6.2f p99=%6.2f ms" % (t_ucan_ver['p95_ms'], t_ucan_ver['p99_ms']))
print()
print("per-hop verify (agent-cryptid): %.2f ms/hop" % (t_ver['median_ms'] / 4))
print("per-hop verify (UCAN):          %.2f ms/hop" % (t_ucan_ver['median_ms'] / 4))

for f in [db, os.path.join(BASE, "_bench_e6_fair2.db")]:
    try: os.remove(f)
    except: pass
