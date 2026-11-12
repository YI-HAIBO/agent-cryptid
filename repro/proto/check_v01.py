# -*- coding: utf-8 -*-
"""v0.1 核心闭环集成验证。

三层：
    A. 身份层：IdentityAuthority 派生标识密钥 + 签名验签
    B. 凭证层：凭证签发 / 校验 / 撤销 / 防重放 / 档位绑定
    C. 委托链：多跳委托 + 审计哈希链存证

外加安全性质测试：防混淆代理人、防降级、防跨服务挪用、防跳链伪造。

产物：check_v01_report.txt
"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from identity import IdentityAuthority, verify_id
from credential import (
    Credential, ALG_SM2, ALG_SM2_MLDSA, ALG_HASH_SIG,
)
from delegation import build_chain, verify_chain, AuditLog
import sm2


lines = []


def rec(label, ok, detail=""):
    lines.append("%s  %s%s" % ("PASS" if ok else "FAIL", label,
                               ("  " + detail) if detail else ""))


# ============================================================
# 一、身份层
# ============================================================
lines.append("=== 一、身份层（IdentityAuthority） ===")
for name, ok in IdentityAuthority.__module__ and __import__(
        "identity").self_check():
    rec(name, ok)

# ============================================================
# 二、凭证层
# ============================================================
lines.append("")
lines.append("=== 二、凭证层（Credential） ===")
from credential import self_check as cred_self_check
for name, ok in cred_self_check():
    rec(name, ok)

# ============================================================
# 三、委托链
# ============================================================
lines.append("")
lines.append("=== 三、委托链（Delegation） ===")
from delegation import self_check as del_self_check
for name, ok in del_self_check():
    rec(name, ok)

# ============================================================
# 四、集成：完整业务场景（签发 → 委托 → 使用 → 撤销）
# ============================================================
lines.append("")
lines.append("=== 四、集成场景：完整业务闭环 ===")

ia = IdentityAuthority()
IDS = [
    "agent://root/issuance-authority",
    "agent://org-a/orchestrator",
    "agent://org-a/worker-01",
    "agent://org-b/subagent-02",
    "agent://org-c/external-03",
]
pubs = {}
for idn in IDS:
    _, p, _ = ia.issue(idn.encode("utf-8"))
    pubs[idn] = p

AUD = "service://invoice"
SCOPE = ["invoice:read", "invoice:list"]
TTL = 3600

# 场景 1：三跳委托链
chain = build_chain(ia, IDS[0], IDS[1], AUD, SCOPE, TTL,
                    [IDS[2], IDS[3]])
now = int(time.time())
ok, reasons = verify_chain(chain, pubs, now=now)
rec("场景1 三跳委托链完整通过", ok,
    "链长 %d, 逐跳 %s" % (len(chain), reasons))

# 场景 2：篡改中间跳签名（改 scope 再签）
tamp = list(chain)
c = tamp[1]
c.scope = ("invoice:admin",)  # 篡改 scope
tamp[1] = c
ok2, reasons2 = verify_chain(tamp, pubs, now=now)
rec("场景2 中间跳 scope 篡改后失败", not ok2)

# 场景 3：中间跳过期
expired_chain = list(chain)
expired_chain[1].exp = now - 60
ok3, reasons3 = verify_chain(expired_chain, pubs, now=now)
rec("场景3 中间跳过期后失败", not ok3)

# 场景 4：受众不一致（下一跳 aud 篡改）
aud_flip = list(chain)
aud_flip[2].aud = "service://payment"
# 需要重签才能通过签名校验，否则签名失败
ok4, reasons4 = verify_chain(aud_flip, pubs, now=now)
rec("场景4 篡改下游 aud 后签名失败", not ok4)

# 场景 5：撤销末端跳
revoked_chain = list(chain)
revoked = {revoked_chain[-1].jti}
ok5, reasons5 = verify_chain(revoked_chain, pubs, now=now,
                             revoked_jtis=revoked)
rec("场景5 末端跳撤销后失败", not ok5)

# 场景 6：nonce 复用（把同一跳凭证重复用）
nonce_seen = {chain[0].nonce}
ok6, reasons6 = verify_chain(chain, pubs, now=now,
                             seen_nonces=nonce_seen)
rec("场景6 根跳 nonce 复现后失败", not ok6)

# ============================================================
# 五、审计哈希链
# ============================================================
lines.append("")
lines.append("=== 五、审计哈希链（AuditLog） ===")

audit = AuditLog()
for i, cred in enumerate(chain):
    audit.append({
        "kind": "delegate" if i > 0 else "issue",
        "seq": i,
        "issuer": cred.iss,
        "subject": cred.sub,
        "jti": cred.jti,
        "alg_tier": cred.alg_tier,
    })
rec("审计链写入 %d 条" % len(chain), audit.count() == len(chain))
rec("审计链根哈希非空", audit.root_hash is not None and len(audit.root_hash) == 64)
ok7, why7 = audit.verify()
rec("审计链完整性", ok7, why7)

# ============================================================
# 六、性能
# ============================================================
lines.append("")
lines.append("=== 六、性能 ===")

t0 = time.time()
for _ in range(3):
    chain_p = build_chain(ia, IDS[0], IDS[1], AUD, SCOPE, TTL,
                          [IDS[2], IDS[3]])
elapsed_build = (time.time() - t0) / 3
t0 = time.time()
ok, _ = verify_chain(chain_p, pubs, now=int(time.time()))
elapsed_verify = time.time() - t0

lines.append("PERF  建链（4 跳含签发） %.1f ms" % (elapsed_build * 1000))
lines.append("PERF  验链（4 跳） %.1f ms" % (elapsed_verify * 1000))

# ============================================================
# 汇总
# ============================================================
lines.append("")
n_fail = sum(1 for x in lines if x.startswith("FAIL"))
n_pass = sum(1 for x in lines if x.startswith("PASS"))
lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))

out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "check_v01_report.txt")
with io.open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(out)
