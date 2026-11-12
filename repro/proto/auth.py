# -*- coding: utf-8 -*-
"""控制面鉴权：API Key → 租户授权表（v2.5）。

为什么必须有
------------
v2.4 之前，租户完全由请求头 `X-Tenant-Id` 决定，且**不做任何校验**——
任何拿到端口的人换一个头就能读写别人的租户（标识注册、凭证签发、撤销
全都越权）。这在 demo 里无所谓，在真实部署里是致命的横向越权漏洞。

本模块提供最小可用的控制面鉴权：
- API Key 绑定**允许操作的租户列表**（最小权限，不支持"任意租户"通配，
  除非显式配置 `"*"`）；
- 校验时用 `hmac.compare_digest` 做**常量时间比较**，防时序侧信道；
- 明文 Key **不落盘**：配置里存 SM3 摘要（32 字节 hex），校验时先摘要
  再比对，配置文件泄露也不会直接交出可用凭据；
- **默认关闭**：不配置 auth 时全部放行（向后兼容 v2.4 及之前的行为，
  demo / 单元测试不受影响）。

配置格式（`config.json` 的 `auth` 段或 `tenants` 段）
----------------------------------------------------
    {
      "auth": {
        "enabled": true,
        "keys": {
          "<sha256_or_sm3_hex_of_key>": {
            "tenants": ["acme", "acme-dev"],
            "note": "Acme 产线控制面"
          },
          "<hex>": {"tenants": ["*"], "note": "平台管理员"}
        }
      }
    }

`"*"` 表示该 Key 可操作任意租户（管理员），用于运维/审计，不应发给客户。

API
---
- `AuthTable.from_config(dict)`  从配置构造；未启用返回 None
- `AuthTable.check(api_key, tenant) -> (ok, reason)`
- `AuthTable.enabled`            是否启用
- `sm3_hex(s)`                   计算配置里要存的摘要
"""
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402


def sm3_hex(secret: str) -> str:
    """把明文 key 折算成配置里要存的摘要（SM3，64 hex 字符）。"""
    return sm2.sm3(secret.encode("utf-8")).hex()


class AuthTable:
    """API Key → 租户授权表。

    mapping: {key_digest_hex: {"tenants": [...], "note": str}}
    """

    def __init__(self, mapping=None, enabled=True):
        self.mapping = dict(mapping or {})
        self.enabled = bool(enabled)

    # ---------------------------------------------------------- 构造
    @classmethod
    def from_config(cls, cfg):
        """从配置 dict 构造。未启用 / 无 keys 时返回 None（表示"不鉴权"）。

        兼容两种写法：
          {"auth": {"enabled": true, "keys": {...}}}
          {"auth": {...}}               # 直接给 keys 映射，视为启用
        """
        if not cfg:
            return None
        a = cfg.get("auth", cfg)
        if not isinstance(a, dict):
            return None
        # 显式 enabled=false → 不鉴权
        if a.get("enabled") is False:
            return None
        keys = a.get("keys")
        if not keys:
            return None
        return cls(mapping=keys, enabled=True)

    def is_empty(self) -> bool:
        return not self.mapping

    # ---------------------------------------------------------- 校验
    def check(self, api_key, tenant):
        """校验 (api_key, tenant)。返回 (ok: bool, reason: str)。

        reason 取值：ok / auth disabled / missing api key /
                     unknown api key / tenant not allowed
        """
        if not self.enabled or not self.mapping:
            return True, "auth disabled"
        if not api_key:
            return False, "missing api key"
        digest = sm3_hex(api_key)
        # 常量时间比对：对每个候选摘要都跑一遍 compare_digest，
        # 不因"第一个不匹配"提前返回（否则泄露匹配进度）
        matched = None
        for cand in self.mapping.keys():
            if hmac.compare_digest(digest, str(cand)):
                matched = cand
        if matched is None:
            return False, "unknown api key"
        allowed = self.mapping[matched].get("tenants", [])
        if "*" in allowed or tenant in allowed:
            return True, "ok"
        return False, "tenant not allowed"

    def tenants_of(self, api_key):
        """返回该 key 允许的租户列表；未知 key 返回 []。"""
        if not api_key:
            return []
        digest = sm3_hex(api_key)
        for cand, meta in self.mapping.items():
            if hmac.compare_digest(digest, str(cand)):
                return list(meta.get("tenants", []))
        return []

    def add(self, api_key, tenants, note=""):
        """运行时追加一个 key（返回摘要，便于写回配置）。"""
        d = sm3_hex(api_key)
        self.mapping[d] = {"tenants": list(tenants), "note": note}
        return d

    def to_config(self) -> dict:
        return {"auth": {"enabled": self.enabled, "keys": self.mapping}}


def self_check() -> list:
    """鉴权表自测。"""
    out = []
    tbl = AuthTable()
    k1 = "acme-prod-key-0001"
    k2 = "globex-prod-key-0002"
    kadmin = "platform-admin-key"
    d1 = tbl.add(k1, ["acme"], note="Acme 产线")
    d2 = tbl.add(k2, ["globex"], note="Globex 产线")
    da = tbl.add(kadmin, ["*"], note="平台管理员")

    # 1) 构造正确性
    out.append(("摘要长度为 64 hex", len(d1) == 64))
    out.append(("两个 key 摘要不同", d1 != d2))

    # 2) 正常放行
    ok, why = tbl.check(k1, "acme")
    out.append(("本租户 key 放行", ok is True and why == "ok"))

    # 3) 横向越权必须拒绝 ★核心
    ok, why = tbl.check(k1, "globex")
    out.append(("跨租户访问被拒", ok is False and why == "tenant not allowed"))
    ok, why = tbl.check(k2, "acme")
    out.append(("反向跨租户也被拒", ok is False))

    # 4) 缺失 / 未知 key
    ok, why = tbl.check(None, "acme")
    out.append(("缺失 key 被拒", ok is False and why == "missing api key"))
    ok, why = tbl.check("", "acme")
    out.append(("空 key 被拒", ok is False))
    ok, why = tbl.check("wrong-key-xxxx", "acme")
    out.append(("未知 key 被拒", ok is False and why == "unknown api key"))
    # 近似 key（只差一个字符）也必须拒绝
    ok, why = tbl.check(k1[:-1] + "2", "acme")
    out.append(("近似 key 被拒", ok is False))

    # 5) 管理员通配
    ok, _ = tbl.check(kadmin, "any-tenant")
    out.append(("管理员可操作任意租户", ok is True))
    out.append(("tenants_of 返回通配",
                tbl.tenants_of(kadmin) == ["*"]))

    # 6) 未启用时全放行（向后兼容）
    off = AuthTable(mapping={}, enabled=False)
    ok, why = off.check(None, "anything")
    out.append(("未启用时全放行", ok is True and why == "auth disabled"))
    out.append(("空表视为未启用", AuthTable().check("x", "y")[0] is True))

    # 7) from_config 语义
    out.append(("from_config(None) → None",
                AuthTable.from_config(None) is None))
    out.append(("from_config(enabled=false) → None",
                AuthTable.from_config({"auth": {"enabled": False}}) is None))
    out.append(("from_config 无 keys → None",
                AuthTable.from_config({"auth": {"enabled": True}}) is None))
    t3 = AuthTable.from_config({"auth": {"enabled": True,
                                         "keys": {d1: {"tenants": ["acme"]}}}})
    out.append(("from_config 正常构造", t3 is not None))
    out.append(("from_config 后校验生效",
                t3.check(k1, "acme")[0] is True
                and t3.check(k1, "globex")[0] is False))

    # 8) 明文不落盘：映射里不应出现明文 key
    blob = json.dumps(tbl.to_config(), ensure_ascii=False)
    out.append(("配置里不含明文 key", k1 not in blob and k2 not in blob))
    out.append(("配置里含摘要", d1 in blob))

    # 9) 摘要确定性（同一 key 多次摘要一致）
    out.append(("SM3 摘要确定性", sm3_hex(k1) == sm3_hex(k1)))
    out.append(("不同 key 摘要不同", sm3_hex(k1) != sm3_hex(k2)))

    return out


def main():
    results = self_check()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%s  %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "auth_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
