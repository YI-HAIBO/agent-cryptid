# -*- coding: utf-8 -*-
"""FR2-06 速率限制与配额管理。

三级滑动窗口限流：
    · tenant   租户级（防单租户打爆）
    · identity 标识级（防单标识刷接口）
    · endpoint 端点级（防单端点被刷）

任一维度超限即拒绝，返回 429 + Retry-After。
配额统计可导出到 /metrics 与审计链。

设计要点：
    · 纯 Python 零依赖，滑动窗口用 deque 实现。
    · 可注入持久化后端，跨进程共享（多 worker 场景）。
    · 内存模式适合单机 demo / 单 worker；生产建议接 Redis。
    · 限流决策全部入审计，便于事后追溯与调参。
"""
import sys
import os
import time
from collections import deque
from typing import Optional, List, Dict, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class QuotaConfig:
    """限流配额配置。

    window_seconds  滑动窗口长度（秒）
    tenant_limit    租户级窗口内最大请求数；None=不限
    identity_limit  标识级窗口内最大请求数；None=不限
    endpoint_limit  端点级窗口内最大请求数；None=不限

    端点级支持按路径精确配置（endpoint_limits 字典），
    未命中时退回 endpoint_limit 兜底。
    """

    def __init__(self, window_seconds=60,
                 tenant_limit=1000,
                 identity_limit=200,
                 endpoint_limit=500,
                 endpoint_limits=None):
        self.window_seconds = window_seconds
        self.tenant_limit = tenant_limit
        self.identity_limit = identity_limit
        self.endpoint_limit = endpoint_limit
        self.endpoint_limits = endpoint_limits or {}

    def limit_for(self, level: str, key: str = "") -> Optional[int]:
        """查某级某 key 的限额。"""
        if level == "tenant":
            return self.tenant_limit
        if level == "identity":
            return self.identity_limit
        if level == "endpoint":
            if key in self.endpoint_limits:
                return self.endpoint_limits[key]
            return self.endpoint_limit
        return None

    def to_dict(self) -> dict:
        return {
            "window_seconds": self.window_seconds,
            "tenant_limit": self.tenant_limit,
            "identity_limit": self.identity_limit,
            "endpoint_limit": self.endpoint_limit,
            "endpoint_limits": dict(self.endpoint_limits),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "QuotaConfig":
        return cls(
            window_seconds=d.get("window_seconds", 60),
            tenant_limit=d.get("tenant_limit", 1000),
            identity_limit=d.get("identity_limit", 200),
            endpoint_limit=d.get("endpoint_limit", 500),
            endpoint_limits=d.get("endpoint_limits") or {},
        )


class _Window:
    """单个滑动窗口计数器。"""

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._events = deque()  # 时间戳序列

    def allow(self, now: int) -> Tuple[bool, int]:
        """检查是否允许；返回 (是否允许, 当前窗口计数)。"""
        cutoff = now - self.window_seconds
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        self._events.append(now)
        return True, len(self._events)

    def count(self, now: int) -> int:
        """当前窗口计数（不写入）。"""
        cutoff = now - self.window_seconds
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        return len(self._events)

    def reset(self):
        self._events.clear()

    def earliest(self, now: int) -> int:
        """最早允许下一次请求的时间（秒级）。"""
        if not self._events:
            return now
        cutoff = now - self.window_seconds
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        if not self._events:
            return now
        return self._events[0] + self.window_seconds

    def state(self) -> list:
        return list(self._events)

    def load_state(self, events: list, now: int):
        """从持久化状态恢复（过滤过期事件）。"""
        cutoff = now - self.window_seconds
        self._events = deque(t for t in events if t > cutoff)


class RateLimiter:
    """三级滑动窗口速率限制器。

    使用：
        rl = RateLimiter(QuotaConfig(tenant_limit=1000,
                                     identity_limit=200,
                                     endpoint_limit=500))
        ok, why = rl.check(tenant="t1", identity="agent://x",
                           endpoint="/v1/credentials")
        if not ok:
            return 429, {"retry_after": why["retry_after"]}

    配额命中时返回 (False, reason_dict)，reason_dict 含：
        · level         命中的维度
        · key           命中的 key
        · current       当前计数
        · limit         配额上限
        · retry_after   建议等待秒数（窗口内最早可用时刻与现在的差）
    """

    def __init__(self, config: Optional[QuotaConfig] = None,
                 now_fn=None):
        self.config = config or QuotaConfig()
        # now_fn 可注入（测试用）；生产用 time.time
        self._now = now_fn if now_fn else (lambda: int(time.time()))
        # 三级窗口缓存：(level, key) -> _Window
        self._windows: Dict[Tuple[str, str], _Window] = {}
        # 配额统计（供 /metrics）
        self._stats = {
            "allowed": 0,
            "rejected": 0,
            "rejected_by_tenant": 0,
            "rejected_by_identity": 0,
            "rejected_by_endpoint": 0,
        }

    def _window(self, level: str, key: str) -> _Window:
        k = (level, key)
        w = self._windows.get(k)
        if w is None:
            w = _Window(self.config.window_seconds)
            self._windows[k] = w
        return w

    def check(self, tenant: str, identity: Optional[str] = None,
              endpoint: Optional[str] = None) -> Tuple[bool, dict]:
        """检查是否允许该请求。

        tenant     租户 ID（必填）
        identity   标识 ID（可选，未提供则跳过标识级）
        endpoint   端点路径（可选，未提供则跳过端点级）

        返回 (ok, reason)。ok=True 时 reason={"level": None}。
        """
        now = self._now()

        # 租户级
        t_limit = self.config.limit_for("tenant")
        if t_limit is not None:
            w = self._window("tenant", tenant)
            cur = w.count(now)
            if cur + 1 > t_limit:
                retry = max(1, w.earliest(now) - now)
                self._stats["rejected"] += 1
                self._stats["rejected_by_tenant"] += 1
                return False, {
                    "level": "tenant", "key": tenant,
                    "current": cur, "limit": t_limit,
                    "retry_after": retry,
                    "reason": "tenant rate limit exceeded",
                }

        # 标识级
        if identity is not None:
            i_limit = self.config.limit_for("identity")
            if i_limit is not None:
                w = self._window("identity", identity)
                cur = w.count(now)
                if cur + 1 > i_limit:
                    retry = max(1, w.earliest(now) - now)
                    self._stats["rejected"] += 1
                    self._stats["rejected_by_identity"] += 1
                    return False, {
                        "level": "identity", "key": identity,
                        "current": cur, "limit": i_limit,
                        "retry_after": retry,
                        "reason": "identity rate limit exceeded",
                    }

        # 端点级
        if endpoint is not None:
            e_limit = self.config.limit_for("endpoint", endpoint)
            if e_limit is not None:
                w = self._window("endpoint", endpoint)
                cur = w.count(now)
                if cur + 1 > e_limit:
                    retry = max(1, w.earliest(now) - now)
                    self._stats["rejected"] += 1
                    self._stats["rejected_by_endpoint"] += 1
                    return False, {
                        "level": "endpoint", "key": endpoint,
                        "current": cur, "limit": e_limit,
                        "retry_after": retry,
                        "reason": "endpoint rate limit exceeded",
                    }

        # 全部通过，记账
        if t_limit is not None:
            self._window("tenant", tenant).allow(now)
        if identity is not None:
            i_limit = self.config.limit_for("identity")
            if i_limit is not None:
                self._window("identity", identity).allow(now)
        if endpoint is not None:
            e_limit = self.config.limit_for("endpoint", endpoint)
            if e_limit is not None:
                self._window("endpoint", endpoint).allow(now)
        self._stats["allowed"] += 1
        return True, {"level": None}

    def reset(self):
        """清空所有窗口（测试/运维用）。"""
        self._windows.clear()

    def stats(self) -> dict:
        """导出配额统计快照（供 /metrics）。"""
        return dict(self._stats)

    def quota_usage(self, tenant: str, identity: Optional[str] = None,
                    endpoint: Optional[str] = None) -> dict:
        """查询当前配额使用率（供治理台 / 运维面板）。"""
        now = self._now()
        usage = {}
        t_limit = self.config.limit_for("tenant")
        if t_limit is not None:
            cur = self._window("tenant", tenant).count(now)
            usage["tenant"] = {
                "key": tenant, "current": cur, "limit": t_limit,
                "ratio": round(cur / t_limit, 4) if t_limit else 0,
            }
        if identity is not None:
            i_limit = self.config.limit_for("identity")
            if i_limit is not None:
                cur = self._window("identity", identity).count(now)
                usage["identity"] = {
                    "key": identity, "current": cur, "limit": i_limit,
                    "ratio": round(cur / i_limit, 4) if i_limit else 0,
                }
        if endpoint is not None:
            e_limit = self.config.limit_for("endpoint", endpoint)
            if e_limit is not None:
                cur = self._window("endpoint", endpoint).count(now)
                usage["endpoint"] = {
                    "key": endpoint, "current": cur, "limit": e_limit,
                    "ratio": round(cur / e_limit, 4) if e_limit else 0,
                }
        return usage

    def state_dict(self) -> dict:
        """导出全部窗口状态（供持久化）。"""
        return {
            "config": self.config.to_dict(),
            "windows": {
                "%s:%s" % (level, key): w.state()
                for (level, key), w in self._windows.items()
            },
            "stats": dict(self._stats),
        }

    def load_state(self, state: dict):
        """从持久化状态恢复。"""
        cfg = state.get("config")
        if cfg:
            self.config = QuotaConfig.from_dict(cfg)
        now = self._now()
        for key, events in state.get("windows", {}).items():
            if ":" not in key:
                continue
            level, ident = key.split(":", 1)
            w = self._window(level, ident)
            w.load_state(events, now)
        stats = state.get("stats")
        if stats:
            self._stats.update(stats)


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def self_check():
    out = []
    cfg = QuotaConfig(window_seconds=60, tenant_limit=5,
                      identity_limit=3, endpoint_limit=10)
    rl = RateLimiter(cfg)

    # 租户级：前 5 次放行
    for i in range(5):
        ok, _ = rl.check(tenant="t1", endpoint="/v1/identities")
        out.append(("A.%d 租户前5放行" % i, ok))
    # 第 6 次租户超限
    ok, why = rl.check(tenant="t1", endpoint="/v1/identities")
    out.append(("A.6 租户第6次拒绝", not ok))
    out.append(("A.7 拒绝原因=tenant", why["level"] == "tenant"))
    out.append(("A.8 拒绝含 retry_after", why["retry_after"] >= 1))

    # 标识级：用新租户，标识限 3
    rl2 = RateLimiter(QuotaConfig(window_seconds=60, tenant_limit=100,
                                  identity_limit=3, endpoint_limit=100))
    for i in range(3):
        ok, _ = rl2.check(tenant="t2", identity="agent://a",
                          endpoint="/v1/credentials")
        out.append(("B.%d 标识前3放行" % i, ok))
    ok, why = rl2.check(tenant="t2", identity="agent://a",
                        endpoint="/v1/credentials")
    out.append(("B.4 标识第4次拒绝", not ok))
    out.append(("B.5 拒绝原因=identity", why["level"] == "identity"))

    # 端点级：精确配置
    cfg3 = QuotaConfig(window_seconds=60, tenant_limit=100,
                       identity_limit=100, endpoint_limit=100,
                       endpoint_limits={"/v1/credentials": 2})
    rl3 = RateLimiter(cfg3)
    for i in range(2):
        ok, _ = rl3.check(tenant="t3", endpoint="/v1/credentials")
        out.append(("C.%d 端点前2放行" % i, ok))
    ok, why = rl3.check(tenant="t3", endpoint="/v1/credentials")
    out.append(("C.3 端点第3次拒绝", not ok))
    out.append(("C.4 拒绝原因=endpoint", why["level"] == "endpoint"))

    # 同租户不同标识独立计数
    rl4 = RateLimiter(QuotaConfig(window_seconds=60, tenant_limit=100,
                                  identity_limit=2, endpoint_limit=100))
    for i in range(2):
        rl4.check(tenant="t4", identity="agent://a", endpoint="/v1/x")
    ok_a, _ = rl4.check(tenant="t4", identity="agent://a", endpoint="/v1/x")
    ok_b, _ = rl4.check(tenant="t4", identity="agent://b", endpoint="/v1/x")
    out.append(("D.1 标识a超限", not ok_a))
    out.append(("D.2 标识b独立放行", ok_b))

    # 配额使用率
    usage = rl3.quota_usage("t3", endpoint="/v1/credentials")
    out.append(("E.1 配额使用率含 endpoint", "endpoint" in usage))
    out.append(("E.2 ratio 正确（2/2=1.0）", usage["endpoint"]["ratio"] == 1.0))

    # 统计
    s = rl3.stats()
    out.append(("F.1 统计含 allowed", s["allowed"] == 2))
    out.append(("F.2 统计含 rejected", s["rejected"] == 1))

    # 状态持久化
    st = rl3.state_dict()
    rl3b = RateLimiter(QuotaConfig())
    rl3b.load_state(st)
    ok, why = rl3b.check(tenant="t3", endpoint="/v1/credentials")
    out.append(("G.1 恢复后第3次仍拒绝", not ok))
    out.append(("G.2 恢复后配额配置正确",
                rl3b.config.endpoint_limits.get("/v1/credentials") == 2))

    # 重置
    rl3b.reset()
    ok, _ = rl3b.check(tenant="t3", endpoint="/v1/credentials")
    out.append(("H.1 重置后放行", ok))

    # 无限额=不限
    rl5 = RateLimiter(QuotaConfig(tenant_limit=None, identity_limit=None,
                                  endpoint_limit=None))
    for i in range(100):
        ok, _ = rl5.check(tenant="t5", identity="a", endpoint="/v1/x")
        assert ok, "无限额应不限"
    out.append(("I.1 无限额=不限", True))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
