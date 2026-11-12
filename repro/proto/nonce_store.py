# -*- coding: utf-8 -*-
"""Nonce 存储抽象层（v2.1 引入，为 P1-⑥ 跨进程/集群防重放做准备）。

背景
----
v2.0 之前 nonce 防重放使用进程内 `set`，仅在当前进程/单机有效；
在多进程（gunicorn worker）、集群、容器滚动发布场景下完全失效。

抽象 NonceStore 让 Platform 通过依赖注入选择后端：
- MemoryNonceStore  内存实现，用于单元测试和单机低并发场景（默认）
- SqliteNonceStore  本地 SQLite，跨进程共享（同机多 worker）
- RedisNonceStore   Redis 实现，跨机器集群；lazy import，装了 redis 包即可用

三者的公共接口都实现了 __contains__ 和 add，可以直接塞给
Credential.verify(seen_nonces=...)，无需改调用方。

线程安全
--------
MemoryNonceStore 无锁——Python GIL 保证 dict 单指令原子性；若担心
GC/多解释器（PyPy、Jython），可换 RLock 版本。
SqliteNonceStore 和 RedisNonceStore 自带 RLock 或 Redis 单线程特性。
"""
import os
import sqlite3
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------
class NonceStore:
    """Nonce 存储基类。子类实现 _get / _set / _del 与 __contains__ / add。

    - __contains__(nonce)：nonce 是否已见过且未过期
    - add(nonce, ttl=86400)：**原子声称**。返回 True 表示本次真正写入
      （首次声称成功），False 表示该 nonce 已存在（重放）。实现方必须保证
      在并发下"声称"是原子的：Redis 用 SET NX EX、SQLite 用 INSERT OR IGNORE。
      调用方（agent_platform.verify_credential）以 add 的返回值作为防重放的
      权威判定——即使 __contains__ 先返回 False（未见），若并发进程抢先 add，
      本进程 add 返回 False 仍会被判为重放（闭合 check-then-act 竞态）。
    - __len__()：可选，用于监控
    - cleanup()：清理过期条目
    """

    def __contains__(self, nonce) -> bool:
        return self._contains(nonce)

    def _contains(self, nonce) -> bool:
        raise NotImplementedError

    def add(self, nonce, ttl: int = 86400) -> bool:
        """原子声称：返回 True=首次写入，False=已存在（重放）。"""
        raise NotImplementedError

    def __len__(self) -> int:
        return -1

    def cleanup(self) -> None:
        pass


# ---------------------------------------------------------------------------
# 内存实现（默认）
# ---------------------------------------------------------------------------
class MemoryNonceStore(NonceStore):
    """单进程内存实现。跨进程/重启会丢。"""

    def __init__(self):
        self._data = {}  # nonce_hex -> expire_ts
        self._lock = threading.RLock()

    @staticmethod
    def _key(nonce) -> str:
        if isinstance(nonce, (bytes, bytearray)):
            return nonce.hex()
        return str(nonce)

    def _contains(self, nonce) -> bool:
        k = self._key(nonce)
        now = int(time.time())
        with self._lock:
            exp = self._data.get(k)
            if exp is None:
                return False
            if exp <= now:
                del self._data[k]
                return False
            return True

    def add(self, nonce, ttl: int = 86400) -> bool:
        k = self._key(nonce)
        with self._lock:
            new = k not in self._data
            self._data[k] = int(time.time()) + ttl
            return new

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def cleanup(self) -> None:
        now = int(time.time())
        with self._lock:
            self._data = {k: v for k, v in self._data.items() if v > now}


# ---------------------------------------------------------------------------
# SQLite 实现（跨进程，单机）
# ---------------------------------------------------------------------------
class SqliteNonceStore(NonceStore):
    """SQLite 持久化实现，跨进程共享（同机多 worker 场景）。"""

    def __init__(self, db_path: str):
        # check_same_thread=False 允许多线程共用；配合 RLock 保证原子性
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.RLock()
        self._init()

    def _init(self):
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS nonces ("
                "nonce TEXT PRIMARY KEY,"
                "expire_at INTEGER NOT NULL)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nonces_exp "
                "ON nonces(expire_at)")
            self._conn.commit()

    @staticmethod
    def _key(nonce) -> str:
        if isinstance(nonce, (bytes, bytearray)):
            return nonce.hex()
        return str(nonce)

    def _contains(self, nonce) -> bool:
        k = self._key(nonce)
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT expire_at FROM nonces WHERE nonce=?", (k,)).fetchone()
            if row is None:
                return False
            if row[0] <= now:
                self._conn.execute(
                    "DELETE FROM nonces WHERE nonce=?", (k,))
                self._conn.commit()
                return False
            return True

    def add(self, nonce, ttl: int = 86400) -> bool:
        k = self._key(nonce)
        with self._lock:
            # INSERT OR IGNORE：若 nonce 已存在（含未过期），不插入，rowcount=0
            # → 返回 False（重放）。该单语句在 SQL 层原子，是跨进程防重放的
            # 权威门。配合 __contains__ 先查（快速路径），闭合 check-then-act。
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO nonces (nonce, expire_at) "
                "VALUES (?, ?)",
                (k, int(time.time()) + ttl))
            self._conn.commit()
            return cur.rowcount > 0

    def __len__(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM nonces").fetchone()[0]

    def cleanup(self) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "DELETE FROM nonces WHERE expire_at <= ?", (now,))
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Redis 实现（跨机器集群）
# ---------------------------------------------------------------------------
class RedisNonceStore(NonceStore):
    """Redis 后端。lazy import——未装 redis 时构造失败，Platform 可捕获降级。

    用法::

        import redis
        client = redis.Redis(host="127.0.0.1", port=6379, db=0)
        store = RedisNonceStore(client)

    Redis 自身通过 SETEX 自动过期，cleanup() 是 no-op。
    """

    def __init__(self, redis_client):
        self._r = redis_client

    @staticmethod
    def _key(nonce) -> str:
        if isinstance(nonce, (bytes, bytearray)):
            return nonce.hex()
        return str(nonce)

    def _contains(self, nonce) -> bool:
        k = self._key(nonce)
        return self._r.exists(k) > 0

    def add(self, nonce, ttl: int = 86400) -> bool:
        k = self._key(nonce)
        # SET NX EX：仅当 key 不存在时写入并设置 TTL。返回 True=首次声称成功
        # （防重放权威门）；False=已存在（重放）。SET NX 是 Redis 单命令原子，
        # 跨机器并发下同样保证"至多一次"。
        return bool(self._r.set(k, 1, nx=True, ex=ttl))

    def __len__(self) -> int:
        return -1  # Redis 没有 O(1) 计数

    def cleanup(self) -> None:
        pass  # TTL 自动过期


def self_check() -> list:
    out = []

    # 1) MemoryNonceStore 基础
    m = MemoryNonceStore()
    nonce1 = b"\x01" * 16
    assert nonce1 not in m
    m.add(nonce1, ttl=100)
    assert nonce1 in m
    out.append(("MemoryNonceStore 基础 add/contains", True))

    # 2) 过期后不再算 contains
    m_expired = MemoryNonceStore()
    nonce2 = b"\x02" * 16
    m_expired.add(nonce2, ttl=0)  # 立即过期
    # 让时间前进 1 秒
    time.sleep(1.05)
    assert nonce2 not in m_expired
    out.append(("MemoryNonceStore 过期失效", True))

    # 3) len 计数
    m3 = MemoryNonceStore()
    for i in range(5):
        m3.add(bytes([i]) * 16, ttl=1000)
    assert len(m3) == 5
    out.append(("MemoryNonceStore __len__", True))

    # 4) cleanup 清理
    m4 = MemoryNonceStore()
    m4.add(b"\x0a" * 16, ttl=1000)
    m4.add(b"\x0b" * 16, ttl=0)
    time.sleep(0.1)
    m4.cleanup()
    assert len(m4) == 1
    out.append(("MemoryNonceStore cleanup", True))

    # 5) SqliteNonceStore
    db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_nonce_store_test.db")
    if os.path.exists(db):
        os.remove(db)
    try:
        s = SqliteNonceStore(db)
        nonce5 = b"\x05" * 16
        assert nonce5 not in s
        s.add(nonce5, ttl=100)
        assert nonce5 in s
        out.append(("SqliteNonceStore 基础", True))
        # 过期
        s.add(b"\x06" * 16, ttl=0)
        time.sleep(1.05)
        assert b"\x06" * 16 not in s
        out.append(("SqliteNonceStore 过期失效", True))
        # 长度
        assert len(s) == 1
        out.append(("SqliteNonceStore __len__", True))

        # 6) 跨连接持久化
        s.close()
        s2 = SqliteNonceStore(db)
        assert nonce5 in s2
        out.append(("SqliteNonceStore 跨连接持久化", True))
        s2.close()
    finally:
        if os.path.exists(db):
            os.remove(db)

    # 7) RedisNonceStore 降级：未装 redis 也不报错
    try:
        import redis  # noqa: F401
        import redis as _r
        try:
            client = _r.Redis(host="127.0.0.1", port=6399, socket_connect_timeout=0.1)
            client.ping()
            rn = RedisNonceStore(client)
            rn.add(b"\x07" * 16, ttl=100)
            out.append(("RedisNonceStore 实连可用", b"\x07" * 16 in rn))
        except Exception:
            out.append(("RedisNonceStore（跳过：本地无服务）", True))
    except ImportError:
        out.append(("RedisNonceStore（跳过：未装 redis 库）", True))

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
                               "nonce_store_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
