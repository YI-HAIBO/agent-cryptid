# -*- coding: utf-8 -*-
"""持久化层：SQLite 后端，支持多租户。

六张表：
    identities          标识登记簿（tenant_id, idn, pub_x, pub_y, status, meta_json）
    revocations         撤销日志（tenant_id, version, jti, reason, ts）
    audit_log           审计事件（tenant_id, seq, ts, kind, hash, prev_hash, event_json）
    audit_anchors       审计锚点（tenant_id, anchor_id, ts, root_hash, chain_len,
                                        issuer_idn, sig_r, sig_s）
    revocation_state    撤销累加器状态（tenant_id, leaves_json, jti_index_json,
                                        capacity, count, frozen_roots_json, version）
    policy              策略快照（tenant_id, key, value_json）

所有表都以 tenant_id 为第一列，WHERE 条件强制带上，物理上隔离多租户。
凭证正文不入库，只存 jti 索引与 wire 编码，控制面不持久化凭证全文。
"""
import json
import os
import sqlite3
import threading
import time


SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    tenant_id   TEXT NOT NULL,
    idn         TEXT NOT NULL,
    pub_x       TEXT NOT NULL,
    pub_y       TEXT NOT NULL,
    status      TEXT NOT NULL,
    meta_json   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, idn)
);
CREATE TABLE IF NOT EXISTS revocations (
    tenant_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    jti         TEXT NOT NULL,
    reason      TEXT,
    ts          INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, version),
    UNIQUE (tenant_id, jti)
);
CREATE TABLE IF NOT EXISTS audit_log (
    tenant_id   TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    kind        TEXT,
    hash        TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    event_json  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
CREATE TABLE IF NOT EXISTS audit_anchors (
    tenant_id   TEXT NOT NULL,
    anchor_id   INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    root_hash   TEXT NOT NULL,
    chain_len   INTEGER NOT NULL,
    issuer_idn  TEXT NOT NULL,
    -- sig_r / sig_s 是 SM2 256 位标量，超过 SQLite 64 位 INTEGER 范围
    -- （2^63-1），必须存 hex 字符串，读出时再转回 int
    sig_r       TEXT,
    sig_s       TEXT,
    PRIMARY KEY (tenant_id, anchor_id)
);
CREATE TABLE IF NOT EXISTS policy (
    tenant_id   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
-- v2.4：撤销累加器状态快照（避免每次启动 O(n) replay 重建）
CREATE TABLE IF NOT EXISTS revocation_state (
    tenant_id          TEXT NOT NULL,
    version            INTEGER NOT NULL,
    capacity           INTEGER NOT NULL,
    count              INTEGER NOT NULL,
    leaves_json        TEXT NOT NULL,
    frozen_roots_json  TEXT NOT NULL,
    jti_index_json     TEXT NOT NULL,
    ts                 INTEGER NOT NULL,
    PRIMARY KEY (tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_revocations_tenant ON revocations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_kind ON audit_log(tenant_id, kind);
CREATE INDEX IF NOT EXISTS idx_anchors_tenant_ts ON audit_anchors(tenant_id, ts);
"""


class SQLiteBackend:
    """SQLite 持久化后端。线程安全（内部加锁）。"""

    def __init__(self, path=":memory:"):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        with self._lock:
            # v2.18（E11-f 归因）：WAL + 并发写等待。默认 rollback journal 下
            # 每次写 commit 触发一次 fsync，写路径仅 ~8 TPS（E11-f 实测）；
            # 且无 busy_timeout（SQLite 默认 0）时，并发多进程写直接抛
            # "database is locked"，进程级并行部署不可用。WAL 恢复 ~66x 写
            # 吞吐，synchronous=NORMAL 与 WAL 配套，busy_timeout=5000 让写者
            # 在锁上排队而非立即失败。与 SqliteNonceStore 同款 WAL 配置。
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ---------------------------------------------------------- 标识
    def put_identity(self, tenant, idn, pub_x, pub_y, status, meta):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO identities"
                "(tenant_id, idn, pub_x, pub_y, status, meta_json)"
                " VALUES(?,?,?,?,?,?)",
                (tenant, idn, pub_x, pub_y, status,
                 json.dumps(meta, ensure_ascii=False)))
            self._conn.commit()

    def get_identity(self, tenant, idn):
        with self._lock:
            row = self._conn.execute(
                "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
                " WHERE tenant_id=? AND idn=?", (tenant, idn)).fetchone()
        if not row:
            return None
        return {"idn": row[0], "pub_x": row[1], "pub_y": row[2],
                "status": row[3],
                "meta": json.loads(row[4])}

    def list_identities(self, tenant, status=None, limit=200):
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
                    " WHERE tenant_id=? AND status=? LIMIT ?",
                    (tenant, status, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
                    " WHERE tenant_id=? LIMIT ?",
                    (tenant, limit)).fetchall()
        return [{"idn": r[0], "pub_x": r[1], "pub_y": r[2],
                 "status": r[3], "meta": json.loads(r[4])}
                for r in rows]

    # ---------------------------------------------------------- 撤销
    def append_revocation(self, tenant, version, jti, reason, ts):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO revocations"
                "(tenant_id, version, jti, reason, ts)"
                " VALUES(?,?,?,?,?)",
                (tenant, version, jti, reason, ts))
            self._conn.commit()

    def is_revoked(self, tenant, jti):
        with self._lock:
            return bool(self._conn.execute(
                "SELECT 1 FROM revocations WHERE tenant_id=? AND jti=?",
                (tenant, jti)).fetchone())

    def revocation_snapshot(self, tenant, since_version=0):
        with self._lock:
            rows = self._conn.execute(
                "SELECT version, jti, reason, ts FROM revocations"
                " WHERE tenant_id=? AND version>? ORDER BY version",
                (tenant, since_version)).fetchall()
            current = self._conn.execute(
                "SELECT COALESCE(MAX(version),0) FROM revocations"
                " WHERE tenant_id=?", (tenant,)).fetchone()[0]
            total = self._conn.execute(
                "SELECT COUNT(*) FROM revocations WHERE tenant_id=?",
                (tenant,)).fetchone()[0]
        return {
            "current_version": current,
            "since_version": since_version,
            "entries": [{"version": r[0], "jti": r[1], "reason": r[2],
                         "ts": r[3]} for r in rows],
            "total_revoked": total,
        }

    # ---------------------------------------------------------- 审计
    def append_audit(self, tenant, seq, ts, kind, h, prev, event):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_log"
                "(tenant_id, seq, ts, kind, hash, prev_hash, event_json)"
                " VALUES(?,?,?,?,?,?,?)",
                (tenant, seq, ts, kind, h, prev,
                 json.dumps(event, ensure_ascii=False)))
            self._conn.commit()

    def query_audit(self, tenant, kind=None, idn=None, limit=100):
        with self._lock:
            if kind:
                rows = self._conn.execute(
                    "SELECT seq, ts, kind, hash, prev_hash, event_json"
                    " FROM audit_log WHERE tenant_id=? AND kind=?"
                    " ORDER BY seq DESC LIMIT ?",
                    (tenant, kind, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT seq, ts, kind, hash, prev_hash, event_json"
                    " FROM audit_log WHERE tenant_id=?"
                    " ORDER BY seq DESC LIMIT ?",
                    (tenant, limit)).fetchall()
        out = []
        for r in rows:
            ev = json.loads(r[5])
            if idn and idn not in (ev.get("idn"), ev.get("iss"),
                                    ev.get("sub"), ev.get("delegator"),
                                    ev.get("delegatee")):
                continue
            out.append({"seq": r[0], "ts": r[1], "kind": r[2],
                        "hash": r[3], "prev_hash": r[4], "event": ev})
        return out

    # ---------------------------------------------------------- 审计锚点
    def append_audit_anchor(self, tenant, anchor):
        """追加一个审计锚点。anchor 是 AuditAnchor.to_dict() 的结构。

        SM2 签名分量 sig_r/sig_s 是 256 位整数，SQLite INTEGER 只支持
        64 位（2^63-1），会抛 OverflowError。这里统一转 hex 字符串入库，
        读取时再 int(..., 16) 还原。
        """
        def _hex(v):
            if v is None:
                return None
            if isinstance(v, int):
                return hex(v)[2:]  # 无前缀 hex
            return str(v)

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_anchors"
                "(tenant_id, anchor_id, ts, root_hash, chain_len,"
                " issuer_idn, sig_r, sig_s) VALUES(?,?,?,?,?,?,?,?)",
                (tenant, anchor.get("anchor_id"), anchor.get("ts"),
                 anchor.get("root_hash"), anchor.get("chain_len"),
                 anchor.get("issuer_idn"),
                 _hex(anchor.get("sig_r")), _hex(anchor.get("sig_s"))))
            self._conn.commit()

    def list_audit_anchors(self, tenant, since_ts=None, limit=100):
        """列出锚点，按 (ts, anchor_id) 倒序。返回 dict 列表。

        把 sig_r / sig_s 从 hex 字符串还原成 int，与 AuditAnchor 内存态一致。
        """
        def _unhex(v):
            if v is None or v == "":
                return None
            if isinstance(v, int):
                return v
            try:
                return int(v, 16)
            except Exception:
                return v

        with self._lock:
            if since_ts is not None:
                rows = self._conn.execute(
                    "SELECT anchor_id, ts, root_hash, chain_len,"
                    " issuer_idn, sig_r, sig_s FROM audit_anchors"
                    " WHERE tenant_id=? AND ts>=?"
                    " ORDER BY ts DESC, anchor_id DESC LIMIT ?",
                    (tenant, since_ts, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT anchor_id, ts, root_hash, chain_len,"
                    " issuer_idn, sig_r, sig_s FROM audit_anchors"
                    " WHERE tenant_id=?"
                    " ORDER BY ts DESC, anchor_id DESC LIMIT ?",
                    (tenant, limit)).fetchall()
        return [{
            "anchor_id": r[0], "ts": r[1], "root_hash": r[2],
            "chain_len": r[3], "issuer_idn": r[4],
            "sig_r": _unhex(r[5]), "sig_s": _unhex(r[6]),
        } for r in rows]

    # ---------------------------------------------------------- 撤销累加器状态
    def save_revocation_state(self, tenant, state):
        """保存累加器状态快照。state 是 RevokeAccumulator.state_dict() 的 dict。

        INSERT OR REPLACE：同租户只保留最新一次快照，历史状态由撤销日志
        记录追溯。leaves 数组大时（1024 × 64 hex）JSON ~4KB，可接受。
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO revocation_state"
                "(tenant_id, version, capacity, count, leaves_json,"
                " frozen_roots_json, jti_index_json, ts)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (tenant,
                 int(state.get("version", 0)),
                 int(state.get("capacity", 1024)),
                 int(state.get("count", 0)),
                 json.dumps(state.get("leaves", [])),
                 json.dumps(state.get("frozen_roots", [])),
                 json.dumps(state.get("jti_index", {})),
                 int(state.get("ts", int(time.time())))))
            self._conn.commit()

    def get_revocation_state(self, tenant):
        """读取累加器状态快照。无状态返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT version, capacity, count, leaves_json,"
                " frozen_roots_json, jti_index_json, ts"
                " FROM revocation_state WHERE tenant_id=?",
                (tenant,)).fetchone()
        if row is None:
            return None
        return {
            "version": row[0],
            "capacity": row[1],
            "count": row[2],
            "leaves": json.loads(row[3]),
            "frozen_roots": json.loads(row[4]),
            "jti_index": json.loads(row[5]),
            "ts": row[6],
        }

    # ---------------------------------------------------------- 策略
    def set_policy(self, tenant, key, value):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO policy(tenant_id, key, value_json)"
                " VALUES(?,?,?)",
                (tenant, key, json.dumps(value)))
            self._conn.commit()

    def get_policy(self, tenant):
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, value_json FROM policy WHERE tenant_id=?",
                (tenant,)).fetchall()
        return {r[0]: json.loads(r[1]) for r in rows}

    # ---------------------------------------------------------- 运维
    def count_by_table(self):
        with self._lock:
            out = {}
            for t in ("identities", "revocations", "audit_log",
                      "audit_anchors", "revocation_state", "policy"):
                out[t] = self._conn.execute(
                    "SELECT COUNT(*) FROM %s" % t).fetchone()[0]
            return out

    def close(self):
        with self._lock:
            self._conn.close()
