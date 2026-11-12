# -*- coding: utf-8 -*-
"""OceanBase（MySQL 兼容模式）持久化后端。

NFR-09：验证存储层可切换到国产数据库。OceanBase 是蚂蚁集团开发的
国产分布式数据库，本模块提供 MySQL 兼容方言后端，接口与
persistence.SQLiteBackend 完全一致，可无侵入替换。

方言差异（相对 SQLiteBackend）：
    ? 占位符          -> %s（pymysql）
    INSERT OR REPLACE -> REPLACE INTO（MySQL REPLACE 语义：唯一约束冲突时
                          先删旧行再插入，与 SQLite INSERT OR REPLACE 等价）
    TEXT 作主键        -> MySQL/OceanBase 不允许 TEXT 列作主键/唯一键，
                          键列改用 VARCHAR(n)（tenant_id/idn/jti/hash 等）
    key 保留字        -> 加反引号 `key`
    CREATE INDEX IF NOT EXISTS -> MySQL 不支持，改用普通 CREATE INDEX
                          （建库时一次性执行，避免重复执行报错）

接口契约与 SQLiteBackend 逐方法对应：
    put_identity/get_identity/list_identities
    append_revocation/is_revoked/revocation_snapshot
    append_audit/query_audit
    append_audit_anchor/list_audit_anchors
    save_revocation_state/get_revocation_state
    set_policy/get_policy
    count_by_table/close

SM2 签名分量 sig_r/sig_s 为 256 位整数，同样以 hex 字符串入库，与
SQLiteBackend 保持一致（读取时 int(..., 16) 还原）。
"""
import json
import threading
import time


# 键列用 VARCHAR（MySQL 不允许 TEXT 作主键/唯一键），值列用 MEDIUMTEXT。
# MEDIUMTEXT（16MB）而非 TEXT（64KB）：撤销累加器的 leaves 快照在
# 1024 叶时 JSON ~66KB，超过 MySQL/OceanBase TEXT 的 65535 字节上限；
# SQLite 的 TEXT 无此限制。用 MEDIUMTEXT 保证 1024+ 叶快照可存。
SCHEMA = [
    "CREATE TABLE IF NOT EXISTS identities ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " idn VARCHAR(256) NOT NULL,"
    " pub_x VARCHAR(128) NOT NULL,"
    " pub_y VARCHAR(128) NOT NULL,"
    " status VARCHAR(32) NOT NULL,"
    " meta_json MEDIUMTEXT NOT NULL,"
    " PRIMARY KEY (tenant_id, idn))",
    "CREATE TABLE IF NOT EXISTS revocations ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " version BIGINT NOT NULL,"
    " jti VARCHAR(128) NOT NULL,"
    " reason VARCHAR(512),"
    " ts BIGINT NOT NULL,"
    " PRIMARY KEY (tenant_id, version),"
    " UNIQUE KEY uq_rev_tenant_jti (tenant_id, jti))",
    "CREATE TABLE IF NOT EXISTS audit_log ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " seq BIGINT NOT NULL,"
    " ts BIGINT NOT NULL,"
    " kind VARCHAR(64),"
    " hash VARCHAR(128) NOT NULL,"
    " prev_hash VARCHAR(128) NOT NULL,"
    " event_json MEDIUMTEXT NOT NULL,"
    " PRIMARY KEY (tenant_id, seq))",
    "CREATE TABLE IF NOT EXISTS audit_anchors ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " anchor_id BIGINT NOT NULL,"
    " ts BIGINT NOT NULL,"
    " root_hash VARCHAR(128) NOT NULL,"
    " chain_len BIGINT NOT NULL,"
    " issuer_idn VARCHAR(256) NOT NULL,"
    " sig_r VARCHAR(256),"
    " sig_s VARCHAR(256),"
    " PRIMARY KEY (tenant_id, anchor_id))",
    "CREATE TABLE IF NOT EXISTS policy ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " `key` VARCHAR(128) NOT NULL,"
    " value_json MEDIUMTEXT NOT NULL,"
    " PRIMARY KEY (tenant_id, `key`))",
    "CREATE TABLE IF NOT EXISTS revocation_state ("
    " tenant_id VARCHAR(128) NOT NULL,"
    " version BIGINT NOT NULL,"
    " capacity BIGINT NOT NULL,"
    " `count` BIGINT NOT NULL,"
    " leaves_json MEDIUMTEXT NOT NULL,"
    " frozen_roots_json MEDIUMTEXT NOT NULL,"
    " jti_index_json MEDIUMTEXT NOT NULL,"
    " ts BIGINT NOT NULL,"
    " PRIMARY KEY (tenant_id))",
    "CREATE INDEX idx_revocations_tenant ON revocations(tenant_id)",
    "CREATE INDEX idx_audit_tenant_kind ON audit_log(tenant_id, kind)",
    "CREATE INDEX idx_anchors_tenant_ts ON audit_anchors(tenant_id, ts)",
]


class OceanBaseBackend:
    """OceanBase（MySQL 兼容）持久化后端。线程安全（内部加锁）。"""

    def __init__(self, host="127.0.0.1", port=2881, user="root",
                 password="", database="test", connect_timeout=15):
        try:
            import pymysql
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "pymysql 未安装：pip3 install --user pymysql") from e
        self._pymysql = pymysql
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self._lock = threading.RLock()
        self._conn = self._connect(connect_timeout)
        with self._lock:
            cur = self._conn.cursor()
            for stmt in SCHEMA:
                if stmt.startswith("CREATE INDEX"):
                    # MySQL/OceanBase 不支持 CREATE INDEX IF NOT EXISTS；
                    # 重复执行时忽略 "Duplicate key name"（1061），保证幂等。
                    try:
                        cur.execute(stmt)
                    except self._pymysql.err.OperationalError as e:
                        if e.args and e.args[0] == 1061:
                            continue
                        raise
                else:
                    cur.execute(stmt)
            self._conn.commit()
            cur.close()

    def _connect(self, connect_timeout):
        return self._pymysql.connect(
            host=self.host, port=self.port, user=self.user,
            password=self.password, database=self.database,
            charset="utf8mb4", autocommit=False,
            connect_timeout=connect_timeout, read_timeout=3600,
            write_timeout=3600)

    def _execute(self, sql, params):
        """执行并提交。返回影响行数。"""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(sql, params)
                n = cur.rowcount
                self._conn.commit()
                return n
            finally:
                cur.close()

    def _query(self, sql, params=()):
        """查询，返回 tuple 行列表。"""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(sql, params)
                return cur.fetchall()
            finally:
                cur.close()

    # ---------------------------------------------------------- 标识
    def put_identity(self, tenant, idn, pub_x, pub_y, status, meta):
        self._execute(
            "REPLACE INTO identities"
            "(tenant_id, idn, pub_x, pub_y, status, meta_json)"
            " VALUES(%s,%s,%s,%s,%s,%s)",
            (tenant, idn, pub_x, pub_y, status,
             json.dumps(meta, ensure_ascii=False)))

    def get_identity(self, tenant, idn):
        rows = self._query(
            "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
            " WHERE tenant_id=%s AND idn=%s", (tenant, idn))
        if not rows:
            return None
        r = rows[0]
        return {"idn": r[0], "pub_x": r[1], "pub_y": r[2],
                "status": r[3], "meta": json.loads(r[4])}

    def list_identities(self, tenant, status=None, limit=200):
        if status:
            rows = self._query(
                "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
                " WHERE tenant_id=%s AND status=%s LIMIT %s",
                (tenant, status, int(limit)))
        else:
            rows = self._query(
                "SELECT idn, pub_x, pub_y, status, meta_json FROM identities"
                " WHERE tenant_id=%s LIMIT %s", (tenant, int(limit)))
        return [{"idn": r[0], "pub_x": r[1], "pub_y": r[2],
                 "status": r[3], "meta": json.loads(r[4])} for r in rows]

    # ---------------------------------------------------------- 撤销
    def append_revocation(self, tenant, version, jti, reason, ts):
        self._execute(
            "REPLACE INTO revocations"
            "(tenant_id, version, jti, reason, ts)"
            " VALUES(%s,%s,%s,%s,%s)",
            (tenant, int(version), jti, reason, int(ts)))

    def is_revoked(self, tenant, jti):
        return bool(self._query(
            "SELECT 1 FROM revocations WHERE tenant_id=%s AND jti=%s",
            (tenant, jti)))

    def revocation_snapshot(self, tenant, since_version=0):
        rows = self._query(
            "SELECT version, jti, reason, ts FROM revocations"
            " WHERE tenant_id=%s AND version>%s ORDER BY version",
            (tenant, int(since_version)))
        cur = self._query(
            "SELECT COALESCE(MAX(version),0) FROM revocations"
            " WHERE tenant_id=%s", (tenant,))
        current = cur[0][0]
        tot = self._query(
            "SELECT COUNT(*) FROM revocations WHERE tenant_id=%s",
            (tenant,))
        return {
            "current_version": current,
            "since_version": int(since_version),
            "entries": [{"version": r[0], "jti": r[1], "reason": r[2],
                         "ts": r[3]} for r in rows],
            "total_revoked": tot[0][0],
        }

    # ---------------------------------------------------------- 审计
    def append_audit(self, tenant, seq, ts, kind, h, prev, event):
        self._execute(
            "REPLACE INTO audit_log"
            "(tenant_id, seq, ts, kind, hash, prev_hash, event_json)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (tenant, int(seq), int(ts), kind, h, prev,
             json.dumps(event, ensure_ascii=False)))

    def query_audit(self, tenant, kind=None, idn=None, limit=100):
        if kind:
            rows = self._query(
                "SELECT seq, ts, kind, hash, prev_hash, event_json"
                " FROM audit_log WHERE tenant_id=%s AND kind=%s"
                " ORDER BY seq DESC LIMIT %s",
                (tenant, kind, int(limit)))
        else:
            rows = self._query(
                "SELECT seq, ts, kind, hash, prev_hash, event_json"
                " FROM audit_log WHERE tenant_id=%s"
                " ORDER BY seq DESC LIMIT %s", (tenant, int(limit)))
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
        def _hex(v):
            if v is None:
                return None
            if isinstance(v, int):
                return hex(v)[2:]
            return str(v)

        self._execute(
            "REPLACE INTO audit_anchors"
            "(tenant_id, anchor_id, ts, root_hash, chain_len,"
            " issuer_idn, sig_r, sig_s) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (tenant, int(anchor.get("anchor_id")), int(anchor.get("ts")),
             anchor.get("root_hash"), int(anchor.get("chain_len")),
             anchor.get("issuer_idn"),
             _hex(anchor.get("sig_r")), _hex(anchor.get("sig_s"))))

    def list_audit_anchors(self, tenant, since_ts=None, limit=100):
        def _unhex(v):
            if v is None or v == "":
                return None
            if isinstance(v, int):
                return v
            try:
                return int(v, 16)
            except Exception:
                return v

        if since_ts is not None:
            rows = self._query(
                "SELECT anchor_id, ts, root_hash, chain_len,"
                " issuer_idn, sig_r, sig_s FROM audit_anchors"
                " WHERE tenant_id=%s AND ts>=%s"
                " ORDER BY ts DESC, anchor_id DESC LIMIT %s",
                (tenant, int(since_ts), int(limit)))
        else:
            rows = self._query(
                "SELECT anchor_id, ts, root_hash, chain_len,"
                " issuer_idn, sig_r, sig_s FROM audit_anchors"
                " WHERE tenant_id=%s"
                " ORDER BY ts DESC, anchor_id DESC LIMIT %s",
                (tenant, int(limit)))
        return [{
            "anchor_id": r[0], "ts": r[1], "root_hash": r[2],
            "chain_len": r[3], "issuer_idn": r[4],
            "sig_r": _unhex(r[5]), "sig_s": _unhex(r[6]),
        } for r in rows]

    # ---------------------------------------------------------- 撤销累加器状态
    def save_revocation_state(self, tenant, state):
        self._execute(
            "REPLACE INTO revocation_state"
            "(tenant_id, version, capacity, `count`, leaves_json,"
            " frozen_roots_json, jti_index_json, ts)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (tenant,
             int(state.get("version", 0)),
             int(state.get("capacity", 1024)),
             int(state.get("count", 0)),
             json.dumps(state.get("leaves", [])),
             json.dumps(state.get("frozen_roots", [])),
             json.dumps(state.get("jti_index", {})),
             int(state.get("ts", int(time.time())))))

    def get_revocation_state(self, tenant):
        rows = self._query(
            "SELECT version, capacity, `count`, leaves_json,"
            " frozen_roots_json, jti_index_json, ts"
            " FROM revocation_state WHERE tenant_id=%s", (tenant,))
        if not rows:
            return None
        r = rows[0]
        return {
            "version": r[0],
            "capacity": r[1],
            "count": r[2],
            "leaves": json.loads(r[3]),
            "frozen_roots": json.loads(r[4]),
            "jti_index": json.loads(r[5]),
            "ts": r[6],
        }

    # ---------------------------------------------------------- 策略
    def set_policy(self, tenant, key, value):
        self._execute(
            "REPLACE INTO policy(tenant_id, `key`, value_json)"
            " VALUES(%s,%s,%s)",
            (tenant, key, json.dumps(value)))

    def get_policy(self, tenant):
        rows = self._query(
            "SELECT `key`, value_json FROM policy WHERE tenant_id=%s",
            (tenant,))
        return {r[0]: json.loads(r[1]) for r in rows}

    # ---------------------------------------------------------- 运维
    def count_by_table(self):
        out = {}
        for t in ("identities", "revocations", "audit_log",
                  "audit_anchors", "revocation_state", "policy"):
            rows = self._query("SELECT COUNT(*) FROM %s" % t)
            out[t] = rows[0][0]
        return out

    def close(self):
        with self._lock:
            self._conn.close()
