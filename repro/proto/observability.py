# -*- coding: utf-8 -*-
"""可观测性：健康检查、指标暴露、日志分级（NFR-10）。

生产部署的入场券——没有这三项，运维无法判断服务是否活着、
是否该摘流量、出了什么事。

零外部依赖（不引 prometheus_client / logging 框架），
指标以 Prometheus 文本格式直接渲染，可被任何抓取器消费。

三件事：
  1. HealthCheck  存活检查（liveness）与就绪检查（readiness）
  2. Metrics      计数器 / 观测值 / 直方图，导出 Prometheus 文本或 JSON
  3. Logger       分级结构化日志（DEBUG/INFO/WARN/ERROR）

设计要点：
  - 就绪检查不能只看"进程活着"，要看依赖是否可用：
    数据库能否读写、标识认证机构密钥是否就位、策略是否已加载。
    否则流量会打到一个"活着但干不了活"的实例上。
  - 指标同时给业务口径（凭证签发数等）与运行口径（请求数、时延），
    前者从审计事件采集，后者由调用方埋点累加。
  - 日志必须带租户与租户内主体，否则多租户下无法归因。
"""
import os
import sys
import time

# 日志级别
DEBUG = 10
INFO = 20
WARN = 30
ERROR = 40
LEVEL_NAMES = {DEBUG: "DEBUG", INFO: "INFO", WARN: "WARN", ERROR: "ERROR"}


# ------------------------------------------------------------------
# 日志
# ------------------------------------------------------------------
class Logger:
    """分级结构化日志。默认输出到 stderr，可注入任意 write 函数。

    字段：ts / level / logger / msg / tenant / 其余自定义字段。
    输出为单行 JSON，便于采集端解析。
    """

    def __init__(self, name="agent-cryptid", level=INFO, sink=None,
                 tenant=None):
        self.name = name
        self.level = level
        self.sink = sink or (lambda line: sys.stderr.write(line + "\n"))
        self.tenant = tenant

    def _log(self, level, msg, **fields):
        if level < self.level:
            return
        rec = {
            "ts": int(time.time()),
            "ts_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": LEVEL_NAMES.get(level, "INFO"),
            "logger": self.name,
            "msg": msg,
        }
        if self.tenant:
            rec["tenant"] = self.tenant
        for k, v in fields.items():
            if v is not None:
                rec[k] = v
        # 单行 JSON（ascii=False 保留中文；采集端按行读）
        import json
        try:
            self.sink(json.dumps(rec, ensure_ascii=False, sort_keys=True))
        except Exception:
            pass  # 日志失败绝不能影响业务主流程

    def debug(self, msg, **f):
        self._log(DEBUG, msg, **f)

    def info(self, msg, **f):
        self._log(INFO, msg, **f)

    def warn(self, msg, **f):
        self._log(WARN, msg, **f)

    def error(self, msg, **f):
        self._log(ERROR, msg, **f)

    def with_tenant(self, tenant):
        """派生一个绑定租户的 logger。"""
        return Logger(self.name, self.level, self.sink, tenant)


# ------------------------------------------------------------------
# 指标
# ------------------------------------------------------------------
class Metrics:
    """极简指标注册表。

    counter(name, labels)  累加计数
    gauge(name, labels)    可增可减的瞬时值
    histogram(name, labels)观测值分布，输出 count/sum/min/max/avg
    """

    def __init__(self, prefix="ac", default_labels=None):
        self.prefix = prefix
        self.default_labels = dict(default_labels or {})
        self._counters = {}
        self._gauges = {}
        self._histograms = {}
        self._help = {}

    def _key(self, name, labels):
        items = tuple(sorted(labels.items()))
        return (name, items)

    def _full_name(self, name):
        return "%s_%s" % (self.prefix, name) if self.prefix else name

    def set_help(self, name, text):
        self._help[name] = text

    def inc_counter(self, name, value=1, **labels):
        lbs = dict(self.default_labels)
        lbs.update(labels)
        k = self._key(name, lbs)
        self._counters[k] = self._counters.get(k, 0) + value
        return self._counters[k]

    def set_gauge(self, name, value, **labels):
        lbs = dict(self.default_labels)
        lbs.update(labels)
        self._gauges[self._key(name, lbs)] = value

    def observe(self, name, value, **labels):
        lbs = dict(self.default_labels)
        lbs.update(labels)
        k = self._key(name, lbs)
        self._histograms.setdefault(k, []).append(float(value))

    # ---- 读取 ----
    def counter_value(self, name, **labels):
        lbs = dict(self.default_labels)
        lbs.update(labels)
        return self._counters.get(self._key(name, lbs), 0)

    def snapshot(self):
        """导出为结构化字典（JSON 友好）。"""
        out = {"counters": [], "gauges": [], "histograms": []}
        for (name, items), v in self._counters.items():
            out["counters"].append({"name": self._full_name(name),
                                    "labels": dict(items), "value": v})
        for (name, items), v in self._gauges.items():
            out["gauges"].append({"name": self._full_name(name),
                                  "labels": dict(items), "value": v})
        for (name, items), vals in self._histograms.items():
            out["histograms"].append({
                "name": self._full_name(name), "labels": dict(items),
                "count": len(vals), "sum": sum(vals),
                "min": min(vals) if vals else 0,
                "max": max(vals) if vals else 0,
                "avg": (sum(vals) / len(vals)) if vals else 0,
            })
        return out

    def render_prometheus(self):
        """渲染为 Prometheus 文本格式（零依赖）。"""
        L = []

        def emit(name, labels, value, mtype):
            fn = self._full_name(name)
            L.append("# HELP %s %s" % (fn, self._help.get(name, fn)))
            L.append("# TYPE %s %s" % (fn, mtype))
            if labels:
                ls = ",".join('%s="%s"' % (k, _esc(v))
                              for k, v in sorted(labels.items()))
                L.append("%s{%s} %s" % (fn, ls, _fmt_num(value)))
            else:
                L.append("%s %s" % (fn, _fmt_num(value)))

        for (name, items), v in sorted(self._counters.items(),
                                       key=lambda x: x[0][0]):
            emit(name, dict(items), v, "counter")
        for (name, items), v in sorted(self._gauges.items(),
                                       key=lambda x: x[0][0]):
            emit(name, dict(items), v, "gauge")
        for (name, items), vals in sorted(self._histograms.items(),
                                          key=lambda x: x[0][0]):
            base = dict(items)
            emit(name + "_count", base, len(vals), "counter")
            emit(name + "_sum", base, sum(vals), "counter")
            if vals:
                emit(name + "_min", base, min(vals), "gauge")
                emit(name + "_max", base, max(vals), "gauge")
                emit(name + "_avg", base, sum(vals) / len(vals), "gauge")
        return "\n".join(L) + ("\n" if L else "")


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def _fmt_num(v):
    if isinstance(v, float):
        return "%.6f" % v
    return str(v)


# ------------------------------------------------------------------
# 从 Platform 采集业务指标
# ------------------------------------------------------------------
def collect_platform_metrics(platform, metrics=None):
    """把 Platform 的运行状态灌进 Metrics（业务口径指标）。"""
    m = metrics or Metrics()
    tenant = getattr(platform, "tenant", "default")

    idents = getattr(platform, "_identities", {}) or {}
    active = sum(1 for v in idents.values() if v.get("status") == "active")
    m.set_gauge("identity_total", len(idents), tenant=tenant)
    m.set_gauge("identity_active", active, tenant=tenant)
    m.set_gauge("identity_disabled", len(idents) - active, tenant=tenant)

    audit = platform.audit_query(limit=100000)
    recs = audit.get("records", [])
    kinds = {}
    for r in recs:
        k = (r.get("event") or {}).get("kind") or "unknown"
        kinds[k] = kinds.get(k, 0) + 1
    for k, v in kinds.items():
        m.set_gauge("audit_events", v, tenant=tenant, kind=k)

    snap = platform.revocation_snapshot(since_version=0)
    m.set_gauge("revocation_total", snap.get("total_revoked", 0),
                tenant=tenant)
    m.set_gauge("revocation_accumulator_version",
                snap.get("acc_version", 0) or 0, tenant=tenant)
    m.set_gauge("audit_chain_length", audit.get("chain_length", 0),
                tenant=tenant)
    anchors = platform.list_audit_anchors(limit=10000)
    m.set_gauge("audit_anchor_total", anchors.get("total", 0), tenant=tenant)

    # 鉴权失败率：凭证校验中失败占比
    ok = kinds.get("credential.verify", 0)
    fail = 0
    for r in recs:
        ev = r.get("event") or {}
        if ev.get("kind") == "credential.verify" and \
           ev.get("result") != "ok":
            fail += 1
    m.set_gauge("credential_verify_fail", fail, tenant=tenant)
    if ok:
        m.set_gauge("credential_verify_fail_ratio", round(fail / ok, 4),
                    tenant=tenant)
    return m


# ------------------------------------------------------------------
# 健康检查
# ------------------------------------------------------------------
class HealthCheck:
    """存活与就绪检查。

    liveness   进程是否活着（不查依赖）
    readiness  依赖是否就绪：数据库可读写、IA 密钥就位、策略已加载
    """

    def __init__(self, platform=None, logger=None):
        self.platform = platform
        self.logger = logger

    def liveness(self):
        return {"status": "ok", "check": "liveness"}

    def readiness(self):
        checks = {}
        p = self.platform

        # 数据库
        if p is None or getattr(p, "_pers", None) is None:
            checks["database"] = {"ok": True, "detail": "in-memory"}
        else:
            try:
                # 用一次真实读探测连接可用性
                p._pers.get_policy(getattr(p, "tenant", "default"))
                checks["database"] = {"ok": True, "detail": "readable"}
            except Exception as e:
                checks["database"] = {"ok": False, "detail": str(e)}

        # 标识认证机构密钥
        ia = getattr(p, "ia", None) if p is not None else None
        checks["identity_authority"] = {
            "ok": bool(ia is not None and getattr(ia, "mk", None)),
            "detail": "master key loaded" if ia and getattr(ia, "mk", None)
                      else "master key missing",
        }

        # 策略
        policy = getattr(p, "_policy", None) if p is not None else None
        checks["policy"] = {
            "ok": bool(policy),
            "detail": "loaded" if policy else "not loaded",
        }

        # 审计链完整性（自洽才算健康）
        chain_ok = True
        if p is not None:
            try:
                chain_ok, why = p.audit.verify()
                checks["audit_chain"] = {
                    "ok": bool(chain_ok),
                    "detail": why or "ok",
                }
            except Exception as e:
                checks["audit_chain"] = {"ok": False, "detail": str(e)}
                chain_ok = False

        all_ok = all(c.get("ok") for c in checks.values()) and chain_ok
        return {
            "status": "ok" if all_ok else "degraded",
            "check": "readiness",
            "checks": checks,
        }

    def check(self, mode="readiness"):
        if mode == "liveness":
            return self.liveness()
        r = self.readiness()
        if self.logger and r["status"] != "ok":
            self.logger.warn("healthcheck degraded", **{k: v.get("ok")
                             for k, v in r["checks"].items()})
        return r


# ------------------------------------------------------------------
# 自检
# ------------------------------------------------------------------
def self_check():
    """可观测性自检。"""
    import json
    from agent_platform import Platform
    from credential import ALG_SM2

    out = []
    p = Platform(tenant="obs")
    p.register_identity("agent://obs/a", org="obs")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    # 日志分级
    lines = []
    log = Logger("test", level=DEBUG, sink=lines.append, tenant="obs")
    log.debug("d")
    log.info("i")
    log.warn("w")
    log.error("e")
    out.append(("日志四级各输出一条", len(lines) == 4))
    rec = json.loads(lines[3])
    out.append(("日志含级别与租户",
                rec["level"] == "ERROR" and rec["tenant"] == "obs"))
    log2 = Logger("test", level=ERROR, sink=lines.append)
    n = len(lines)
    log2.info("should be dropped")
    out.append(("低于级别不输出", len(lines) == n))

    # 指标
    m = Metrics()
    m.inc_counter("requests_total", method="POST", path="/v1/credentials")
    m.inc_counter("requests_total", method="POST", path="/v1/credentials")
    out.append(("计数器累加", m.counter_value(
        "requests_total", method="POST", path="/v1/credentials") == 2))
    m.observe("latency_ms", 3.5)
    m.observe("latency_ms", 6.5)
    snap = m.snapshot()
    hist = [h for h in snap["histograms"] if h["name"] == "ac_latency_ms"][0]
    out.append(("直方图统计正确",
                hist["count"] == 2 and hist["avg"] == 5.0))
    text = m.render_prometheus()
    out.append(("Prometheus 文本含 HELP/TYPE",
                "# HELP" in text and "# TYPE" in text))
    out.append(("Prometheus 含标签", 'method="POST"' in text))

    # 业务指标采集
    m2 = collect_platform_metrics(p)
    s2 = m2.snapshot()
    names = [g["name"] for g in s2["gauges"]]
    out.append(("业务指标含标识总数", "ac_identity_total" in names))
    out.append(("业务指标含审计链长", "ac_audit_chain_length" in names))

    # 健康检查
    hc = HealthCheck(p)
    out.append(("存活检查 ok", hc.liveness()["status"] == "ok"))
    r = hc.readiness()
    out.append(("就绪检查 ok", r["status"] == "ok"))
    out.append(("就绪检查含四项依赖", len(r["checks"]) >= 4))

    # 篡改审计链 → 就绪应降级
    p.audit.chain.append({"hash": "deadbeef", "prev": "wrong",
                          "event": {}, "payload": "{}", "ts": 0})
    r2 = HealthCheck(p).readiness()
    out.append(("审计链不自洽时降级", r2["status"] == "degraded"))
    return out


if __name__ == "__main__":
    ok = 0
    res = self_check()
    for name, passed in res:
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            ok += 1
    print("RESULT  PASS=%d  FAIL=%d" % (ok, len(res) - ok))
