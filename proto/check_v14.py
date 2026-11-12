# -*- coding: utf-8 -*-
"""v2.10 测试：NFR-10 健康检查 / 指标暴露 / 日志分级。

覆盖：
  [A] 日志分级与结构化
  [B] 指标原语（counter / gauge / histogram）
  [C] Prometheus 文本渲染
  [D] 业务口径指标采集
  [E] 健康检查（存活 / 就绪 / 降级）
  [F] HTTP 端点 /health 与 /metrics
  [G] 运行口径埋点（随调用累加）
  [H] ASGI 层可观测端点
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_platform import Platform
from http_api import route as http_route, TenantPool
from observability import (Logger, Metrics, HealthCheck, DEBUG, INFO,
                           WARN, ERROR, collect_platform_metrics)
from credential import ALG_SM2
import asgi_app

PASS = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("PASS     %s" % name)
    else:
        FAIL.append(name)
        print("FAIL     %s  %s" % (name, detail))


def new_platform(tenant="obs"):
    p = Platform(tenant=tenant)
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})
    return p


# ---------------------------------------------------------------------------
# [A] 日志
# ---------------------------------------------------------------------------

def test_logger():
    print("\n=== [A] 日志分级与结构化 ===")
    lines = []
    log = Logger("t", level=DEBUG, sink=lines.append, tenant="obs")
    log.debug("d", k=1)
    log.info("i")
    log.warn("w")
    log.error("e")
    check("A1 四级各输出一条", len(lines) == 4)
    parsed = [json.loads(x) for x in lines]
    check("A2 级别顺序正确",
          [r["level"] for r in parsed] == ["DEBUG", "INFO", "WARN", "ERROR"])
    check("A3 含租户字段", all(r["tenant"] == "obs" for r in parsed))
    check("A4 含时间戳", all("ts" in r for r in parsed))
    check("A5 自定义字段透传", parsed[0]["k"] == 1)
    check("A6 单行 JSON 可解析", all(isinstance(r, dict) for r in parsed))

    # 级别过滤
    lines2 = []
    log2 = Logger("t", level=WARN, sink=lines2.append)
    log2.debug("x")
    log2.info("x")
    log2.warn("kept")
    log2.error("kept")
    check("A7 低于级别被丢弃", len(lines2) == 2)

    # 派生租户 logger
    lines3 = []
    base = Logger("t", level=INFO, sink=lines3.append)
    base.with_tenant("derived").info("m")
    check("A8 派生 logger 带租户",
          json.loads(lines3[0])["tenant"] == "derived")


# ---------------------------------------------------------------------------
# [B] 指标原语
# ---------------------------------------------------------------------------

def test_metrics():
    print("\n=== [B] 指标原语 ===")
    m = Metrics()
    m.inc_counter("requests_total", method="POST")
    m.inc_counter("requests_total", method="POST")
    m.inc_counter("requests_total", method="GET")
    check("B1 同标签累加", m.counter_value("requests_total",
                                           method="POST") == 2)
    check("B2 不同标签独立", m.counter_value("requests_total",
                                             method="GET") == 1)
    check("B3 未定义标签返回 0",
          m.counter_value("requests_total", method="PUT") == 0)

    m.set_gauge("identity_total", 7, tenant="t1")
    m.set_gauge("identity_total", 3, tenant="t1")
    snap = m.snapshot()
    g = [x for x in snap["gauges"]
         if x["name"] == "ac_identity_total"][0]
    check("B4 gauge 覆盖而非累加", g["value"] == 3)

    for v in [2.0, 4.0, 6.0]:
        m.observe("latency_ms", v)
    h = [x for x in m.snapshot()["histograms"]
         if x["name"] == "ac_latency_ms"][0]
    check("B5 直方图 count", h["count"] == 3)
    check("B6 直方图 sum", h["sum"] == 12.0)
    check("B7 直方图 min/max", h["min"] == 2.0 and h["max"] == 6.0)
    check("B8 直方图 avg", h["avg"] == 4.0)

    # 默认标签
    m2 = Metrics(default_labels={"service": "ac"})
    m2.inc_counter("x_total")
    check("B9 默认标签生效",
          m2.snapshot()["counters"][0]["labels"]["service"] == "ac")


# ---------------------------------------------------------------------------
# [C] Prometheus 渲染
# ---------------------------------------------------------------------------

def test_prometheus():
    print("\n=== [C] Prometheus 文本渲染 ===")
    m = Metrics()
    m.set_help("requests_total", "Total requests")
    m.inc_counter("requests_total", method="POST", path="/v1/credentials")
    m.set_gauge("identity_total", 5, tenant="t1")
    m.observe("latency_ms", 1.5)
    text = m.render_prometheus()
    check("C1 含 HELP", "# HELP ac_requests_total Total requests" in text)
    check("C2 含 TYPE", "# TYPE ac_requests_total counter" in text)
    check("C3 含标签", 'method="POST"' in text)
    check("C4 gauge 行存在", "ac_identity_total" in text)
    check("C5 直方图派生 count/sum",
          "ac_latency_ms_count" in text and "ac_latency_ms_sum" in text)
    check("C6 直方图派生 min/max/avg",
          all(k in text for k in ["ac_latency_ms_min", "ac_latency_ms_max",
                                  "ac_latency_ms_avg"]))
    # 特殊字符转义
    m3 = Metrics()
    m3.inc_counter("weird", label='a"b')
    t3 = m3.render_prometheus()
    check("C7 标签值转义", 'a\\"b' in t3)
    check("C8 空指标渲染空串", Metrics().render_prometheus() == "")


# ---------------------------------------------------------------------------
# [D] 业务口径采集
# ---------------------------------------------------------------------------

def test_platform_metrics():
    print("\n=== [D] 业务口径指标采集 ===")
    p = new_platform("obsD")
    p.register_identity("agent://d/1", org="d")
    p.register_identity("agent://d/2", org="d")
    r = p.issue_credential("agent://d/1", "agent://d/2", "service://d",
                           ["d:read"], ttl=3600)
    p.verify_credential(r["cred"], audience="service://d")
    p.revoke(r["cred"]["jti"], reason="test")
    p.anchor_audit("agent://d/1", reason="test")

    m = collect_platform_metrics(p)
    snap = m.snapshot()
    gauges = {g["name"]: g["value"] for g in snap["gauges"]}
    check("D1 标识总数", gauges.get("ac_identity_total") == 2)
    check("D2 活跃标识", gauges.get("ac_identity_active") == 2)
    check("D3 撤销总数", gauges.get("ac_revocation_total") == 1)
    check("D4 审计链长", gauges.get("ac_audit_chain_length", 0) > 0)
    check("D5 锚点数", gauges.get("ac_audit_anchor_total") == 1)
    check("D6 租户标签",
          all(g["labels"].get("tenant") == "obsD" for g in snap["gauges"]))
    # 事件分类指标
    kinds = [g["labels"].get("kind") for g in snap["gauges"]
             if g["name"] == "ac_audit_events"]
    check("D7 审计事件按 kind 分指标", "credential.issue" in kinds)


# ---------------------------------------------------------------------------
# [E] 健康检查
# ---------------------------------------------------------------------------

def test_health():
    print("\n=== [E] 健康检查 ===")
    p = new_platform("obsE")
    p.register_identity("agent://e/1", org="e")
    hc = HealthCheck(p)

    live = hc.liveness()
    check("E1 存活 ok", live["status"] == "ok")

    ready = hc.readiness()
    check("E2 就绪 ok", ready["status"] == "ok")
    check("E3 就绪含数据库检查", "database" in ready["checks"])
    check("E4 就绪含密钥检查", "identity_authority" in ready["checks"])
    check("E5 就绪含策略检查", "policy" in ready["checks"])
    check("E6 就绪含审计链检查", "audit_chain" in ready["checks"])
    check("E7 内存后端标记为 in-memory",
          ready["checks"]["database"]["detail"] == "in-memory")

    # 审计链被篡改 → 降级
    p.audit.chain.append({"hash": "0" * 64, "prev": "bad",
                          "event": {}, "payload": "{}", "ts": 0})
    r2 = HealthCheck(p).readiness()
    check("E8 审计链不自洽时降级", r2["status"] == "degraded")
    check("E9 降级点名审计链",
          r2["checks"]["audit_chain"]["ok"] is False)

    # mode 参数
    check("E10 liveness 模式不查依赖",
          HealthCheck(p).check("liveness")["status"] == "ok")
    check("E11 readiness 模式反映降级",
          HealthCheck(p).check("readiness")["status"] == "degraded")


# ---------------------------------------------------------------------------
# [F] HTTP 端点
# ---------------------------------------------------------------------------

def test_http_endpoints():
    print("\n=== [F] HTTP /health 与 /metrics ===")
    pool = TenantPool()
    plat = pool.get("t1")
    plat.configure_policy({"allowed_algs": [ALG_SM2],
                           "max_ttl_seconds": 3600})
    plat.register_identity("agent://f/1", org="f")

    code, r = http_route(pool, "GET", "/health", None, None, tenant="t1")
    check("F1 /health 返回 200", code == 200, detail=str(r))
    check("F2 /health ok", r.get("ok") is True)
    check("F3 /health 含 check 字段", "check" in r)
    check("F4 /health 含依赖明细", "checks" in r)

    code, r = http_route(pool, "GET", "/health", {"mode": ["liveness"]},
                         None, tenant="t1")
    check("F5 liveness 模式可用", code == 200 and r["check"] == "liveness")

    code, r = http_route(pool, "GET", "/metrics", None, None, tenant="t1")
    check("F6 /metrics 返回 200", code == 200)
    check("F7 /metrics 含快照", "snapshot" in r)
    check("F8 /metrics 含 Prometheus 文本", "prometheus" in r)
    check("F9 Prometheus 文本非空", len(r["prometheus"]) > 0)
    check("F10 快照含业务指标",
          any(g["name"] == "ac_identity_total"
              for g in r["snapshot"]["gauges"]))


# ---------------------------------------------------------------------------
# [G] 运行口径埋点
# ---------------------------------------------------------------------------

def test_instrumentation():
    print("\n=== [G] 运行口径埋点 ===")
    pool = TenantPool()
    plat = pool.get("t1")
    plat.configure_policy({"allowed_algs": [ALG_SM2],
                           "max_ttl_seconds": 3600})
    plat.register_identity("agent://g/1", org="g")

    before = pool.metrics.counter_value("requests_total", method="POST")
    http_route(pool, "POST", "/v1/identities", None,
               {"idn": "agent://g/2", "org": "g"}, tenant="t1")
    http_route(pool, "POST", "/v1/identities", None,
               {"idn": "agent://g/3", "org": "g"}, tenant="t1")
    after = pool.metrics.counter_value("requests_total", method="POST",
                                       path="/v1/identities", status="200")
    check("G1 请求计数累加", after == 2, detail="%s -> %s" % (before, after))

    # 失败请求计入错误数
    http_route(pool, "POST", "/v1/identities", None,
               {"idn": "agent://g/2", "org": "g"}, tenant="t1")  # 重复 → 400
    errs = pool.metrics.counter_value("requests_error_total",
                                      method="POST",
                                      path="/v1/identities", status="400")
    check("G2 错误请求计入", errs >= 1, detail=str(errs))

    # 时延观测
    snap = pool.metrics.snapshot()
    lat = [h for h in snap["histograms"]
           if h["name"] == "ac_request_duration_ms"]
    check("G3 时延被观测", len(lat) >= 1 and lat[0]["count"] >= 3)


# ---------------------------------------------------------------------------
# [H] ASGI 层
# ---------------------------------------------------------------------------

def test_asgi():
    print("\n=== [H] ASGI 可观测端点 ===")
    asgi_app.init_pool()
    status, r = asgi_app._call({"method": "GET", "path": "/health"},
                               None, "asgi-obs")
    check("H1 ASGI /health", status == 200 and r.get("ok") is True)

    status, r = asgi_app._call({"method": "GET", "path": "/metrics"},
                               None, "asgi-obs")
    check("H2 ASGI /metrics", status == 200 and "snapshot" in r)
    check("H3 ASGI 指标含 Prometheus",
          "prometheus" in r and len(r["prometheus"]) > 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_logger()
    test_metrics()
    test_prometheus()
    test_platform_metrics()
    test_health()
    test_http_endpoints()
    test_instrumentation()
    test_asgi()

    print("\n" + "=" * 60)
    print("PASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print("  -", f)
    print("RESULT  PASS=%d  FAIL=%d" % (len(PASS), len(FAIL)))

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "check_v14_report.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("check_v14 PASS=%d FAIL=%d\n" % (len(PASS), len(FAIL)))
        for name in PASS:
            f.write("PASS  %s\n" % name)
        for name in FAIL:
            f.write("FAIL  %s\n" % name)
        f.write("RESULT  PASS=%d  FAIL=%d\n" % (len(PASS), len(FAIL)))
    print(out_path)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
