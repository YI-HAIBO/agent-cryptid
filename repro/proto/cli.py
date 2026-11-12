# -*- coding: utf-8 -*-
"""FR7-05：命令行工具，用于调试与批量操作。

用法：
    # 直接模式（进程内，适合快速调试）
    python cli.py --mode direct --tenant demo --cmd register --idn "agent://a"

    # HTTP 模式（连接远程服务器）
    python cli.py --mode http --server http://localhost:8000 --tenant demo --cmd list

    # 查看所有命令
    python cli.py --help

命令列表：
    register   注册标识
    list       列出标识（支持 --org --tag --status 过滤）
    issue      签发凭证
    verify     校验凭证
    revoke     撤销凭证
    export     导出标识
    import     批量导入标识
    rotate     轮换主密钥
    keys       查询密钥版本
    stats      平台统计
    smoke      跑 10 API 烟测
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ======================================================================
# Direct 模式：进程内直调 Platform
# ======================================================================
class DirectClient:
    """进程内客户端，直接调用 Platform 方法。"""

    def __init__(self, tenant="default", persistence=None):
        from agent_platform import Platform
        from persistence import SQLiteBackend
        if persistence:
            self.plat = Platform(tenant=tenant, persistence=persistence)
        else:
            self.plat = Platform(tenant=tenant)

    def route(self, method, path, body=None, query=None):
        """模拟路由调用，返回 (status, result)。"""
        try:
            if method == "GET":
                return self._get(path, query)
            elif method == "POST":
                return self._post(path, body)
            return 400, {"ok": False, "reason": "unsupported method"}
        except Exception as e:
            return 500, {"ok": False, "reason": str(e)}

    def _get(self, path, query=None):
        p = self.plat
        q = query or {}
        if path == "/v1/identities":
            return 200, p.list_identities(
                org=q.get("org"), tag=q.get("tag"),
                status=q.get("status"), limit=int(q.get("limit", "1000")))
        if path == "/v1/keys/version":
            return 200, p.key_versions()
        if path == "/v1/identities/export":
            return 200, p.list_identities(limit=10000)
        if path == "/v1/stats":
            return 200, {"ok": True, "identities": len(p._identities),
                         "revoked": len(p._revoked_jtis), "audit": p.audit.count()}
        return 404, {"ok": False, "reason": "unknown path"}

    def _post(self, path, body=None):
        p = self.plat
        b = body or {}
        if path == "/v1/identities":
            r = p.register_identity(b.get("idn"), org=b.get("org"),
                                    agent_type=b.get("agent_type"),
                                    owner=b.get("owner"),
                                    tags=b.get("tags"))
            return (200 if r.get("ok") else 400), r
        if path == "/v1/credentials":
            r = p.issue_credential(
                issuer_idn=b.get("issuer_idn"),
                subject_idn=b.get("subject_idn"),
                audience=b.get("audience", "svc://test"),
                scope=b.get("scope", ["read"]),
                ttl=b.get("ttl"),
                alg_tier=b.get("alg_tier", "sm2"))
            return (200 if r.get("ok") else 400), r
        if path == "/v1/credentials/verify":
            r = p.verify_credential(b.get("cred"))
            return (200 if r.get("ok") else 400), r
        if path == "/v1/revocations":
            r = p.revoke(b.get("jti"), reason=b.get("reason", "manual"))
            return (200 if r.get("ok") else 400), r
        if path == "/v1/keys/rotate":
            r = p.rotate_master_key(alg=b.get("alg", "sm2"),
                                    reason=b.get("reason", "cli rotate"))
            return (200 if r.get("ok") else 400), r
        if path == "/v1/identities/import":
            identities = b.get("identities", [])
            results = []
            for ident in identities:
                r = p.register_identity(idn=ident["idn"], org=ident.get("org"),
                                        agent_type=ident.get("agent_type"),
                                        owner=ident.get("owner"),
                                        tags=ident.get("tags"))
                results.append(r)
            imported = sum(1 for r in results if r.get("ok"))
            return 200, {"ok": True, "total": len(results),
                         "imported": imported, "results": results}
        if path == "/v1/smoke":
            return 200, _run_smoke()
        return 404, {"ok": False, "reason": "unknown path"}


# ======================================================================
# HTTP 模式：连接远程服务器
# ======================================================================
class HttpClient:
    """HTTP 客户端，连接远程服务器。"""

    def __init__(self, server_url, tenant="default", api_key=None):
        self.server = server_url.rstrip("/")
        self.tenant = tenant
        self.api_key = api_key

    def route(self, method, path, body=None, query=None):
        import urllib.request
        import urllib.parse
        if query:
            qs = urllib.parse.urlencode(query)
            path = path + "?" + qs
        url = self.server + path
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Tenant-Id", self.tenant)
        if self.api_key:
            req.add_header("X-API-Key", self.api_key)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read().decode("utf-8"))
            return resp.status, result
        except urllib.error.HTTPError as e:
            result = json.loads(e.read().decode("utf-8"))
            return e.code, result


# ======================================================================
# 烟测
# ======================================================================
def _run_smoke():
    """跑 10 API 烟测。"""
    try:
        from agent_platform import self_check
        return self_check()
    except Exception as e:
        return [("smoke", False, str(e))]


# ======================================================================
# CLI 入口
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="agent-cryptid CLI - 调试与批量操作工具")
    parser.add_argument("--mode", choices=["direct", "http"], default="direct",
                        help="运行模式：direct（进程内）或 http（远程）")
    parser.add_argument("--server", default="http://localhost:8000",
                        help="HTTP 服务器地址（http 模式）")
    parser.add_argument("--tenant", default="default", help="租户 ID")
    parser.add_argument("--db", default=None, help="SQLite 数据库路径")
    parser.add_argument("--api-key", default=None, help="API 密钥")
    parser.add_argument("--cmd", required=True,
                        choices=["register", "list", "issue", "verify",
                                 "revoke", "export", "import", "rotate",
                                 "keys", "stats", "smoke"],
                        help="要执行的命令")
    parser.add_argument("--idn", default=None, help="标识 ID")
    parser.add_argument("--org", default=None, help="组织")
    parser.add_argument("--agent-type", default=None, help="智能体类型")
    parser.add_argument("--owner", default=None, help="责任人")
    parser.add_argument("--tag", default=None, help="标签")
    parser.add_argument("--status", default=None, help="状态过滤")
    parser.add_argument("--issuer", default=None, help="签发方 ID")
    parser.add_argument("--subject", default=None, help="主体 ID")
    parser.add_argument("--audience", default="svc://test", help="受众")
    parser.add_argument("--scope", default="read", help="作用域（逗号分隔）")
    parser.add_argument("--ttl", type=int, default=None, help="凭证有效期（秒）")
    parser.add_argument("--alg", default="sm2", help="算法档位")
    parser.add_argument("--jti", default=None, help="凭证 JTI")
    parser.add_argument("--reason", default=None, help="原因")
    parser.add_argument("--file", default=None, help="JSON 文件路径（import/export）")
    args = parser.parse_args()

    # 初始化客户端
    if args.mode == "http":
        client = HttpClient(args.server, tenant=args.tenant, api_key=args.api_key)
    else:
        pers = None
        if args.db:
            from persistence import SQLiteBackend
            pers = SQLiteBackend(args.db)
        client = DirectClient(tenant=args.tenant, persistence=pers)

    # 执行命令
    status, result = _execute(client, args)

    # 输出结果
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))

    # 判断成功：dict 含 ok=True，或 list 全部 True
    if isinstance(result, dict):
        success = result.get("ok") is True
    elif isinstance(result, list):
        success = all(item[1] for item in result if isinstance(item, (list, tuple)))
    else:
        success = False
    return 0 if success else 1


def _execute(client, args):
    """根据命令执行对应操作。"""
    cmd = args.cmd

    if cmd == "register":
        body = {"idn": args.idn, "org": args.org,
                "agent_type": args.agent_type, "owner": args.owner}
        return client.route("POST", "/v1/identities", body)

    elif cmd == "list":
        query = {}
        if args.org:
            query["org"] = args.org
        if args.tag:
            query["tag"] = args.tag
        if args.status:
            query["status"] = args.status
        return client.route("GET", "/v1/identities", query=query)

    elif cmd == "issue":
        scope = [s.strip() for s in args.scope.split(",")] if args.scope else ["read"]
        body = {"issuer_idn": args.issuer, "subject_idn": args.subject,
                "audience": args.audience, "scope": scope,
                "ttl": args.ttl, "alg_tier": args.alg}
        return client.route("POST", "/v1/credentials", body)

    elif cmd == "verify":
        body = {"cred": {"jti": args.jti}}  # 简化：实际需要完整凭证
        return client.route("POST", "/v1/credentials/verify", body)

    elif cmd == "revoke":
        body = {"jti": args.jti, "reason": args.reason or "cli revoke"}
        return client.route("POST", "/v1/revocations", body)

    elif cmd == "export":
        return client.route("GET", "/v1/identities/export")

    elif cmd == "import":
        if not args.file:
            return 400, {"ok": False, "reason": "--file required for import"}
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
        bodies = data.get("identities", data if isinstance(data, list) else [])
        return client.route("POST", "/v1/identities/import",
                            {"identities": bodies})

    elif cmd == "rotate":
        body = {"alg": args.alg, "reason": args.reason or "cli rotate"}
        return client.route("POST", "/v1/keys/rotate", body)

    elif cmd == "keys":
        return client.route("GET", "/v1/keys/version")

    elif cmd == "stats":
        return client.route("GET", "/v1/stats")

    elif cmd == "smoke":
        return client.route("POST", "/v1/smoke", {})

    return 400, {"ok": False, "reason": "unknown command: %s" % cmd}


if __name__ == "__main__":
    sys.exit(main())
