# -*- coding: utf-8 -*-
"""MCP 服务端鉴权适配组件（FR7-02）。

模型上下文协议（Model Context Protocol, MCP）是智能体连接外部工具与
数据源的标准协议。工具调用是智能体最具破坏力的动作，因此本组件承担
MCP 服务端的鉴权中间件：在工具真正执行之前，用智能体密码身份中台的
凭证完成鉴权，使每一次工具调用都有密码学可验证的授权依据。

零外部依赖，只依赖本项目的 Platform / Credential / delegation。

设计要点（后续别改坏）：
  1. 失败关闭（fail-closed）：未登记作用域的工具默认拒绝；
     任何一步校验不通过即拒绝，绝不降级放行。
  2. 受众绑定：凭证的 aud 必须等于本 MCP 服务端标识，
     防止为 A 服务签发的凭证被拿来调 B 服务的工具（跨服务挪用）。
  3. 最小权限：tools/list 按凭证实际作用域过滤，
     只暴露调用方有权调用的工具，而不是先全列再逐个拒绝。
  4. 委托链：支持末端执行者持委托链调用，权限取链上交集；
     主体（sub，末端执行者）与发起方（act，链根）分别返回，
     避免混淆代理人攻击。
  5. 防重放：复用凭证的 nonce 机制，同一凭证不可二次使用。
  6. 全量审计：每次鉴权决策（含拒绝）都入审计链，供事后追溯。

用法：
    plat = Platform(tenant="acme")
    authz = MCPAuthzAdapter(plat, audience="mcp://fileserver",
                            tool_scopes={"read_file": ["file:read"],
                                         "write_file": ["file:write"]})
    d = authz.authorize_tool_call(cred_wire, "read_file")
    if d["allow"]:
        ...  # 执行工具
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# 无需鉴权的握手方法
_HANDSHAKE_METHODS = ("initialize", "ping", "notifications/initialized")


def _request_fingerprint(jti, tool, arguments):
    """请求指纹：(jti, 工具, 参数) → SM3 摘要。

    用于 per-request 粒度的防重放。用 SM3 与全链路国密保持一致。
    """
    import json
    from sm2 import sm3
    payload = json.dumps({"jti": jti, "tool": tool, "args": arguments},
                         sort_keys=True, ensure_ascii=False,
                         default=str).encode("utf-8")
    d = sm3(payload)
    return d.hex() if isinstance(d, (bytes, bytearray)) else str(d)


class MCPAuthzAdapter:
    """MCP 服务端鉴权适配器。

    platform    Platform 实例（进程内 SDK，或经 HTTP 调用的本地代理）
    audience    本 MCP 服务端标识，须与凭证 aud 严格相等
    tool_scopes 工具名 -> 所需作用域列表；未登记的工具默认拒绝
    """

    def __init__(self, platform, audience, tool_scopes=None):
        if not audience:
            raise ValueError("audience is required (受众绑定不可省略)")
        self.platform = platform
        self.audience = audience
        self.tool_scopes = dict(tool_scopes or {})
        # 请求指纹表，用于 per-request 防重放（见 authorize_tool_call）
        self._seen_requests = set()

    # ---------------------------------------------------------------
    # 工具作用域登记
    # ---------------------------------------------------------------
    def register_tool(self, name, scopes):
        """登记一个工具及其所需作用域。"""
        self.tool_scopes[name] = list(scopes)
        return self

    def required_scope(self, tool_name):
        """返回工具所需作用域；未登记返回 None（调用方须按拒绝处理）。"""
        return self.tool_scopes.get(tool_name)

    # ---------------------------------------------------------------
    # 凭证提取
    # ---------------------------------------------------------------
    @staticmethod
    def extract_credential(params):
        """从 MCP 请求参数中提取凭证与委托链。

        支持两种携带方式（兼容不同客户端实现）：
            params._meta.credential / params._meta.chain
            params.credential      / params.chain
        """
        if not isinstance(params, dict):
            return None, None
        meta = params.get("_meta") or {}
        cred = meta.get("credential") or params.get("credential")
        chain = meta.get("chain") or params.get("chain")
        return cred, chain

    # ---------------------------------------------------------------
    # 核心：工具调用鉴权
    # ---------------------------------------------------------------
    def authorize_tool_call(self, credential=None, tool_name=None,
                            chain=None, arguments=None,
                            nonce_mode="per-request"):
        """鉴权一次工具调用。

        credential   单凭证（wire 格式）；与 chain 二选一
        chain        委托链（wire 格式列表），末端为执行者
        tool_name    被调用的工具名
        arguments    工具参数（参与请求指纹，防重放）
        nonce_mode   防重放粒度（重要，别默认错）：
            "per-request"（默认）——按 (jti, 工具, 参数) 三元组去重。
                同一张凭证可调用不同工具、或带不同参数重复调用，
                但完全相同的请求不可重放。这是 MCP 场景的正确粒度：
                一张短时凭证在一次任务内要调多次工具。
            "once"           ——走平台级 nonce，一凭证仅能用一次。
                更严格，适用于一次性的高危操作。

        返回决策字典，关键字段：
            allow           是否放行
            reason          "ok" 或具体拒绝原因
            required_scope  该工具所需作用域
            granted_scope   凭证实际授予的作用域（委托链取交集）
            sub             主体标识（末端执行者）
            act             发起方标识（委托链根签发方）
            jti             末端凭证撤销句柄
        """
        decision = {
            "allow": False, "reason": "unspecified",
            "tool": tool_name, "audience": self.audience,
            "required_scope": None, "granted_scope": None,
            # sub = 主体（末端执行者）；act = 代表方（防混淆代理人，
            # 无委托时与 sub 相同）；origin = 授权链源头（责任溯源用）。
            # 三者语义不同，不可混用。
            "sub": None, "act": None, "origin": None, "jti": None,
            "chain_length": 0,
        }

        # 1) 工具是否已登记（fail-closed：未登记即拒绝）
        required = self.required_scope(tool_name)
        if required is None:
            decision["reason"] = "tool not registered"
            self._audit(decision, arguments)
            return decision
        decision["required_scope"] = list(required)

        # 2) 凭证是否存在
        if not credential and not chain:
            decision["reason"] = "missing credential"
            self._audit(decision, arguments)
            return decision

        # 3) 委托链 or 单凭证
        if chain:
            res = self.platform.verify_delegation_chain(
                chain, self.audience, list(required))
            decision["chain_length"] = len(chain)
            if not res.get("ok"):
                decision["reason"] = self._chain_reason(res)
                self._audit(decision, arguments)
                return decision
            decision["granted_scope"] = list(res.get("scope_intersection") or [])
            tail = chain[-1]
            decision["sub"] = tail.get("sub")
            decision["act"] = tail.get("act") or tail.get("sub")
            decision["origin"] = chain[0].get("iss")
            decision["jti"] = tail.get("jti")
        else:
            v = self.platform.verify_credential(
                credential, audience=self.audience,
                record_nonce=(nonce_mode == "once"))
            if not v.get("ok"):
                decision["reason"] = v.get("reason") or "credential invalid"
                self._audit(decision, arguments)
                return decision
            granted = set(credential.get("scope") or [])
            decision["granted_scope"] = sorted(granted)
            decision["sub"] = credential.get("sub")
            decision["act"] = credential.get("act") or credential.get("sub")
            decision["origin"] = credential.get("iss")
            decision["jti"] = credential.get("jti")
            # 单凭证的作用域是否覆盖工具所需
            if not set(required).issubset(granted):
                lack = sorted(set(required) - granted)
                decision["reason"] = "insufficient scope: %s" % lack
                self._audit(decision, arguments)
                return decision

        # per-request 防重放：完全相同的 (凭证, 工具, 参数) 不可重放
        if nonce_mode == "per-request":
            fp = _request_fingerprint(decision["jti"], tool_name, arguments)
            if fp in self._seen_requests:
                decision["reason"] = "replay detected"
                self._audit(decision, arguments)
                return decision
            self._seen_requests.add(fp)

        decision["allow"] = True
        decision["reason"] = "ok"
        self._audit(decision, arguments)
        return decision

    # ---------------------------------------------------------------
    # 资源读取鉴权
    # ---------------------------------------------------------------
    def authorize_resource_read(self, credential=None, resource_uri=None,
                                chain=None, required_scope=None,
                                nonce_mode="per-request"):
        """鉴权一次资源读取。

        required_scope 未显式给出时，按约定取 ["resource:read"]。
        nonce_mode 语义同 authorize_tool_call；资源读取同样按
        (jti, 资源, 作用域) 三元组做 per-request 防重放。
        """
        scope = list(required_scope or ["resource:read"])
        decision = {
            "allow": False, "reason": "unspecified",
            "tool": "resources/read", "audience": self.audience,
            "required_scope": scope, "granted_scope": None,
            "sub": None, "act": None, "origin": None, "jti": None,
            "resource": resource_uri, "chain_length": 0,
        }
        if not credential and not chain:
            decision["reason"] = "missing credential"
            self._audit(decision, None)
            return decision

        if chain:
            res = self.platform.verify_delegation_chain(
                chain, self.audience, scope)
            decision["chain_length"] = len(chain)
            if not res.get("ok"):
                decision["reason"] = self._chain_reason(res)
                self._audit(decision, None)
                return decision
            decision["granted_scope"] = list(res.get("scope_intersection") or [])
            decision["sub"] = chain[-1].get("sub")
            decision["act"] = chain[-1].get("act") or chain[-1].get("sub")
            decision["origin"] = chain[0].get("iss")
            decision["jti"] = chain[-1].get("jti")
        else:
            v = self.platform.verify_credential(
                credential, audience=self.audience,
                record_nonce=(nonce_mode == "once"))
            if not v.get("ok"):
                decision["reason"] = v.get("reason") or "credential invalid"
                self._audit(decision, None)
                return decision
            granted = set(credential.get("scope") or [])
            decision["granted_scope"] = sorted(granted)
            decision["sub"] = credential.get("sub")
            decision["act"] = credential.get("act") or credential.get("sub")
            decision["origin"] = credential.get("iss")
            decision["jti"] = credential.get("jti")
            if not set(scope).issubset(granted):
                lack = sorted(set(scope) - granted)
                decision["reason"] = "insufficient scope: %s" % lack
                self._audit(decision, None)
                return decision

        # per-request 防重放：同一凭证读同一资源的重复请求不可重放
        if nonce_mode == "per-request":
            fp = _request_fingerprint(decision["jti"], resource_uri, scope)
            if fp in self._seen_requests:
                decision["reason"] = "replay detected"
                self._audit(decision, None)
                return decision
            self._seen_requests.add(fp)

        decision["allow"] = True
        decision["reason"] = "ok"
        self._audit(decision, None)
        return decision

    # ---------------------------------------------------------------
    # 最小权限：工具清单过滤
    # ---------------------------------------------------------------
    def filter_tools(self, credential=None, tools=None, chain=None):
        """按凭证作用域过滤可见工具（最小权限，先过滤而非先放行）。

        tools 为 [{"name":..., "description":...}, ...]。
        凭证无效时返回空列表——看不到就不该调。
        """
        if tools is None:
            tools = [{"name": n} for n in sorted(self.tool_scopes)]
        granted = self._granted_scope(credential, chain)
        if granted is None:
            return []
        visible = []
        for t in tools:
            name = t.get("name") if isinstance(t, dict) else t
            req = self.required_scope(name)
            if req is None:
                continue  # 未登记工具一律不暴露
            if set(req).issubset(granted):
                visible.append(t)
        return visible

    def _granted_scope(self, credential, chain):
        """取凭证实际作用域；无效返回 None。"""
        if chain:
            res = self.platform.verify_delegation_chain(
                chain, self.audience, [])
            if not res.get("ok"):
                return None
            return set(res.get("scope_intersection") or [])
        if credential:
            v = self.platform.verify_credential(
                credential, audience=self.audience, record_nonce=False)
            if not v.get("ok"):
                return None
            return set(credential.get("scope") or [])
        return None

    # ---------------------------------------------------------------
    # MCP JSON-RPC 统一入口
    # ---------------------------------------------------------------
    def handle_request(self, method, params=None):
        """处理一条 MCP 请求，返回鉴权结果。

        返回 dict：
            allow   是否放行
            reason  原因
            ...     视方法不同附带 tools / decision 等

        握手方法（initialize / ping）无需鉴权直接放行。
        """
        params = params or {}
        if method in _HANDSHAKE_METHODS:
            return {"allow": True, "reason": "handshake", "method": method}

        cred, chain = self.extract_credential(params)

        if method == "tools/list":
            tools = params.get("tools")
            visible = self.filter_tools(cred, tools, chain)
            return {"allow": True, "reason": "ok", "method": method,
                    "tools": visible}

        if method == "tools/call":
            name = params.get("name")
            d = self.authorize_tool_call(
                credential=cred, tool_name=name, chain=chain,
                arguments=params.get("arguments"))
            d["method"] = method
            d["arguments"] = params.get("arguments")
            return d

        if method == "resources/read":
            d = self.authorize_resource_read(
                credential=cred, resource_uri=params.get("uri"),
                chain=chain, required_scope=params.get("required_scope"))
            d["method"] = method
            return d

        # 未知方法：失败关闭。拒绝决策同样入审计——
        # 探测未支持方法本身是可疑行为，须留痕。
        self._audit({"tool": method, "allow": False,
                     "reason": "unsupported method"}, None)
        return {"allow": False, "reason": "unsupported method",
                "method": method}

    # ---------------------------------------------------------------
    # 内部：审计与原因归一
    # ---------------------------------------------------------------
    def _chain_reason(self, res):
        reasons = res.get("reasons") or []
        if not res.get("scope_satisfied"):
            return "insufficient scope on chain"
        if not res.get("audience_satisfied"):
            return "audience mismatch on chain"
        for r in reasons:
            if not r.endswith(": ok"):
                return r
        return "chain verification failed"

    def _audit(self, decision, arguments=None):
        """鉴权决策入审计链（放行与拒绝都记）。"""
        try:
            self.platform.audit.append({
                "kind": "mcp.authorize",
                "tenant": getattr(self.platform, "tenant", None),
                "audience": self.audience,
                "tool": decision.get("tool"),
                "allow": decision.get("allow"),
                "reason": decision.get("reason"),
                "sub": decision.get("sub"),
                "act": decision.get("act"),
                "jti": decision.get("jti"),
                "chain_length": decision.get("chain_length"),
                "required_scope": decision.get("required_scope"),
                "granted_scope": decision.get("granted_scope"),
                "has_arguments": arguments is not None,
            })
        except Exception:
            pass  # 审计失败不阻塞鉴权主流程


# ------------------------------------------------------------------
# 自检
# ------------------------------------------------------------------
def self_check():
    """MCP 鉴权适配器端到端自检。"""
    from agent_platform import Platform
    from credential import ALG_SM2

    out = []
    p = Platform(tenant="mcp")
    for idn in ["agent://mcp/root", "agent://mcp/orch", "agent://mcp/worker"]:
        p.register_identity(idn, org="mcp")
    p.configure_policy({"allowed_algs": [ALG_SM2], "max_ttl_seconds": 3600})

    authz = MCPAuthzAdapter(
        p, audience="mcp://fileserver",
        tool_scopes={"read_file": ["file:read"],
                     "write_file": ["file:write"]})

    # 签发一张具备 file:read 的凭证
    r = p.issue_credential("agent://mcp/root", "agent://mcp/orch",
                           "mcp://fileserver", ["file:read"], ttl=3600)
    cred = r["cred"]

    d = authz.authorize_tool_call(cred, "read_file")
    out.append(("MCP 授权通过（作用域匹配）",
                d["allow"] and d["reason"] == "ok"))

    d = authz.authorize_tool_call(cred, "write_file")
    out.append(("MCP 拒绝（作用域不足）",
                not d["allow"] and "insufficient scope" in d["reason"]))

    d = authz.authorize_tool_call(cred, "delete_file")
    out.append(("MCP 拒绝（工具未登记 fail-closed）",
                not d["allow"] and d["reason"] == "tool not registered"))

    # 受众不符
    r2 = p.issue_credential("agent://mcp/root", "agent://mcp/orch",
                            "mcp://otherserver", ["file:read"], ttl=3600)
    d = authz.authorize_tool_call(r2["cred"], "read_file")
    out.append(("MCP 拒绝（受众不符，防跨服务挪用）", not d["allow"]))

    # 防重放：同一凭证二次使用
    d2 = authz.authorize_tool_call(cred, "read_file")
    out.append(("MCP 拒绝（同一凭证重放）", not d2["allow"]))

    # 委托链：worker 持链调用
    r3 = p.issue_credential("agent://mcp/root", "agent://mcp/orch",
                            "mcp://fileserver", ["file:read"], ttl=3600)
    r4 = p.issue_delegation("agent://mcp/orch", "agent://mcp/worker",
                            "mcp://fileserver", ["file:read"], ttl=3600,
                            parent_cred=r3["cred"])
    d = authz.authorize_tool_call(chain=[r3["cred"], r4["cred"]],
                                  tool_name="read_file")
    out.append(("MCP 委托链调用放行", d["allow"]))
    out.append(("MCP 委托链区分 sub 与 act",
                d["sub"] == "agent://mcp/worker"
                and d["act"] == "agent://mcp/root"))

    # 最小权限过滤
    tools = [{"name": "read_file"}, {"name": "write_file"},
             {"name": "delete_file"}]
    vis = authz.filter_tools(r3["cred"], tools)
    names = [t["name"] for t in vis]
    out.append(("MCP tools/list 最小权限过滤",
                names == ["read_file"]))

    # JSON-RPC 入口
    res = authz.handle_request("initialize", {})
    out.append(("MCP 握手放行", res["allow"]))
    res = authz.handle_request(
        "tools/call", {"name": "read_file", "_meta": {"credential": r3["cred"]}})
    out.append(("MCP JSON-RPC tools/call 放行", res["allow"]))
    res = authz.handle_request("unknown/method", {})
    out.append(("MCP 未知方法拒绝", not res["allow"]))

    # 审计留痕
    a = p.audit_query(kind="mcp.authorize", limit=50)
    out.append(("MCP 鉴权决策全部入审计",
                len(a.get("records", [])) >= 6))

    return out


if __name__ == "__main__":
    ok = 0
    res = self_check()
    for name, passed in res:
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            ok += 1
    print("RESULT  PASS=%d  FAIL=%d" % (ok, len(res) - ok))
