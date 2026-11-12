# -*- coding: utf-8 -*-
"""主流智能体编排框架的插件（FR7-04）。

LangChain / AutoGen / CrewAI 一类编排框架把「工具」暴露给大模型调用，
框架本身只负责调度，几乎不做授权——谁能调用工具由框架使用者自己保证。
一旦智能体开始自主调用工具，缺失授权依据就是最危险的缺口：一次越权的
文件删除或转账调用，在日志里只是普通的一次函数调用。

本模块把智能体密码身份中台接进编排框架：工具被调用前，用中台凭证完成
鉴权，每一次调用都有密码学可验证的授权依据，且全部（含拒绝）入审计链。

零第三方依赖约束（重要，别改坏）：
    本项目坚持零外部依赖 + 纯 Python 自研，因此本模块**不 import
    langchain / autogen / crewai**。做法是鸭子类型适配——产出的对象
    满足各框架对工具的属性与方法约定，可直接塞进对应框架的 tools
    列表，但不引入对框架包的硬依赖。这样既接入生态又不破坏零依赖。

各框架的约定适配点：
    LangChain  BaseTool：属性 name / description；调用 run() / invoke()
               / _run()；函数式工具读 func。
    CrewAI     BaseTool：属性 name / description；调用 _run() / run()。
    AutoGen    函数注册用 dict：{"name", "description", "function"}。

设计要点（后续别改坏）：
  1. 失败关闭：未登记的工具默认拒绝；任何一步不通过即拒绝。
  2. 受众绑定：凭证 aud 必须等于本插件的 audience，防跨服务挪用。
  3. 最小权限：按凭证实际作用域校验，不靠"先调用再判断"。
  4. 委托链：末端执行者持链调用时权限取链上交集；
     sub（末端执行者）与 act（发起方）分别返回，防混淆代理人。
  5. 防重放：per-request 粒度，按 (jti, 工具, 参数) 去重——
     一张短时凭证在一次任务内要调多次工具，按凭证一次性会误杀。
  6. 全量审计：每次调用（含拒绝）都入审计链。

用法：
    plat = Platform(tenant="acme")
    plug = OrchestratorPlugin(plat, audience="orch://invoice-bot")
    plug.register_tool("restart_service", my_fn, scopes=["ops:restart"])

    # 直接调用
    plug.invoke("restart_service", {"name": "nginx"}, credential=cred)

    # 接入 LangChain / CrewAI（duck typing，直接放进 tools 列表）
    tool = plug.as_tool("restart_service", description="重启服务")

    # 接入 AutoGen（dict 形式注册函数）
    fn_schema = plug.as_autogen_function("restart_service")
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _request_fingerprint(jti, tool, arguments):
    """请求指纹：(jti, 工具, 参数) → SM3 hex。与 MCP 适配器同口径。"""
    import json
    from sm2 import sm3
    payload = json.dumps({"jti": jti, "tool": tool, "args": arguments},
                         sort_keys=True, ensure_ascii=False,
                         default=str).encode("utf-8")
    d = sm3(payload)
    return d.hex() if isinstance(d, (bytes, bytearray)) else str(d)


class CryptidTool:
    """鸭子类型工具对象。

    同时满足 LangChain 与 CrewAI 对工具的属性/方法约定：
        name / description    两个框架都读
        _run()                CrewAI BaseTool 与 LangChain BaseTool 的实现入口
        run() / invoke()      LangChain 常用调用方式
        func                  函数式工具读取的原始 callable

    不继承任何框架基类（保持零依赖）；框架若要求 isinstance 校验，
    则由使用者在框架侧做薄包装，本对象提供全部所需属性。
    """

    def __init__(self, name, description, func):
        self.name = name
        self.description = description or name
        self.func = func

    def _run(self, *args, **kwargs):
        """CrewAI / LangChain BaseTool 的实现入口。"""
        return self.func(*args, **kwargs)

    def run(self, tool_input=None, **kwargs):
        """LangChain 字符串入参风格。"""
        if isinstance(tool_input, dict):
            return self.func(**tool_input)
        return self.func(tool_input, **kwargs) if tool_input is not None \
            else self.func(**kwargs)

    def invoke(self, input=None, **kwargs):
        """LangChain 新版本统一入口。"""
        if isinstance(input, dict):
            return self.func(**input)
        return self.run(input, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class OrchestratorPlugin:
    """编排框架身份插件。

    platform    Platform 实例
    audience    本插件服务的受众标识，须与凭证 aud 严格相等
    nonce_mode  防重放粒度："per-request"（默认）或 "once"
    """

    def __init__(self, platform, audience, nonce_mode="per-request"):
        if not audience:
            raise ValueError("audience is required (受众绑定不可省略)")
        self.platform = platform
        self.audience = audience
        self.nonce_mode = nonce_mode
        # name -> {"fn": callable, "scopes": [...], "description": str}
        self._tools = {}
        self._seen_requests = set()

    # ---------------------------------------------------------------
    # 工具登记
    # ---------------------------------------------------------------
    def register_tool(self, name, fn=None, scopes=None, description=None):
        """登记一个工具及其所需作用域。

        fn 可为 None——HTTP 决策模式下只登记作用域元数据，不提供实现
        （此时只能用 guard() 做鉴权决策，不能 invoke() 执行）。
        """
        desc = description
        if not desc:
            doc = getattr(fn, "__doc__", None) if fn is not None else None
            desc = (doc or name).strip()
        self._tools[name] = {
            "fn": fn,
            "scopes": list(scopes or []),
            "description": desc,
        }
        return self

    def required_scope(self, tool_name):
        """工具所需作用域；未登记返回 None（须按拒绝处理）。"""
        t = self._tools.get(tool_name)
        return list(t["scopes"]) if t else None

    def list_tools(self):
        return sorted(self._tools.keys())

    # ---------------------------------------------------------------
    # 核心：调用鉴权
    # ---------------------------------------------------------------
    def guard(self, tool_name, arguments=None, credential=None, chain=None):
        """鉴权一次工具调用（不执行）。返回决策 dict。

        credential   单凭证 wire；与 chain 二选一
        chain        委托链 wire 列表，末端为执行者
        """
        decision = {
            "allow": False, "reason": "unspecified",
            "tool": tool_name, "audience": self.audience,
            "required_scope": None, "granted_scope": None,
            "sub": None, "act": None, "origin": None, "jti": None,
            "chain_length": 0,
        }

        # 1) 工具必须已登记（fail-closed）
        t = self._tools.get(tool_name)
        if t is None:
            decision["reason"] = "tool not registered"
            self._audit(decision, arguments)
            return decision
        required = t["scopes"]
        decision["required_scope"] = list(required)

        # 2) 凭证必须存在
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
                record_nonce=(self.nonce_mode == "once"))
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
            if not set(required).issubset(granted):
                lack = sorted(set(required) - granted)
                decision["reason"] = "insufficient scope: %s" % lack
                self._audit(decision, arguments)
                return decision

        # 4) per-request 防重放
        if self.nonce_mode == "per-request":
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

    def invoke(self, tool_name, arguments=None, credential=None, chain=None):
        """鉴权并执行工具。返回 {"ok", "result"/"reason", "decision"}。"""
        d = self.guard(tool_name, arguments, credential, chain)
        if not d["allow"]:
            return {"ok": False, "reason": d["reason"], "decision": d}
        fn = self._tools[tool_name]["fn"]
        args = arguments or {}
        try:
            result = fn(**args) if isinstance(args, dict) else fn(args)
        except Exception as e:
            return {"ok": False, "reason": "tool error: %s" % e,
                    "decision": d}
        return {"ok": True, "result": result, "decision": d}

    # ---------------------------------------------------------------
    # 框架适配（鸭子类型）
    # ---------------------------------------------------------------
    def as_tool(self, tool_name, description=None):
        """产出 LangChain / CrewAI 可直接使用的工具对象。

        返回的 CryptidTool 具备 name / description / _run / run /
        invoke / func，满足两框架对工具的属性与方法约定。
        调用时通过闭包携带当前凭证（由外层注入 credential_provider）。
        """
        t = self._tools.get(tool_name)
        if t is None:
            raise ValueError("tool not registered: %s" % tool_name)

        def _guarded(**kwargs):
            cred = kwargs.pop("__credential__", None)
            chain = kwargs.pop("__chain__", None)
            if cred is None and chain is None:
                cred = self._current_credential
            r = self.invoke(tool_name, kwargs, credential=cred, chain=chain)
            if not r["ok"]:
                raise PermissionError(
                    "cryptid: tool %s denied: %s" % (tool_name, r["reason"]))
            return r["result"]

        tool = CryptidTool(tool_name,
                           description or t["description"],
                           _guarded)
        return tool

    def as_autogen_function(self, tool_name, description=None):
        """产出 AutoGen 函数注册用 dict：{name, description, function}。"""
        t = self._tools.get(tool_name)
        if t is None:
            raise ValueError("tool not registered: %s" % tool_name)
        guarded = self.as_tool(tool_name, description)
        return {
            "name": tool_name,
            "description": description or t["description"],
            "function": guarded.func,
        }

    def as_generic(self, tool_name):
        """产出通用 guarded callable（不绑定框架约定）。"""
        return self.as_tool(tool_name).func

    # 当前凭证由外层在调用前注入（框架 plumbing 用）
    _current_credential = None

    def use_credential(self, credential):
        """设置后续 as_tool 产出的工具所使用的凭证。"""
        self._current_credential = credential
        return self

    # ---------------------------------------------------------------
    # 内部：审计与原因归一化
    # ---------------------------------------------------------------
    def _audit(self, decision, arguments=None):
        self.platform.audit.append({
            "kind": "orchestrator.invoke",
            "tenant": self.platform.tenant,
            "tool": decision.get("tool"),
            "audience": self.audience,
            "allow": decision.get("allow"),
            "reason": decision.get("reason"),
            "sub": decision.get("sub"),
            "act": decision.get("act"),
            "jti": decision.get("jti"),
            "required_scope": decision.get("required_scope"),
            "granted_scope": decision.get("granted_scope"),
            "ts": int(time.time()),
        })

    @staticmethod
    def _chain_reason(res):
        reasons = res.get("reasons") or []
        if isinstance(reasons, (list, tuple)) and reasons:
            return str(reasons[0])
        return "chain invalid"


# ------------------------------------------------------------------
# 自测
# ------------------------------------------------------------------
def self_check():
    out = []
    from agent_platform import Platform

    p = Platform(tenant="orchtest")
    p.register_identity("agent://acme/orch", org="acme")
    p.register_identity("agent://acme/worker", org="acme")
    p.register_identity("agent://acme/sub", org="acme")

    calls = []

    def restart_service(name):
        calls.append(("restart", name))
        return "restarted:%s" % name

    def delete_all():
        calls.append(("delete",))
        return "deleted"

    plug = OrchestratorPlugin(p, audience="orch://bot")
    plug.register_tool("restart_service", restart_service,
                       scopes=["ops:restart"], description="重启服务")
    plug.register_tool("delete_all", delete_all,
                       scopes=["ops:delete"], description="删除数据")

    # --- A 登记 ---
    out.append(("A1 工具已登记",
                plug.required_scope("restart_service") == ["ops:restart"]))
    out.append(("A2 未登记工具返回 None",
                plug.required_scope("unknown_tool") is None))
    out.append(("A3 list_tools 含两个", len(plug.list_tools()) == 2))

    # --- B 正常鉴权通过 ---
    r = p.issue_credential(issuer_idn="agent://acme/orch",
                           subject_idn="agent://acme/worker",
                           audience="orch://bot",
                           scope=["ops:restart"], ttl=3600)
    cred = r["cred"]
    d = plug.guard("restart_service", {"name": "nginx"}, credential=cred)
    out.append(("B1 作用域足够放行", d["allow"] is True))
    out.append(("B2 sub 为末端执行者", d["sub"] == "agent://acme/worker"))
    out.append(("B3 act 防混淆代理人有值", d["act"] is not None))

    # --- C 执行 ---
    r2 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:restart"], ttl=3600)
    res = plug.invoke("restart_service", {"name": "api"},
                      credential=r2["cred"])
    out.append(("C1 调用成功", res["ok"] is True))
    out.append(("C2 返回结果正确", res["result"] == "restarted:api"))
    out.append(("C3 工具确实被执行", ("restart", "api") in calls))

    # --- D 无凭证 ---
    d = plug.guard("restart_service", {"name": "x"})
    out.append(("D1 无凭证被拒",
                d["allow"] is False and d["reason"] == "missing credential"))

    # --- E 未登记工具 ---
    d = plug.guard("ghost_tool", {}, credential=cred)
    out.append(("E1 未登记工具被拒",
                d["allow"] is False and d["reason"] == "tool not registered"))

    # --- F 作用域不足 ---
    r3 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:read"], ttl=3600)
    d = plug.guard("restart_service", {"name": "y"},
                   credential=r3["cred"])
    out.append(("F1 作用域不足被拒", d["allow"] is False))
    out.append(("F2 原因含 insufficient scope",
                "insufficient scope" in (d["reason"] or "")))

    # --- G 受众不符（跨服务挪用） ---
    r4 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://other",
                            scope=["ops:restart"], ttl=3600)
    d = plug.guard("restart_service", {"name": "z"},
                   credential=r4["cred"])
    out.append(("G1 受众不符被拒", d["allow"] is False))

    # --- H 防重放（同参数二次） ---
    r5 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:restart"], ttl=3600)
    c5 = r5["cred"]
    d1 = plug.guard("restart_service", {"name": "dup"}, credential=c5)
    d2 = plug.guard("restart_service", {"name": "dup"}, credential=c5)
    out.append(("H1 首次放行", d1["allow"] is True))
    out.append(("H2 同参数重放被拒",
                d2["allow"] is False and d2["reason"] == "replay detected"))
    d3 = plug.guard("restart_service", {"name": "diff"}, credential=c5)
    out.append(("H3 不同参数仍放行", d3["allow"] is True))

    # --- I 撤销凭证 ---
    r6 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:restart"], ttl=3600)
    c6 = r6["cred"]
    d_ok = plug.guard("restart_service", {"name": "pre"}, credential=c6)
    p.revoke(c6["jti"], reason="test")
    d_rev = plug.guard("restart_service", {"name": "post"}, credential=c6)
    out.append(("I1 撤销前放行", d_ok["allow"] is True))
    out.append(("I2 撤销后被拒", d_rev["allow"] is False))
    out.append(("I3 撤销原因正确", d_rev["reason"] == "revoked"))

    # --- J 委托链（权限取交集） ---
    r7 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:restart", "ops:delete"], ttl=7200)
    root = r7["cred"]
    r8 = p.issue_delegation(delegator_idn="agent://acme/worker",
                            delegatee_idn="agent://acme/sub",
                            audience="orch://bot",
                            scope=["ops:restart"],
                            parent_cred=root, ttl=3600)
    chain = [root, r8["cred"]] if r8.get("ok") else None
    if chain:
        d = plug.guard("restart_service", {"name": "chain"}, chain=chain)
        out.append(("J1 委托链调用放行", d["allow"] is True))
        out.append(("J2 链长=2", d["chain_length"] == 2))
        out.append(("J3 sub 为末端执行者", d["sub"] == "agent://acme/sub"))
        out.append(("J4 act 为发起方", d["act"] == "agent://acme/worker"))
        d2 = plug.guard("delete_all", {}, chain=chain)
        out.append(("J5 链上无删除权限被拒", d2["allow"] is False))
    else:
        out.append(("J1 委托链调用放行", False))
        out.append(("J2 链长=2", False))
        out.append(("J3 sub 为末端执行者", False))
        out.append(("J4 act 为发起方", False))
        out.append(("J5 链上无删除权限被拒", False))

    # --- K 框架适配：LangChain / CrewAI 鸭子类型 ---
    tool = plug.as_tool("restart_service", description="重启服务")
    out.append(("K1 工具名正确", tool.name == "restart_service"))
    out.append(("K2 有 description", bool(tool.description)))
    out.append(("K3 有 _run（CrewAI/LangChain 入口）",
                callable(getattr(tool, "_run", None))))
    out.append(("K4 有 run / invoke",
                callable(getattr(tool, "run", None))
                and callable(getattr(tool, "invoke", None))))
    out.append(("K5 有 func（函数式工具）",
                callable(getattr(tool, "func", None))))

    # --- L AutoGen dict schema ---
    schema = plug.as_autogen_function("restart_service")
    out.append(("L1 schema 为 dict", isinstance(schema, dict)))
    out.append(("L2 含 name", schema.get("name") == "restart_service"))
    out.append(("L3 含 description", bool(schema.get("description"))))
    out.append(("L4 function 可调用", callable(schema.get("function"))))

    # --- M 凭证注入后工具可执行 ---
    r9 = p.issue_credential(issuer_idn="agent://acme/orch",
                            subject_idn="agent://acme/worker",
                            audience="orch://bot",
                            scope=["ops:restart"], ttl=3600)
    plug.use_credential(r9["cred"])
    out2 = tool.run({"name": "injected"})
    out.append(("M1 注入凭证后工具执行成功",
                out2 == "restarted:injected"))

    # --- N 无凭证工具抛 PermissionError ---
    plug.use_credential(None)
    denied = False
    try:
        tool.run({"name": "nocred"})
    except PermissionError:
        denied = True
    except Exception:
        denied = False
    out.append(("N1 无凭证执行抛 PermissionError", denied))

    # --- O 审计入链 ---
    kinds = [e.get("event", {}).get("kind") for e in p.audit.chain]
    out.append(("O1 调用审计入链", "orchestrator.invoke" in kinds))
    allow_flags = [e.get("event", {}).get("allow")
                   for e in p.audit.chain
                   if e.get("event", {}).get("kind") == "orchestrator.invoke"]
    out.append(("O2 拒绝也入审计", False in allow_flags))

    return out


if __name__ == "__main__":
    n_ok = 0
    res = self_check()
    for name, passed in res:
        print("%-8s %s" % ("PASS" if passed else "FAIL", name))
        if passed:
            n_ok += 1
    print("\nRESULT  PASS=%d  FAIL=%d" % (n_ok, len(res) - n_ok))
