# -*- coding: utf-8 -*-
"""Mock 智能体运行时：把 Platform API 包装成 Agent 与 Service 两个角色。

设计：
    - Agent：持有一组已签发凭证，支持接收委托链、发起服务调用。
    - Service：暴露一个受保护资源，调用需通过凭证链校验。
    - 全部进程内演示，模拟真实生产环境的角色边界。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_platform import Platform  # noqa: E402


class Agent:
    """智能体实例，持有本平台签发的凭证与已接到的委托链。"""

    def __init__(self, idn, name=""):
        self.idn = idn
        self.name = name or idn.split("/")[-1]
        self.creds = []       # 已持有的凭证 wire dicts
        self.audit_calls = 0

    def receive(self, cred_wire):
        """接一枚凭证。"""
        self.creds.append(cred_wire)

    def call_service(self, service, target_scope, platform,
                     chain_wires=None):
        """调用服务。chain_wires 是给服务看的完整委托链。

        无论校验成功或失败，都在 service.calls 里留一条审计记录。
        """
        self.audit_calls += 1
        chain = chain_wires or self.creds
        result = platform.verify_delegation_chain(
            chain, target_audience=service.audience,
            target_scope=target_scope)
        if not result["ok"]:
            service.calls.append({
                "caller": self.idn,
                "requested": list(target_scope),
                "chain_length": result.get("chain_length", 0),
                "scope_intersection": result.get("scope_intersection", []),
                "action": "rejected",
                "reason": result.get("reasons", []),
            })
            return {"ok": False, "reason": result["reasons"]}
        return service.execute(target_scope, self.idn, result)


class Service:
    """受保护资源，通过 Platform 校验委托链再执行。"""

    def __init__(self, audience, allowed_scopes, description=""):
        self.audience = audience
        self.allowed_scopes = set(allowed_scopes)
        self.description = description
        self.calls = []

    def execute(self, requested_scope, caller_idn, chain_result):
        """执行一次资源调用，返回业务结果。"""
        record = {
            "caller": caller_idn,
            "requested": list(requested_scope),
            "chain_length": chain_result["chain_length"],
            "scope_intersection": chain_result["scope_intersection"],
            "action": "executed",
        }
        self.calls.append(record)
        return {"ok": True, "caller": caller_idn,
                "action": "executed",
                "data": "invoice-list[0..3] (mock)",
            }
