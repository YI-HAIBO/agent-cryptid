# -*- coding: utf-8 -*-
"""Step 4 SUT：可被**官方 A2A TCK** 与**多语言客户端**测试的真实 A2A 服务。

为什么需要它
------------
官方 TCK（``a2aproject/a2a-tck``）的工作方式是把一个 A2A 实现当作
System Under Test：

    run_tck.py --sut-host http://localhost:9999 --transport jsonrpc

它会做三件事：
  1. 从 ``{sut-host}/.well-known/agent-card.json`` **无鉴权**拉取 Agent Card
     （A2A 规范 §8.2 的服务发现要求）；
  2. 读卡片 ``supportedInterfaces[]`` 的 ``protocolBinding`` + ``url``，
     为每个接口建对应 transport client（JSONRPC / GRPC / HTTP+JSON）；
  3. 跑 RFC 2119 分层用例，逐 requirement 记录 PASS/FAIL，出报告。

本模块提供三种部署形态（同一个 app 工厂，参数切换）：

  ``baseline``  无鉴权、不声明 cryptid —— 测「底层 A2A 实现」本身是否符合规范
  ``gated``     卡片公开 + 操作加锁 —— **推荐形态**：发现公开、操作受 cryptid 保护
  ``card-gated`` 连卡片一起锁 —— 反例，用于证明它会破坏 §8.2 发现（TCK 直接挂）

用法
----
    # 基线（给 TCK 用）
    python sut_a2a_server.py --mode baseline --port 9999

    # 推荐形态（给多语言客户端用）
    python sut_a2a_server.py --mode gated --port 9999
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from a2a_guard import (CryptidAuthMiddleware, _make_agent_card,  # noqa: E402
                       _make_echo_executor)

CARD_URL = "/.well-known/agent-card.json"


def build_sut_app(base_url, *, mode="baseline", declare_cryptid=True,
                  platform=None, expected_aud="service://a2a-agent",
                  card_name="cryptid-guarded-agent",
                  card_desc="A2A agent guarded by agent-cryptid credentials"):
    """构造 A2A FastAPI app。返回 (app, meta)。

    - base_url: 卡片 supportedInterfaces 里写的外部地址（TCK 会照着连）。
    - mode: baseline / gated / card-gated（见模块 docstring）。
    - platform / expected_aud: 仅 gated 与 card-gated 需要。
    """
    from fastapi import FastAPI
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (add_a2a_routes_to_fastapi,
                                   create_agent_card_routes,
                                   create_jsonrpc_routes)

    # gated 形态不声明 cryptid 安全方案（那是基线的"纯 A2A"对照）；
    # card-gated 仍声明，因为卡片的职责是告知客户端"该带什么凭证"。
    card = _make_agent_card(card_name, card_desc, "1.0.0",
                            cryptid_aud=expected_aud,
                            declare_cryptid=declare_cryptid,
                            base_url=base_url)
    handler = DefaultRequestHandler(
        agent_executor=_make_echo_executor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    app = FastAPI(title=card_name)

    if mode in ("gated", "card-gated"):
        # 关键：gated 模式必须把 agent-card 路由放行（A2A §8.2 发现），
        # 只锁 JSON-RPC 消息路由。card-gated 是反例，故意连卡片一起锁。
        exempt = (CARD_URL,) if mode == "gated" else ("/health",)
        app.add_middleware(CryptidAuthMiddleware, platform=platform,
                           expected_aud=expected_aud, exempt_paths=exempt,
                           record_nonce=False)

    card_routes = create_agent_card_routes(card, card_url=CARD_URL)
    jsonrpc_routes = create_jsonrpc_routes(handler, rpc_url="/")
    add_a2a_routes_to_fastapi(app, agent_card_routes=card_routes,
                              jsonrpc_routes=jsonrpc_routes)
    return app, {"card_url": CARD_URL, "rpc_url": "/", "card": card,
                 "mode": mode}


def main():
    import uvicorn
    from cryptid_bridge import CryptidAuthority

    ap = argparse.ArgumentParser(description="cryptid-guarded A2A SUT")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--mode", choices=["baseline", "gated", "card-gated"],
                    default="baseline")
    ap.add_argument("--base-url", default=None,
                    help="卡片里声明的外部地址；默认 http://<host>:<port>/")
    args = ap.parse_args()

    base_url = args.base_url or "http://%s:%d/" % (args.host, args.port)
    auth = CryptidAuthority()
    auth.register("agent://sut/issuer", agent_type="issuance")
    auth.register("agent://sut/worker", agent_type="worker")

    declare = args.mode != "baseline"
    app, meta = build_sut_app(
        base_url, mode=args.mode, declare_cryptid=declare,
        platform=auth.platform)

    print("[SUT] mode=%s base_url=%s card=%s" % (
        meta["mode"], base_url, meta["card_url"]), flush=True)
    print("[SUT] supported_interfaces=%s" % [
        (i.url, i.protocol_binding, i.protocol_version)
        for i in meta["card"].supported_interfaces], flush=True)

    if args.mode in ("gated", "card-gated"):
        tok, _ = auth.issue("agent://sut/issuer", "agent://sut/worker",
                            "service://a2a-agent", ["agent:invoke"], ttl=3600)
        print("[SUT] DEMO_TOKEN=%s" % tok, flush=True)

    uvicorn.run(app, host=args.host, port=args.port,
                log_level="warning", lifespan="off")


if __name__ == "__main__":
    main()
