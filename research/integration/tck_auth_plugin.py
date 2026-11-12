# -*- coding: utf-8 -*-
"""cryptid-aware conformance harness：让官方 A2A TCK 能带着 cryptid 凭证跑。

问题（官方 TCK 的硬缺口）
------------------------
TCK（commit 5daf014）全程**没有任何认证入口**，三处证据：

  1. ``tests/compatibility/conftest.py::agent_card``
     → ``response = httpx.get(url)`` —— 拉 Agent Card **不带任何 header**
  2. ``conftest.py::transport_clients``
     → ``client_class(url)`` —— ``JsonRpcClient.__init__(self, base_url: str)``
        只吃一个 URL 参数，**不接受 headers / auth / token**
  3. ``run_tck.py`` / ``pytest_addoption``
     → CLI 只有 ``--sut-host / --transport / --level / --webhook-host``
        **没有** ``--header`` / ``--token`` / ``--auth`` 之类选项

于是凡是被授权门禁保护的 A2A 服务（而 A2A 规范 AUTH-SERVER-002 明确要求
"Server MUST authenticate every incoming request"），用官方 TCK 去测时，
操作类用例会被 401 挡在门外 —— 报出来的合规率下降**是度量假象，不是
A2A 语义回退**。

解法
----
不改 TCK 一行源码，在 pytest 传输层 monkeypatch ``httpx``，把
``Authorization: Bearer <cryptid token>`` 注入到**每一个**出站请求。
补丁只打两个入口，覆盖 TCK 全部流量：

  · ``httpx.get``                 —— 卡片发现（conftest::agent_card）
  · ``httpx.Client.__init__``     —— 所有 transport client 的 httpx 客户端
                                    （JSONRPC / HTTP+JSON 均出自这里）

因为补丁只作用于**测试进程自己的出站请求**，被测服务（SUT）与 TCK 的代码
都未被修改，可复现、可审计。

用法
----
    CRYPTID_TOKEN=<wire> CRYPTID_SCHEME=bearer \
        python -m pytest tests/compatibility/ -p tck_auth_plugin ...

无 ``CRYPTID_TOKEN`` 时本插件是纯 no-op（便于对照跑未带认证的形态）。
"""
from __future__ import annotations

import os

_SCHEME = os.environ.get("CRYPTID_SCHEME", "bearer").strip()
_TOKEN = os.environ.get("CRYPTID_TOKEN", "").strip()

# 自检计数：确认注入真的发生（写进报告，避免"以为注入了其实没生效"）。
# 用模块级 dict 而非 config.stash —— pytest 的 stash 强制要求 StashKey
# 实例，直接写字符串键会抛 TypeError。
_injected = {"requests": 0, "card_fetches": 0}
_state = {"injected": bool(_TOKEN), "scheme": _SCHEME,
          "token_len": len(_TOKEN), "token_prefix": _TOKEN[:12]}


def _auth_header() -> dict[str, str]:
    return {"Authorization": "%s %s" % (_SCHEME, _TOKEN)}


def pytest_configure(config):
    """在 fixture 求值前打补丁（fixture 都是惰性求值，配置期打即可）。"""
    if not _TOKEN:
        return
    import httpx

    orig_get = httpx.get
    orig_client_init = httpx.Client.__init__

    def _get(url, **kwargs):
        headers = kwargs.get("headers")
        if headers is None:
            kwargs["headers"] = dict(_auth_header())
        else:
            hdrs = dict(headers)
            hdrs.setdefault("Authorization", "%s %s" % (_SCHEME, _TOKEN))
            kwargs["headers"] = hdrs
        _injected["card_fetches"] += 1
        _injected["requests"] += 1
        return orig_get(url, **kwargs)

    def _client_init(self, *args, **kwargs):
        headers = kwargs.get("headers")
        if headers is None:
            kwargs["headers"] = dict(_auth_header())
        else:
            hdrs = dict(headers)
            hdrs.setdefault("Authorization", "%s %s" % (_SCHEME, _TOKEN))
            kwargs["headers"] = hdrs
        _injected["requests"] += 1
        return orig_client_init(self, *args, **kwargs)

    httpx.get = _get
    httpx.Client.__init__ = _client_init


def pytest_sessionfinish(session, exitstatus):
    """把注入计数打到终端，作为"认证真的生效了"的旁证。"""
    info = _state
    if info and info.get("injected"):
        tr = session.config.pluginmanager.get_plugin("terminalreporter")
        if tr is not None:
            tr.write_line("")
            tr.write_line(
                "  [cryptid-auth] injected=%s scheme=%s token_prefix=%s... "
                "card_fetches=%d client_requests=%d" % (
                    info["injected"], info["scheme"], info["token_prefix"],
                    _injected["card_fetches"], _injected["requests"]))
