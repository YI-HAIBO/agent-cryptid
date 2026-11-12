# -*- coding: utf-8 -*-
"""agent-cryptid 原型包（proto）。

本目录既可直接执行各脚本（`python entrypoint.py --check`），
也可作为包调用（`python -m proto`、`python -m proto.entrypoint`）。

注意：包内各模块（sm2 / sm9 / credential / identity / delegation /
agent_platform / mldsa / slhdsa / shake 等）之间用「同目录平铺导入」
（`sys.path.insert(0, 本目录)` + `import sm2`），不使用相对导入，
以保证单独执行任意一个脚本都能正常工作。
"""
