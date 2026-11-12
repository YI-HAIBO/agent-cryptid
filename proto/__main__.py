# -*- coding: utf-8 -*-
"""proto 包入口：`python -m proto [--check | --smoke | --http | --demo]`。

等价于直接执行 `python entrypoint.py ...`，只是走包导入路径，
便于在把本目录当作模块/包调用的场景下使用（见 README 目录说明）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from entrypoint import main  # noqa: E402

if __name__ == "__main__":
    main()
