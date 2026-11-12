# -*- coding: utf-8 -*-
"""
G4 部署拓扑图：agent-cryptid 身份层插入真实 A2A/MCP 多平台边界。

纯 matplotlib 矢量输出（PDF + PNG）。标签 ASCII/英文，配色沿用 make_fig.py。
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrow

HERE = os.path.dirname(os.path.abspath(__file__))
C_AGENT = "#2f74ea"
C_GUARD = "#8248f1"
C_SRV = "#0a9d78"
C_ID = "#253449"
C_CALL = "#eef2f7"
C_CALL_TX = "#475569"
ARROW = "#33415c"


def box(ax, x, y, w, h, fc, ec=None, alpha=0.95, r=0.012):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}",
        linewidth=0.7, edgecolor=ec or fc, facecolor=fc, alpha=alpha, zorder=2))


def main():
    fig, ax = plt.subplots(figsize=(6.7, 2.9), dpi=300)
    ax.set_xlim(0, 1); ax.set_ylim(0.40, 0.88); ax.axis("off")
    fig.subplots_adjust(left=0.005, right=0.995, top=0.99, bottom=0.01)

    # ---- 左：调用方代理 ----
    lx, lw = 0.025, 0.185
    box(ax, lx, 0.52, lw, 0.34, C_AGENT)
    ax.text(lx + lw / 2, 0.83, "Calling Agents", fontsize=5.6, fontweight="bold",
            color="#fff", ha="center", va="top")
    ax.text(lx + lw / 2, 0.75, "Dev {r,w,admin}", fontsize=4.2,
            color="#dbe8ff", ha="center", va="top")
    ax.text(lx + lw / 2, 0.665, "Ops {r,w}", fontsize=4.2,
            color="#dbe8ff", ha="center", va="top")
    ax.text(lx + lw / 2, 0.58, "Sec {r}", fontsize=4.2,
            color="#dbe8ff", ha="center", va="top")

    # ---- 中：cryptid 身份边界 ----
    mx, mw = 0.245, 0.30
    box(ax, mx, 0.42, mw, 0.44, C_GUARD)
    ax.text(mx + mw / 2, 0.825, "cryptid Identity Boundary", fontsize=5.6,
            fontweight="bold", color="#fff", ha="center", va="top")
    ax.text(mx + mw / 2, 0.755, "Platform: issue / verify / delegate", fontsize=4.4,
            color="#efe2ff", ha="center", va="top")
    ax.text(mx + mw / 2, 0.695, "A2A CryptidAuthMiddleware", fontsize=4.4,
            color="#efe2ff", ha="center", va="top")
    ax.text(mx + mw / 2, 0.635, "MCP CryptidTokenVerifier", fontsize=4.4,
            color="#efe2ff", ha="center", va="top")
    ax.text(mx + mw / 2, 0.575, "delegation-chain verifier", fontsize=4.4,
            color="#efe2ff", ha="center", va="top")
    ax.text(mx + mw / 2, 0.50, "Bearer credential\n(aud + scope + alg_tier + nonce)",
            fontsize=4.0, color="#efe2ff", ha="center", va="top", linespacing=1.4)

    # ---- 右：资源服务 ----
    rx, rw = 0.585, 0.185
    box(ax, rx, 0.60, rw, 0.26, C_SRV)
    ax.text(rx + rw / 2, 0.835, "A2A Agent", fontsize=5.4, fontweight="bold",
            color="#fff", ha="center", va="top")
    ax.text(rx + rw / 2, 0.77, "echo executor", fontsize=4.3, color="#d6f5ea",
            ha="center", va="top")
    box(ax, rx, 0.42, rw, 0.16, C_SRV)
    ax.text(rx + rw / 2, 0.55, "MCP Server", fontsize=5.4, fontweight="bold",
            color="#fff", ha="center", va="top")
    ax.text(rx + rw / 2, 0.48, "invoice tool", fontsize=4.3, color="#d6f5ea",
            ha="center", va="top")

    # ---- 箭头 ----
    for y0, y1 in [(0.66, 0.64), (0.50, 0.50)]:
        ax.annotate("", xy=(rx - 0.006, y1), xytext=(mx + mw + 0.004, y0),
                    arrowprops=dict(arrowstyle="-|>", color=ARROW, lw=0.9))
    ax.annotate("", xy=(mx - 0.006, 0.60), xytext=(lx + lw + 0.004, 0.60),
                arrowprops=dict(arrowstyle="-|>", color=ARROW, lw=0.9))
    ax.text((lx + lw + mx) / 2, 0.62, "Bearer", fontsize=4.2, color=C_CALL_TX,
            ha="center", va="bottom")
    ax.text((mx + mw + rx) / 2, 0.72, "verify", fontsize=4.2, color=C_CALL_TX,
            ha="center", va="bottom")

    for name in ("fig_deployment_topology.png", "fig_deployment_topology.pdf"):
        fig.savefig(os.path.join(HERE, name), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote:", "fig_deployment_topology.png/.pdf")


if __name__ == "__main__":
    main()
