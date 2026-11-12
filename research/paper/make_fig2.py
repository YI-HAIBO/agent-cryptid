# -*- coding: utf-8 -*-
"""
Generate two additional figures for the agent-cryptid paper (Path B / G3).

  fig_delegation_flow.pdf / .png  -- delegation chain with scope convergence,
                                     sub/act/origin separation, and three-tier
                                     agility switching across the chain.
  fig_performance.pdf / .png      -- delegation-chain verification latency vs
                                     chain depth (agent-cryptid vs UCAN), log-y.

Pure matplotlib (no cairo / cairosvg needed). All labels ASCII/English only.
Palette matches fig_architecture (make_fig.py).
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, FancyArrow

HERE = os.path.dirname(os.path.abspath(__file__))

# --- palette (matches make_fig.py) ---
C_L1 = "#253449"
C_L2 = "#2f74ea"
C_L3 = "#8248f1"
C_L4 = "#0a9d78"
C_T1 = "#1e40af"
C_T2 = "#6d28d9"
C_T3 = "#047857"
C_CALL = "#eef2f7"
C_CALL_TX = "#475569"
C_WHITE = "#f8fafc"
C_SUB = "#d7dfeb"
ARROW = "#33415c"


def box(ax, x, y, w, h, fc, ec=None, alpha=0.95, r=0.014, lw=0.7):
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        linewidth=lw, edgecolor=ec or fc, facecolor=fc, alpha=alpha, zorder=2,
    )
    ax.add_patch(p)
    return p


def fig_delegation_flow():
    """Delegation chain + scope convergence + sub/act/origin + agility tiers."""
    fig, ax = plt.subplots(figsize=(6.7, 2.75), dpi=300)
    ax.set_xlim(0, 1); ax.set_ylim(0.42, 0.88); ax.axis("off")
    fig.subplots_adjust(left=0.005, right=0.995, top=0.99, bottom=0.01)

    # ---- three agent nodes ----
    node_w, node_h = 0.185, 0.235
    ys = 0.575
    xs = [0.035, 0.405, 0.775]
    names = ["Root\n(origin)", "Dev", "Ops"]
    scopes = ["{r,w,admin}", "{r,w}", "{r}"]
    tiers = ["SM2", "SM2+ML-DSA\n(fail-closed)", "SLH-DSA"]
    cols = [C_T1, C_T2, C_T3]

    for i, x in enumerate(xs):
        box(ax, x, ys, node_w, node_h, cols[i], alpha=0.9, r=0.012)
        ax.text(x + node_w / 2, ys + node_h - 0.030, names[i],
                fontsize=5.4, fontweight="bold", color="#ffffff",
                ha="center", va="top", linespacing=1.35)
        ax.text(x + node_w / 2, ys + node_h - 0.100, "scope:",
                fontsize=4.4, color="#e3ebf7", ha="center", va="top")
        ax.text(x + node_w / 2, ys + node_h - 0.130, scopes[i],
                fontsize=5.2, fontweight="bold", color="#ffffff",
                ha="center", va="top", linespacing=1.3)
        ax.text(x + node_w / 2, ys + node_h - 0.190, "tier: " + tiers[i].split("\n")[0],
                fontsize=4.3, color="#d6e4ff", ha="center", va="top")
        if "\n" in tiers[i]:
            ax.text(x + node_w / 2, ys + node_h - 0.216, tiers[i].split("\n")[1],
                    fontsize=3.7, color="#d6e4ff", ha="center", va="top")

    # ---- arrows between nodes ----
    for i in range(2):
        x0 = xs[i] + node_w + 0.004
        x1 = xs[i + 1] - 0.004
        ax.annotate("", xy=(x1, ys + node_h * 0.55), xytext=(x0, ys + node_h * 0.55),
                    arrowprops=dict(arrowstyle="-|>", color=ARROW, lw=1.0))

    # ---- hop labels above arrows ----
    hop_labels = [
        "iss: Root, sub: Dev\nact: Dev, origin: Root",
        "iss: Dev, sub: Ops\nact: Ops, origin: Root",
    ]
    for i in range(2):
        xm = (xs[i] + node_w + xs[i + 1]) / 2
        ax.text(xm, ys + node_h + 0.020, hop_labels[i], fontsize=3.9,
                color=C_L1, ha="center", va="bottom", linespacing=1.35)

    # ---- scope convergence bracket (bottom) ----
    ax.text(0.5, 0.470, "scope convergence: child \u2286 parent, enforced at issuance (rejects 'scope escalation')",
            fontsize=4.4, color=C_L3, ha="center", va="center")

    for name in ("fig_delegation_flow.png", "fig_delegation_flow.pdf"):
        fig.savefig(os.path.join(HERE, name), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote:", "fig_delegation_flow.png/.pdf")


def fig_performance():
    """Delegation-chain verification latency vs chain depth (log-y)."""
    fig, ax = plt.subplots(figsize=(3.45, 2.35), dpi=300)
    fig.subplots_adjust(left=0.16, right=0.97, top=0.90, bottom=0.14)

    depth = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    # agent-cryptid: measured (1,4.83) (4,17.1) (10,51.74); linear fit ~5.21 ms/hop
    ac = 4.83 + (51.74 - 4.83) / 9.0 * (depth - 1)
    # UCAN: measured 4h=311.2 -> 77.8 ms/hop
    ucan = 77.8 * depth

    ax.plot(depth, ac, marker="o", markersize=4, color=C_T1, lw=1.4,
            label="agent-cryptid (SM2 tier)")
    ax.plot(depth, ucan, marker="s", markersize=4, color="#b91c1c", lw=1.4,
            label="UCAN (chained sig.)")
    ax.plot([4], [17.1], marker="o", markersize=7, color=C_T1, mfc="none", mec=C_T1)
    ax.plot([4], [311.2], marker="s", markersize=7, color="#b91c1c", mfc="none", mec="#b91c1c")

    ax.annotate("4h: 17.1 ms", xy=(4, 17.1), xytext=(4.5, 40),
                fontsize=4.6, color=C_T1, arrowprops=dict(arrowstyle="-", lw=0.6, color=C_T1))
    ax.annotate("4h: 311.2 ms", xy=(4, 311.2), xytext=(5.8, 640),
                fontsize=4.6, color="#b91c1c", arrowprops=dict(arrowstyle="-", lw=0.6, color="#b91c1c"))
    ax.annotate("18.2\u00d7", xy=(6.4, 95), fontsize=5.4, fontweight="bold",
                color="#33415c", ha="center")

    ax.set_xlabel("delegation chain depth (hops)", fontsize=5.6)
    ax.set_ylabel("verification latency (ms)", fontsize=5.6)
    ax.set_yscale("log")
    ax.set_ylim(1, 1100)
    ax.set_xlim(0.5, 10.5)
    ax.set_xticks([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    ax.set_xticklabels([str(d) for d in depth], fontsize=4.6)
    ax.tick_params(axis="y", labelsize=4.6)
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    ax.legend(fontsize=4.6, loc="upper left", framealpha=0.9, handlelength=1.4)

    for name in ("fig_performance.png", "fig_performance.pdf"):
        fig.savefig(os.path.join(HERE, name), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote:", "fig_performance.png/.pdf")


if __name__ == "__main__":
    fig_delegation_flow()
    fig_performance()
