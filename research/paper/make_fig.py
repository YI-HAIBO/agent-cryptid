# -*- coding: utf-8 -*-
"""
Generate the four-layer architecture figure for the agent-cryptid paper.

Pure matplotlib rendering (no cairo / cairosvg needed).
Outputs both a high-DPI PNG and a vector PDF so the LaTeX build works
regardless of whether pdflatex or the svg package is used.

All labels are ASCII/English only -- avoids missing-glyph boxes with
DejaVu / limited font sets.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrow

HERE = os.path.dirname(os.path.abspath(__file__))

# --- palette (matches fig_architecture.svg) ---
C_L1 = "#253449"   # slate
C_L2 = "#2f74ea"   # blue
C_L3 = "#8248f1"   # purple
C_L4 = "#0a9d78"   # green
C_T1 = "#1e40af"
C_T2 = "#6d28d9"
C_T3 = "#047857"
C_CALL = "#eef2f7"
C_CALL_TX = "#475569"
C_WHITE = "#f8fafc"
C_SUB = "#d7dfeb"
C_SUB2 = "#a8b6c8"

ARROW = "#33415c"

FS_TITLE = 8.0
FS_HEAD = 6.6
FS_BODY = 5.0
FS_SMALL = 4.6

# vertical step between body lines inside a layer box (axes units)
LH = 0.028
# offset from box top to first (title) line
TOFF = 0.036


def box(ax, x, y, w, h, fc, ec=None, alpha=0.95):
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0,rounding_size=0.014",
        linewidth=0.7,
        edgecolor=ec or fc,
        facecolor=fc,
        alpha=alpha,
        zorder=2,
    )
    ax.add_patch(p)
    return p


def arrow(ax, x, y0, y1):
    ax.add_patch(FancyArrow(
        x, y0, 0, y1 - y0,
        width=0.0022, head_width=0.014, head_length=0.011,
        length_includes_head=True,
        color=ARROW, linewidth=0.8,
        zorder=3,
    ))


def layer_text(ax, x, top, head, lines, small=()):
    """head at top-TOFF, then one line every LH downward."""
    ax.text(x, top - TOFF, head, fontsize=FS_HEAD, fontweight="bold",
            color=C_WHITE, va="top", ha="left")
    y = top - TOFF - 0.026
    for i, s in enumerate(lines):
        fs = FS_SMALL if i in small else FS_BODY
        ax.text(x, y, s, fontsize=fs, color=C_SUB, va="top", ha="left")
        y -= LH


def main():
    fig, ax = plt.subplots(figsize=(3.45, 3.15), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)

    L, R = 0.05, 0.95
    W = R - L
    X = L + 0.024  # text inset

    # ---- Layer 1: Identification  (top 0.945 -> bottom 0.800) ----
    top1, y1, h1 = 0.945, 0.795, 0.150
    box(ax, L, y1, W, h1, C_L1)
    layer_text(ax, X, top1, "Layer 1: Identification", [
        "agent://<org>/<id>   |   tenant-scoped identity record",
        "Public keys: SM2 / ML-DSA-65 / SLH-DSA",
        "Private keys derived locally; hardware root (SecureKeyBackend)",
    ], small=(2,))
    arrow(ax, 0.5, 0.778, 0.793)

    # ---- Layer 2: Credentialing  (top 0.765 -> bottom 0.520) ----
    top2, y2, h2 = 0.765, 0.520, 0.245
    box(ax, L, y2, W, h2, C_L2)
    ax.text(X, top2 - TOFF, "Layer 2: Credentialing - Three-Tier Agility",
            fontsize=FS_HEAD, fontweight="bold", color=C_WHITE, va="top")

    # three tier boxes (2-line labels, taller boxes)
    ty, th = 0.610, 0.080
    tiers = [
        (L + 0.024, 0.250, C_T1, "SM2 Tier\n(GB/T 32918)"),
        (L + 0.302, 0.300, C_T2, "Hybrid: SM2 + ML-DSA-65\n(fail-closed)"),
        (L + 0.630, 0.295, C_T3, "SLH-DSA Tier\n(FIPS 205)"),
    ]
    for tx, tw, tc, tlabel in tiers:
        box(ax, tx, ty, tw, th, tc, alpha=0.88)
        ax.text(tx + tw / 2, ty + th / 2, tlabel,
                fontsize=4.8, fontweight="bold", color="#ffffff",
                ha="center", va="center", linespacing=1.45)

    ax.text(X, 0.585,
            "Fields: iss / sub / act / origin / aud / scope / alg_tier / nonce",
            fontsize=FS_BODY, color="#d6e4ff", va="top")
    ax.text(X, 0.557,
            "Fail-closed: both components must verify; alg_tier signed; aud bound",
            fontsize=FS_BODY, color="#d6e4ff", va="top")
    arrow(ax, 0.5, 0.505, 0.518)

    # ---- Layer 3: Delegation  (top 0.490 -> bottom 0.350) ----
    top3, y3, h3 = 0.490, 0.350, 0.140
    box(ax, L, y3, W, h3, C_L3)
    layer_text(ax, X, top3, "Layer 3: Delegation", [
        "Chainable authority; scope convergence (child \u2286 parent)",
        "sub / act / origin separation blocks confused-deputy attacks",
    ])
    arrow(ax, 0.5, 0.333, 0.348)

    # ---- Layer 4: Notarization  (top 0.315 -> bottom 0.175) ----
    top4, y4, h4 = 0.315, 0.175, 0.140
    box(ax, L, y4, W, h4, C_L4)
    layer_text(ax, X, top4, "Layer 4: Notarization", [
        "Revocation: Merkle accumulator, offline non-revocation proofs",
        "Audit: PoA-signed hash-ledger anchoring (reproducible ChainLedger)",
    ])

    png = os.path.join(HERE, "fig_architecture.png")
    pdf = os.path.join(HERE, "fig_architecture.pdf")
    fig.savefig(png, dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(pdf, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote:", png)
    print("wrote:", pdf)


if __name__ == "__main__":
    main()
