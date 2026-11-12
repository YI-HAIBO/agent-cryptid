# -*- coding: utf-8 -*-
# ASCII-only converter. Chinese content lives in the .md source only.
import sys
import os
import re

from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

SONG = "\u5b8b\u4f53"          # Song
HEI = "\u9ed1\u4f53"           # Hei
KAI = "\u6977\u4f53_GB2312"    # Kai_GB2312
MONO = "Consolas"

HEADER_SHADING = "D9E2F3"


def set_fonts(run, cn):
    run.font.name = "Times New Roman"
    rPr = run._element.get_or_add_rPr()
    rF = rPr.find(qn('w:rFonts'))
    if rF is None:
        rF = OxmlElement('w:rFonts')
        rPr.insert(0, rF)
    rF.set(qn('w:ascii'), "Times New Roman")
    rF.set(qn('w:hAnsi'), "Times New Roman")
    rF.set(qn('w:eastAsia'), cn)


def add_rich(p, text, size, cn, base_bold=False, align=None):
    """Render inline **bold** segments. Asterisks never reach the document."""
    if align is not None:
        p.alignment = align
    segs = text.split("**")
    for i, seg in enumerate(segs):
        if seg == "":
            continue
        r = p.add_run(seg)
        r.font.size = Pt(size)
        set_fonts(r, cn)
        r.font.bold = bool(base_bold) or (i % 2 == 1)
    return p


def shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hexcolor)
    tcPr.append(shd)


def set_cell_text(cell, text, size, cn, bold=False, align=None):
    cell.text = ""
    p = cell.paragraphs[0]
    pf = p.paragraph_format
    pf.space_before = Pt(2)
    pf.space_after = Pt(2)
    pf.line_spacing = 1.15
    if align is not None:
        p.alignment = align
    add_rich(p, text, size, cn, base_bold=bold, align=align)


def body_para(doc, text, size=12, cn=SONG, indent=True, align=None):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.line_spacing = 1.5
    pf.space_before = Pt(3)
    pf.space_after = Pt(3)
    if indent:
        pf.first_line_indent = Pt(24)
    if align is not None:
        pf.first_line_indent = Pt(0)
        p.alignment = align
    add_rich(p, text, size, cn, align=align)
    return p


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: md2docx.py src.md out.docx\n")
        return 2

    src = sys.argv[1]
    out = sys.argv[2]

    with open(src, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")

    doc = Document()
    sec = doc.sections[0]
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.left_margin = Cm(3.17)
    sec.right_margin = Cm(3.17)
    sec.top_margin = Cm(2.54)
    sec.bottom_margin = Cm(2.54)

    style = doc.styles['Normal']
    style.font.name = "Times New Roman"
    style.font.size = Pt(12)
    style.element.rPr.rFonts.set(qn('w:eastAsia'), SONG)

    seen_break = False
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i].rstrip()
        s = raw.strip()

        if s == "":
            i += 1
            continue

        if s == "BREAK":
            p = doc.add_paragraph()
            p.add_run().add_break(WD_BREAK.PAGE)
            seen_break = True
            i += 1
            continue

        if s.startswith("TABLE:"):
            rows = []
            i += 1
            while i < n and lines[i].strip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(row)
                i += 1
            if not rows:
                continue
            ncol = max(len(r) for r in rows)
            tbl = doc.add_table(rows=len(rows), cols=ncol)
            tbl.style = 'Table Grid'
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            for ri, row in enumerate(rows):
                for ci in range(ncol):
                    val = row[ci] if ci < len(row) else ""
                    cell = tbl.cell(ri, ci)
                    if ri == 0:
                        shade(cell, HEADER_SHADING)
                        set_cell_text(cell, val, 10.5, HEI,
                                      bold=True,
                                      align=WD_ALIGN_PARAGRAPH.CENTER)
                    else:
                        set_cell_text(cell, val, 10.5, SONG)
            doc.add_paragraph()
            continue

        if s.startswith("CENTER:"):
            text = s[len("CENTER:"):].strip()
            size = 22 if not seen_break else 12
            cn = HEI if not seen_break else SONG
            body_para(doc, text, size=size, cn=cn,
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            i += 1
            continue

        if s.startswith("### "):
            text = s[4:].strip()
            p = doc.add_paragraph()
            pf = p.paragraph_format
            pf.line_spacing = 1.5
            pf.space_before = Pt(6)
            pf.space_after = Pt(3)
            pf.first_line_indent = Pt(24)
            add_rich(p, text, 12, SONG, base_bold=True)
            i += 1
            continue

        if s.startswith("## "):
            text = s[3:].strip()
            p = doc.add_paragraph()
            pf = p.paragraph_format
            pf.line_spacing = 1.5
            pf.space_before = Pt(10)
            pf.space_after = Pt(5)
            add_rich(p, text, 13, KAI)
            i += 1
            continue

        if s.startswith("# "):
            text = s[2:].strip()
            if not seen_break:
                p = doc.add_paragraph()
                pf = p.paragraph_format
                pf.space_before = Pt(90)
                pf.space_after = Pt(18)
                add_rich(p, text, 22, HEI,
                         align=WD_ALIGN_PARAGRAPH.CENTER)
            else:
                p = doc.add_paragraph()
                pf = p.paragraph_format
                pf.line_spacing = 1.5
                pf.space_before = Pt(14)
                pf.space_after = Pt(8)
                add_rich(p, text, 15, HEI)
            i += 1
            continue

        if s.startswith("- "):
            text = s[2:].strip()
            body_para(doc, text, size=12, cn=SONG, indent=False)
            i += 1
            continue

        body_para(doc, s)
        i += 1

    doc.save(out)

    # self-verification
    d2 = Document(out)
    bad = sum(1 for p in d2.paragraphs if "*" in p.text)
    bad_tbl = 0
    for t in d2.tables:
        for row in t.rows:
            for c in row.cells:
                if "*" in c.text:
                    bad_tbl += 1
    report = "OUTPUT=%s\nparagraphs=%d\ntables=%d\nstray_asterisk_para=%d\nstray_asterisk_cell=%d\n" % (
        out, len(d2.paragraphs), len(d2.tables), bad, bad_tbl)
    with open(os.path.join(os.path.dirname(os.path.abspath(out)), "_build_report.txt"),
              "w", encoding="utf-8") as f:
        f.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
