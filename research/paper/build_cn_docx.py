# -*- coding: utf-8 -*-
# Build the Chinese (CNKI-format) manuscript docx from agent_cryptid_cn.md
import re
import os
from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

HERE = os.path.dirname(os.path.abspath(__file__))
SONG = "宋体"
HEI = "黑体"
KAI = "楷体_GB2312"
MONO = "Times New Roman"

CN_NUM = ["一", "二", "三", "四", "五", "六", "七", "八", "九", "十", "十一", "十二"]


def set_fonts(run, cn, size):
    run.font.name = MONO
    run.font.size = Pt(size)
    rPr = run._element.get_or_add_rPr()
    rF = rPr.find(qn('w:rFonts'))
    if rF is None:
        rF = OxmlElement('w:rFonts')
        rPr.insert(0, rF)
    rF.set(qn('w:ascii'), MONO)
    rF.set(qn('w:hAnsi'), MONO)
    rF.set(qn('w:eastAsia'), cn)


def add_text(p, text, cn, size, bold=False, align=None, indent=False, line15=True):
    if align is not None:
        p.alignment = align
    pf = p.paragraph_format
    if line15:
        pf.line_spacing = 1.5
    if indent:
        pf.first_line_indent = Pt(size * 2)
    segs = re.split(r'(\*\*[^*]+\*\*|\*[^*]+\*)', text)
    for seg in segs:
        if seg == "":
            continue
        b = bold
        if seg.startswith("**") and seg.endswith("**"):
            seg = seg[2:-2]
            b = True
        elif seg.startswith("*") and seg.endswith("*") and len(seg) > 2:
            seg = seg[1:-1]
        r = p.add_run(seg)
        set_fonts(r, cn, size)
        r.font.bold = b


def add_heading(doc, text, level, num_prefix):
    p = doc.add_paragraph()
    if level == 1:
        cn, size = HEI, 15
        full = num_prefix + text
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        add_text(p, full, cn, size, bold=False)
    elif level == 2:
        cn, size = KAI, 13
        full = num_prefix + text
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        add_text(p, full, cn, size, bold=False)
    else:
        cn, size = SONG, 12
        full = num_prefix + text
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        add_text(p, full, cn, size, bold=True)
    pf = p.paragraph_format
    pf.line_spacing = 1.5
    pf.space_before = Pt(6)
    pf.space_after = Pt(3)
    return p


def add_figure(doc, path, caption):
    if not os.path.exists(path):
        print("  !! missing figure:", path)
        return
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(6)
    run = p.add_run()
    run.add_picture(path, width=Cm(14.5))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_text(cap, caption, SONG, 10.5, bold=False, line15=False)
    cap.paragraph_format.space_after = Pt(6)


def main():
    src = os.path.join(HERE, "agent_cryptid_cn.md")
    out = os.path.join(HERE, "agent_cryptid_cn.docx")
    lines = open(src, encoding="utf-8").read().split("\n")
    doc = Document()
    # page setup A4
    sec = doc.sections[0]
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Cm(2.54)
    sec.bottom_margin = Cm(2.54)
    sec.left_margin = Cm(3.17)
    sec.right_margin = Cm(3.17)

    L1 = {"1": "一、", "2": "二、", "3": "三、", "4": "四、", "5": "五、", "6": "六、", "7": "七、"}
    L2 = {"1": "（一）", "2": "（二）", "3": "（三）", "4": "（四）", "5": "（五）"}
    in_meta = False
    in_abs = False
    in_refs = False
    l1idx = 0

    for line in lines:
        line = line.rstrip()
        if not line.strip():
            continue
        # title
        if line.startswith("# ") and not line.startswith("## "):
            t = line[2:].strip()
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            add_text(p, t, HEI, 16, bold=False, line15=False)
            p.paragraph_format.space_after = Pt(12)
            in_meta = True
            continue
        # metadata (作者/单位/邮箱/orcid/基金)
        if in_meta and line.startswith("**"):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            add_text(p, line, SONG, 10.5, bold=False, line15=False)
            continue
        if line.startswith("## 摘要"):
            in_meta = False
            in_abs = True
            p = doc.add_paragraph()
            add_text(p, "摘  要", HEI, 13, bold=False, line15=False)
            p.paragraph_format.space_before = Pt(6)
            continue
        if line.startswith("## 参考文献"):
            in_abs = False
            in_refs = True
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            add_text(p, "参考文献", HEI, 14, bold=False, line15=False)
            continue
        # L1 heading: ## N 标题  (must be checked before abstract block, resets in_abs)
        m1 = re.match(r'^##\s+(\d+)\s+(.+)$', line)
        if m1:
            in_abs = False
            l1idx = int(m1.group(1))
            add_heading(doc, m1.group(2), 1, L1.get(m1.group(1), ""))
            continue
        if in_abs:
            if line.startswith("**关键词**"):
                p = doc.add_paragraph()
                add_text(p, line, SONG, 10.5, bold=False, line15=False)
                p.paragraph_format.space_after = Pt(8)
            else:
                p = doc.add_paragraph()
                # bold 【摘要】 label
                if "**摘要**" in line:
                    add_text(p, line, SONG, 10.5, bold=False, line15=False)
                else:
                    add_text(p, line, SONG, 10.5, bold=False, line15=False)
                p.paragraph_format.space_after = Pt(4)
            continue
        if in_refs:
            if re.match(r'^\[\d+\]', line):
                p = doc.add_paragraph()
                add_text(p, line, SONG, 10.5, bold=False, line15=False)
                p.paragraph_format.space_after = Pt(2)
            continue
        # figure
        mfig = re.match(r'^!\[([^\]]*)\]\(([^)]*)\)', line)
        if mfig:
            add_figure(doc, os.path.join(HERE, mfig.group(2)), mfig.group(1))
            continue
        # L2 heading: ### N.M 标题
        m2 = re.match(r'^###\s+(\d+)\.(\d+)\s+(.+)$', line)
        if m2:
            add_heading(doc, m2.group(3), 2, L2.get(m2.group(2), ""))
            continue
        # body
        p = doc.add_paragraph()
        add_text(p, line, SONG, 12, bold=False, indent=True, line15=True)
        p.paragraph_format.space_after = Pt(3)

    doc.save(out)
    print("saved:", out)
    print("paragraphs:", len(doc.paragraphs))


if __name__ == "__main__":
    main()
