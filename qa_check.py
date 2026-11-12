# -*- coding: utf-8 -*-
# QA checker. ASCII-only source; reads the .md and writes a UTF-8 report.
import sys
import os
import re

CN_NUM = ["\u4e00", "\u4e8c", "\u4e09", "\u56db", "\u4e94", "\u516d",
          "\u4e03", "\u516b", "\u4e5d", "\u5341",
          "\u5341\u4e00", "\u5341\u4e8c", "\u5341\u4e09", "\u5341\u56db",
          "\u5341\u4e94", "\u5341\u516d", "\u5341\u4e03", "\u5341\u516b",
          "\u5341\u4e5d", "\u4e8c\u5341"]
# 一 二 三 四 五 六 七 八 九 十 十一 十二 十三 十四 十五 十六 十七 十八 十九 二十

ASCII_PUNCT = [",", ";", "!", "?", ":", "(", ")", "\""]

AI_WORDS = ["\u8d4b\u80fd", "\u6293\u624b", "\u6253\u9020", "\u95ed\u73af",
            "\u826f\u6027\u5faa\u73af", "\u751f\u6001\u5316", "\u5168\u94fe\u6761",
            "\u590d\u76d8", "\u503c\u5f97\u6ce8\u610f", "\u7efc\u4e0a\u6240\u8ff0",
            "\u603b\u800c\u8a00\u4e4b", "\u4e0d\u65ad\u4f18\u5316\u8fed\u4ee3",
            "\u6709\u6548\u843d\u5730", "\u6df1\u5ea6\u8d4b\u80fd"]
# 赋能 抓手 打造 闭环 良性循环 生态化 全链条 复盘 值得注意 综上所述 总而言之 不断优化迭代 有效落地 深度赋能


def main():
    src = sys.argv[1]
    with open(src, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")

    out = []
    issues = 0

    # 1. chapter numbering
    heads = [l.strip()[3:].strip() for l in lines if l.strip().startswith("## ")]
    expect = CN_NUM[:len(heads)]
    got_prefix = [h.split("\u3001")[0] for h in heads]
    if got_prefix == expect:
        out.append("[PASS] chapter numbering: %d chapters, sequential" % len(heads))
    else:
        issues += 1
        out.append("[FAIL] chapter numbering: got=%s expect=%s"
                   % (got_prefix, expect))

    # 2. ASCII punctuation in body text
    bad_punct = []
    for idx, l in enumerate(lines):
        s = l.strip()
        if s.startswith("CENTER:") or s.startswith("TABLE:") or s.startswith("|"):
            continue
        if s.startswith("BREAK") or s == "":
            continue
        for ch in ASCII_PUNCT:
            if ch in s:
                bad_punct.append((idx + 1, ch, s[:40]))
    if bad_punct:
        issues += len(bad_punct)
        for ln, ch, snip in bad_punct[:20]:
            out.append("[WARN] line %d ASCII punct '%s' -> %s" % (ln, ch, snip))
    else:
        out.append("[PASS] no ASCII punctuation in body text")

    # 3. quote pairing
    text = "\n".join(lines)
    lq = text.count("\u300c")
    rq = text.count("\u300d")
    lp = text.count("\uff08")
    rp = text.count("\uff09")
    if lq == rq and lp == rp:
        out.append("[PASS] brackets paired: %s=%s, %s=%s" % (lq, rq, lp, rp))
    else:
        issues += 1
        out.append("[FAIL] brackets unpaired: %s/%s, %s/%s" % (lq, rq, lp, rp))

    # 4. tables
    tbl_bad = []
    tbl_idx = 0
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("TABLE:"):
            tbl_idx += 1
            rows = []
            i += 1
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            widths = set(len(r) for r in rows)
            if len(widths) > 1:
                tbl_bad.append("table %d inconsistent cols %s" % (tbl_idx, sorted(widths)))
            empty = sum(1 for r in rows for c in r if c == "")
            if empty:
                tbl_bad.append("table %d has %d empty cells" % (tbl_idx, empty))
            continue
        i += 1
    if tbl_bad:
        issues += len(tbl_bad)
        for b in tbl_bad:
            out.append("[WARN] %s" % b)
    else:
        out.append("[PASS] tables consistent, no empty cells")

    # 5. AI-flavored wording
    hits = []
    for idx, l in enumerate(lines):
        s = l.strip()
        if s.startswith("CENTER:") or s.startswith("|"):
            continue
        for w in AI_WORDS:
            if w in s:
                hits.append((idx + 1, w, s[:40]))
    if hits:
        for ln, w, snip in hits:
            out.append("[INFO] AI-ish word line %d '%s' -> %s" % (ln, w, snip))
    else:
        out.append("[PASS] no AI-flavored wording")

    # 6. counts
    cn_chars = len(re.findall(r'[\u4e00-\u9fff]', text))
    out.append("[INFO] Chinese characters: %d" % cn_chars)
    out.append("[INFO] lines: %d" % len(lines))
    out.append("[RESULT] issues=%d" % issues)

    rep = "\n".join(out) + "\n"
    with open(os.path.join(os.path.dirname(os.path.abspath(src)), "_qa_report.txt"),
              "w", encoding="utf-8") as f:
        f.write(rep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
