# -*- coding: utf-8 -*-
"""把标准 Markdown 表格预处理成 md2docx.py 约定格式：
1. 表格块首行前插入 TABLE:
2. 删除 |---| 分隔行
3. 删除表格内的空单元格导致的列数不一致（补齐由转换器负责）
"""
import sys, os, re

def preprocess(src, dst):
    with open(src, 'r', encoding='utf-8') as f:
        lines = f.read().split('\n')
    out = []
    i = 0
    n = len(lines)
    ntab = 0
    while i < n:
        s = lines[i].strip()
        # 识别表格起始：当前行以 | 开头，且上一行不是表格行
        is_table_row = s.startswith('|') and s.endswith('|') and len(s) > 2
        prev_is_table = bool(out) and out[-1].startswith('|')
        if is_table_row and not prev_is_table:
            # 找表格块结束
            j = i
            while j < n and lines[j].strip().startswith('|'):
                j += 1
            block = [l.strip() for l in lines[i:j] if l.strip().startswith('|')]
            # 去分隔行
            rows = [r for r in block if not re.match(r'^\|[\s:\-\|]+\|$', r)]
            if len(rows) >= 2:
                out.append('TABLE:')
                out.extend(rows)
                ntab += 1
            else:
                out.extend(block)
            i = j
            continue
        # 块引用转正文（去掉 > 前缀）
        if s.startswith('>'):
            body = s.lstrip('>').strip()
            if body.startswith('**') and body.endswith('**') and len(body) > 4:
                out.append('### ' + body[2:-2])
            elif body:
                out.append(body)
            i += 1
            continue
        # 水平分隔线丢弃
        if re.match(r'^-{3,}$', s):
            i += 1
            continue
        out.append(lines[i])
        i += 1
    with open(dst, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))
    return ntab

if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    t = preprocess(src, dst)
    print('tables=%d -> %s' % (t, dst))
