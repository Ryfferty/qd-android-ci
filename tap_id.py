#!/usr/bin/env python3
"""按控件 id 片段从 uiautomator XML 找中心坐标，输出 "x y"。用法: tap_id.py <xml> <id片段>"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/u.xml'
key = sys.argv[2] if len(sys.argv) > 2 else 'tvQQ'
try:
    t = open(path, encoding='utf-8', errors='replace').read()
except Exception:
    sys.exit(0)

pat = r'resource-id="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(key)
for m in re.finditer(pat, t):
    x1, y1, x2, y2 = map(int, m.groups())
    print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
    sys.exit(0)

# 若控件不可点击，尝试找它的父节点（clickable=true 的祖先不好回溯，改用同 bounds 附近的可点击项）
for m in re.finditer(r'clickable="true"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', t):
    x1, y1, x2, y2 = map(int, m.groups())
    print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
    break
