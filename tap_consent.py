#!/usr/bin/env python3
"""从 uiautomator XML 里找出「同意并继续」按钮的中心坐标，打印 "x y"。找不到则无输出。"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/u.xml'
try:
    t = open(path, encoding='utf-8', errors='replace').read()
except Exception:
    sys.exit(0)

# 优先按 resource-id
for rid in ('btnAgree', 'button_text_id', 'tvAgree', 'agree'):
    pat = r'resource-id="[^"]*%s"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % rid
    for m in re.finditer(pat, t):
        x1, y1, x2, y2 = map(int, m.groups())
        print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
        sys.exit(0)

# 兜底：按文本
for kw in ('同意并继续', '同意', '继续'):
    pat = r'text="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % kw
    for m in re.finditer(pat, t):
        x1, y1, x2, y2 = map(int, m.groups())
        print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
        sys.exit(0)

# ★ 不再做"任意 clickable"兜底（会误点登录页的 × 关闭按钮，导致 App 退出）
