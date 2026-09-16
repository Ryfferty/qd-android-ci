#!/usr/bin/env python3
"""从 uiautomator XML 里找出「同意并继续」按钮的中心坐标，打印 "x y"。找不到则无输出。"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/u.xml'
try:
    t = open(path, encoding='utf-8', errors='replace').read()
except Exception:
    sys.exit(0)

# 只认两个精确目标（其余一律不点，避免误点）
# ① 精确 id：btnAgree
for m in re.finditer(r'resource-id="com\.qidian\.QDReader:id/btnAgree"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', t):
    x1, y1, x2, y2 = map(int, m.groups())
    print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
    sys.exit(0)

# ② 精确文本：同意并继续
for m in re.finditer(r'text="同意并继续"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', t):
    x1, y1, x2, y2 = map(int, m.groups())
    print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
    sys.exit(0)

# ★ 不再做"任意 clickable"兜底（会误点登录页的 × 关闭按钮，导致 App 退出）
