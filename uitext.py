#!/usr/bin/env python3
"""打印 uiautomator XML 里的可见文本与控件 id"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/u2.xml'
try:
    t = open(path, encoding='utf-8', errors='replace').read()
except Exception as e:
    print('读取失败', e)
    sys.exit(0)

txts = [x for x in re.findall(r'text="([^"]{1,60})"', t) if x.strip()]
print('文本:', txts[:30])
ids = re.findall(r'resource-id="com\.qidian\.QDReader:id/([^"]{2,44})"', t)
print('控件 id:', ids[:25])
print('XML 大小:', len(t))
