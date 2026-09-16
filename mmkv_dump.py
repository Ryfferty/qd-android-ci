#!/usr/bin/env python3
# mmkv_dump.py — 分析 App 的 MMKV 文件，找出 pref_fock_key 的真实存储格式
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/pref_utils.bin'
try:
    d = open(path, 'rb').read()
except Exception as e:
    print('读取失败 %s: %s' % (path, e))
    raise SystemExit

print('文件大小: %d' % len(d))
i = d.find(b'pref_fock_key')
print('pref_fock_key 偏移 = %d' % i)

if i >= 0:
    seg = d[i:i + 800]
    print('--- 可打印片段 ---')
    for m in re.finditer(rb'[\x20-\x7e]{6,}', seg):
        print('  @%d: %s' % (m.start(), m.group().decode('ascii', 'replace')[:300]))
    print('--- 原始 hex 前 192 字节 ---')
    print('  ' + seg[:192].hex())

print('--- 全文里的 JSON 片段 ---')
for m in re.finditer(rb'\{[^{}]{0,400}\}', d):
    txt = m.group().decode('utf-8', 'replace')
    print('  JSON@%d: %s' % (m.start(), txt[:300]))

print('--- 以 { 开头的长片段（可能是 map）---')
for m in re.finditer(rb'\{[\x20-\x7e]{20,600}\}', d):
    txt = m.group().decode('utf-8', 'replace')
    if ':' in txt:
        print('  MAP@%d: %s' % (m.start(), txt[:400]))
