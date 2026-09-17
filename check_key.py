#!/usr/bin/env python3
# check_key.py — 对照：协议拿到的 Key vs 设备 MMKV 里的 Key
import json, sys, re, os
def show_key(path):
    try:
        d = json.load(open(path))
        k = d.get('Key','')
        print('  %s → len=%d head=%s' % (path, len(k), k[:50]))
        return k
    except Exception as e:
        print('  读 %s 失败: %s' % (path, e)); return ''
ak = show_key('/tmp/params.json')
dev = ''
try:
    raw = open('/tmp/mmkv.bin','rb').read().decode('utf-8','ignore')
    m = re.search(r'\{"1639985422":"([A-Za-z0-9+/=]{40,})', raw)
    if m: dev = m.group(1); print('  设备 MMKV Key → len=%d head=%s' % (len(dev), dev[:50]))
    else: print('  设备 MMKV 里没找到 pref_fock_key（App 未成功请求密钥）')
except Exception as e:
    print('  读 mmkv.bin 失败:', e)
if ak and dev:
    print()
    print('★★ 对照结果：%s' % ('完全一致 ✅ —— 协议复刻成功！' if ak == dev else '不一致 ❌ —— 身份仍有差异'))
    if ak != dev:
        for i in range(min(len(ak), len(dev))):
            if ak[i] != dev[i]:
                print('   首个不同位置 %d: 协议=%s 设备=%s' % (i, ak[i], dev[i])); break
