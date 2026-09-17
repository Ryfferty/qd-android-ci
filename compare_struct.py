#!/usr/bin/env python3
"""compare_struct.py — 比较两份 params 的密文/Key 是否相同"""
import json, os
try:
    a = json.load(open('/tmp/params_legacy.json'))
    b = json.load(open('/tmp/params_app.json'))
    print('  legacy blob head:', (a.get('blob_b64') or '')[:48])
    print('  app    blob head:', (b.get('blob_b64') or '')[:48])
    print('  密文相同?', (a.get('blob_b64') or '')[:64] == (b.get('blob_b64') or '')[:64])
    print('  Key 相同?', a.get('Key') == b.get('Key'))
except Exception as e:
    print('  比较失败:', e)
