#!/usr/bin/env python3
import json
try:
    d = json.load(open('/tmp/params.json'))
    print(' Key len=%d head=%s' % (len(d.get('Key','')), d.get('Key','')[:40]))
    print(' Version=%s' % d.get('Version'))
    print(' blob_b64 len=%d' % len(d.get('blob_b64','')))
    print(' chapter_id=%s' % d.get('chapter_id'))
except Exception as e:
    print('读 params 失败:', e)
