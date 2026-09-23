#!/usr/bin/env python3
# anon_pair.py — 匿名(无登录)同轮抓 (Key, Version, blob) for 免费章; 供 v4 矩阵用
# 用法: python3 anon_pair.py <bookId> <chapterId> <out.json>
import sys, os, json, base64, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ['SESS'] = ''  # 强制匿名
import argus_fetch as af

book = sys.argv[1] if len(sys.argv) > 1 else '1049120379'
cid = sys.argv[2] if len(sys.argv) > 2 else '903350205'
out = sys.argv[3] if len(sys.argv) > 3 else '/tmp/anon_pair.json'

raw = af.aget('/argus/api/v3/bookcontent/getkey', {'bookId': book}, 'getkey')
try:
    dd = json.loads(raw).get('Data') or {}
except Exception:
    print('getkey NON-JSON:', raw[:200]); sys.exit(1)
key_b64 = dd.get('Key'); version = dd.get('Version')
print('KEY len=%s VER=%s' % (len(key_b64 or ''), version), flush=True)

time.sleep(1)
j = af.getcontentbatch(book, cid, '/tmp/anon_batch.json')
d = j.get('Data') or {}
durl = d.get('DownloadUrl') or ''
print('Result=%s durl_len=%d' % (j.get('Result'), len(durl)), flush=True)
if not durl:
    print('NO blob:', json.dumps(j, ensure_ascii=False)[:300]); sys.exit(2)

params = {
    'Key': key_b64, 'Version': str(version), 'blob_b64': durl,
    'userKey': af.IMEI,
    'addks': [
        [cid, book + '_' + cid],   # n0.search 形态: (str2, str3)
        [book + '_' + cid, ''],
        [book, book + '_' + cid],
        ['', ''],
        ['BatchChapterCos_' + book + '_' + cid, ''],
        [cid, ''],
        [book, ''],
    ],
}
json.dump(params, open(out, 'w'))
print('saved %s blob=%dB' % (out, len(base64.b64decode(durl))))
