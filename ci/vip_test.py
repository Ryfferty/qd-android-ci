#!/usr/bin/env python3
"""vip_test.py —— 在 CI（不同出口 IP）下测 VIP 端点，判断 -429 是否 IP 级限流"""
import gzip
import json
import os
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.environ.get('GITHUB_WORKSPACE', '.'), 'ci'))
os.environ.setdefault('SESS', '/tmp/ci/sess.json')
os.environ.setdefault('DEV_ANDROID_ID', '7489ce4eb6aa591652700cf910001671a911')
import argus_fetch as A  # noqa: E402

print('账号: %s' % A.YW)


def api(path, params):
    url = A.HOST + path + '?' + urllib.parse.urlencode(params)
    h = {
        'User-Agent': 'Mozilla/mobile QDReaderAndroid/%s/%s/%s' % (A.APPVER, A.VC, A.ASRC),
        'Accept-Encoding': 'gzip',
        'Cookie': A.COOKIE,
        'QDInfo': A.qdinfo(A.YW),
        'tstamp': str(int(time.time() * 1000)),
        'QDSign': A.qdsign(A.canon(params), A.YW),
        'Referer': 'http://android.qidian.com',
    }
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=30)
        raw = r.read()
        if r.headers.get('Content-Encoding') == 'gzip':
            raw = gzip.decompress(raw)
        try:
            return json.loads(raw)
        except Exception:
            return {'_bin': len(raw), '_head': raw[:32].hex()}
    except Exception as e:
        return {'error': str(e)}


print('=== ① 登录态判据 ===')
j = api('/argus/api/v2/subscription/getunboughtchapterlist', {'bookId': '1049898328'})
print('  %s' % json.dumps(j, ensure_ascii=False)[:180])
time.sleep(3)

print('=== ② getvipcontent（VIP 章）===')
for book, chap, lbl in [('1049462635', '923399275', '《大汉棋圣》VIP章'),
                        ('1049898328', '929343527', '《请勿高考时渡劫》VIP章')]:
    j = api('/argus/api/v2/bookcontent/getvipcontent', {'bookId': book, 'chapterId': chap})
    if '_bin' in j:
        print('  [%s] ★ 二进制 %dB head=%s' % (lbl, j['_bin'], j['_head']))
    else:
        d = j.get('Data')
        c = (d.get('Content') or '') if isinstance(d, dict) else ''
        print('  [%s] Result=%s %s' % (
            lbl, j.get('Result'),
            ('★ %d 字符: %s' % (len(c), c[:90])) if c else (j.get('Message') or j.get('error', ''))[:45]))
    time.sleep(10)

print('=== ③ safegetcontent（App 主路径）===')
j = api('/argus/api/v2/bookcontent/safegetcontent', {'bookId': '1049462635', 'chapterId': '923399275'})
if '_bin' in j:
    print('  ★ 二进制容器 %dB head=%s' % (j['_bin'], j['_head']))
else:
    print('  Result=%s %s' % (j.get('Result'), (j.get('Message') or j.get('error', ''))[:50]))

print('=== ④ getcontent（对照：免费章）===')
j = api('/argus/api/v1/bookcontent/getcontent', {'bookId': '1049120379', 'chapterId': '903350205'})
d = j.get('Data') or {}
c = (d.get('Content') or '') if isinstance(d, dict) else ''
print('  Result=%s %s' % (j.get('Result'), ('★ 明文 %d 字符' % len(c)) if c else '（无内容）'))
