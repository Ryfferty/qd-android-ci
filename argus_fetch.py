#!/usr/bin/env python3
# argus_fetch.py — 只用 argus（App 协议）拿解密三要素：Key / Version / 密文
# 零网页请求。环境变量 BOOK / CID 指定书目与章节。
import json, base64, hashlib, time, urllib.request, urllib.parse, gzip, os
from Crypto.Cipher import DES3

try:
    S = json.load(open(os.environ.get('SESS','/tmp/sess.json')))
except Exception:
    S = {}
YW = S.get('ywguid') or '0'
COOKIE = '; '.join('%s=%s' % (k, v) for k, v in S.items())
APPVER, VC, ASRC = '7.9.472', '1956', '1000009'
HOST = 'https://bravev6.if.qidian.com'
# ★ 设备身份：优先用环境变量（= 模拟器里 App 的真实身份），保证密文与 App 的密钥同源
IMEI  = os.environ.get('DEV_IMEI')       or '5a271be5da434be'
Q     = os.environ.get('DEV_ANDROID_ID') or 'b3b295be58644158'
MODEL = os.environ.get('DEV_MODEL')      or 'V2329A'
DEVICEID = os.environ.get('DEV_DEVICEID') or ''
P_VAL = os.environ.get('DEV_P') or '1'
print('设备身份 DEV: IMEI=%s Q=%s MODEL=%s' % (IMEI, Q, MODEL))


def enc(d, k, iv):
    p = 8 - len(d) % 8 or 8
    return DES3.new(k, DES3.MODE_CBC, iv).encrypt(d + bytes([p]) * p)


B64 = lambda b: base64.b64encode(b).decode()


MODE = os.environ.get('DEV_QDINFO_MODE') or 'legacy'


def qdinfo(u='0'):
    ts = str(int(time.time() * 1000))
    if MODE == 'app':
        # ★ 按 App 的 15 字段结构（com.qidian.common.lib.d.U）
        #   d() | judian | k | l | R | m | P | n | cihai | search.r | this.d | d0() | ts | c | qimei
        f = [IMEI, '', '720', '1184', ASRC, '', P_VAL, MODEL, VC, ASRC, DEVICEID or '', u, ts, '1', Q]
    else:
        f = [IMEI, APPVER, '720', '1184', ASRC, '14', '1', MODEL, VC, ASRC, DEVICEID or '4', u, ts, '1', Q, '', '', '', '0']
    k = b'0821CAAD409B8402'
    return B64(enc('|'.join(f).encode(), k + k[:8], b'\x00' * 8))


def qdsign(si, u='0'):
    ts = str(int(time.time() * 1000))
    pl = '|'.join(['Rv1rPTnczce', ts, '0', IMEI, '1', APPVER, '0',
                   hashlib.md5(si.encode()).hexdigest(), 'f189adc92b816b3e9da29ea304d4a7e4'])
    return B64(enc(pl.encode(), bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68'), b'01234567'))


def canon(p):
    return '&'.join('%s=%s' % (k, v) for k, v in sorted((k.lower(), v) for k, v in p.items()))


def aget(path, params, lbl, save=None):
    h = {'User-Agent': 'Mozilla/mobile QDReaderAndroid/%s/%s/%s' % (APPVER, VC, ASRC),
         'Accept-Encoding': 'gzip', 'Cookie': COOKIE, 'QDInfo': qdinfo(YW),
         'tstamp': str(int(time.time() * 1000)), 'QDSign': qdsign(canon(params), YW),
         'Referer': 'http://android.qidian.com'}
    url = HOST + path + '?' + urllib.parse.urlencode(params)
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=30)
        raw, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    except Exception as e:
        print('[%s] EXC %s' % (lbl, str(e)[:110]))
        return None
    try:
        raw = gzip.decompress(raw)
    except Exception:
        pass
    print('[%s] %s %dB %s' % (lbl, code, len(raw), raw[:110]))
    if save and code == 200 and not raw.startswith(b'{'):
        open(save, 'wb').write(raw)
        print('   saved %s (%dB)' % (save, len(raw)))
    return raw


BOOK = os.environ.get('BOOK', '1040025277')
CID = os.environ.get('CID', '794290414')
out = {}

raw = aget('/argus/api/v3/bookcontent/getkey', {'bookId': BOOK}, 'getkey')
if raw and raw.startswith(b'{'):
    try:
        dd = json.loads(raw).get('Data') or {}
        out['Key'] = dd.get('Key'); out['V'] = dd.get('V'); out['Version'] = dd.get('Version')
        print('   Key len=%s V=%s Version=%s' % (len(out.get('Key') or ''), out.get('V'), out.get('Version')))
    except Exception as e:
        print('   parse fail', e)

time.sleep(3)
raw = aget('/argus/api/v3/bookcontent/getkey', {'bookId': BOOK, 'ui': '1'}, 'getkey ui=1')
if raw and raw.startswith(b'{'):
    try:
        dd = json.loads(raw).get('Data') or {}
        if dd.get('Key'):
            out['key_ui1'] = dd['Key']
            print('   key_ui1 len=%s head=%s' % (len(dd['Key']), dd['Key'][:32]))
            if dd['Key'] != out.get('Key'):
                out['key_b'] = dd['Key']
                print('   （与 ui=0 不同 ✓）')
            else:
                print('   （与 ui=0 相同）')
    except Exception:
        pass

time.sleep(3)
raw = aget('/argus/api/v2/bookcontent/safegetcontent', {'bookId': BOOK, 'chapterId': CID},
           'safegetcontent', '/tmp/cipher.bin')
if raw and not raw.startswith(b'{'):
    out['blob_b64'] = base64.b64encode(raw).decode()

out.setdefault('qimei16', Q)
out['ywguid'] = YW
out['ywkey'] = S.get('ywkey') or ''
out['ywopenid'] = S.get('ywopenid') or ''
json.dump(out, open('/tmp/params.json', 'w'))
print('params keys=%s' % list(out.keys()))
for k in ('Key', 'key_b', 'blob_b64'):
    if out.get(k):
        print('   %s len=%d head=%s' % (k, len(out[k]), out[k][:40]))

def getcontentbatch(book, cids, save=None):
    """POST /argus/newapi/v1/bookcontent/getcontentbatch → DownloadUrl+Key+Md5"""
    body = 'b=%s&c=%s&useImei=1' % (book, cids)
    params = {'b': str(book), 'c': str(cids), 'useImei': '1'}
    h = {'User-Agent': 'Mozilla/mobile QDReaderAndroid/%s/%s/%s' % (APPVER, VC, ASRC),
         'Accept-Encoding': 'gzip', 'Cookie': COOKIE, 'QDInfo': qdinfo(YW),
         'Content-Type': 'application/x-www-form-urlencoded',
         'tstamp': str(int(time.time() * 1000)), 'QDSign': qdsign(canon(params), YW),
         'Referer': 'http://android.qidian.com'}
    import urllib.request as ur
    req = ur.Request(HOST + '/argus/newapi/v1/bookcontent/getcontentbatch', data=body.encode(),
                     headers=h)
    with ur.urlopen(req, timeout=30) as r:
        raw = r.read()
        if r.headers.get('Content-Encoding') == 'gzip':
            import gzip; raw = gzip.decompress(raw)
    j = json.loads(raw)
    if save:
        open(save, 'wb').write(raw)
    return j

if __name__ == '__main__':
    import sys
    j = getcontentbatch(sys.argv[1], sys.argv[2], '/tmp/batch_resp.json')
    d = j.get('Data') or {}
    print('Result=%s' % j.get('Result'))
    print('DownloadChapters=%s' % json.dumps(d.get('DownloadChapters'))[:200])
    print('DownloadUrl len=%s' % len(d.get('DownloadUrl') or ''))
    print('Key=%s' % (d.get('Key') or '')[:80])
    print('Md5=%s' % (d.get('Md5') or ''))
    import base64
    try:
        rawb = base64.b64decode(d.get('DownloadUrl') or '')
        print('DownloadUrl b64解码=%dB head=%s' % (len(rawb), rawb[:16].hex()))
        open('/tmp/durl.bin','wb').write(rawb)
    except Exception as e:
        print('b64 err', e)
