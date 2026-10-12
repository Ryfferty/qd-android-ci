#!/usr/bin/env python3
# borgus_replay.py — getconf 重放器(已验证 200/Result=0)
# 用法: python3 borgus_replay.py [borgus_hex] [ts_ms]
#   无参数: fresh ts, 无 borgus(也能过)
#   带参数: 指定 borgus 与 tstamp(需与 borgus 生成时的 ts 一致才是"真"对)
# 关键构造: POST + query(?localLabels=&gender=0) + body, QDSign 的 md5 字段 = md5(canon(query))
# 2026-10-13 实测: 无borgus/垃圾borgus/过期borgus 全部 200 Result=0(本机IP)
import sys, json, hashlib, base64, time, urllib.request, urllib.parse, urllib.error, gzip
from Crypto.Cipher import DES3

APPVER, VC, ASRC = '7.9.464', '1906', '1000009'
HOST = 'https://bravev6.if.qidian.com'
IMEI = 'b18c7a7f5d584fe'          # det3 run 设备(可改)
Q, MODEL = 'b3b295be58644158', 'redroid11_arm64'
B64 = lambda b: base64.b64encode(b).decode()

def enc3(d, k, iv):
    p = 8 - len(d) % 8 or 8
    return DES3.new(k, DES3.MODE_CBC, iv).encrypt(d + bytes([p]) * p)

def canon(p):
    return '&'.join('%s=%s' % (k, v) for k, v in sorted((k.lower(), v) for k, v in p.items()))

def call(borgus=None, ts=None, params=None):
    params = params or {'localLabels': '', 'gender': '0'}
    ts = ts or str(int(time.time() * 1000))
    f = [IMEI, APPVER, '720', '1112', ASRC, '14', '1', MODEL, VC, ASRC, '4', '0', ts, '1', Q, '', '', '', '0']
    qi = B64(enc3('|'.join(f).encode(), b'0821CAAD409B8402' + b'0821CAAD409B8402'[:8], b'\x00' * 8))
    m = hashlib.md5(canon(params).encode()).hexdigest()
    pl = '|'.join(['Rv1rPTnczce', ts, '0', IMEI, '1', APPVER, '0', m, 'f189adc92b816b3e9da29ea304d4a7e4'])
    qs = B64(enc3(pl.encode(), bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68'), b'01234567'))
    h = {'User-Agent': 'Mozilla/mobile QDReaderAndroid/%s/%s/%s' % (APPVER, VC, ASRC),
         'Accept-Encoding': 'gzip',
         'Cookie': 'QDInfo=%s; ywkey=; ywguid=; appId=12; areaId=30; lang=cn; mode=normal; bar=36; qid=; qidth=; ' % qi,
         'QDInfo': qi, 'tstamp': ts, 'QDSign': qs, 'Referer': 'http://android.qidian.com'}
    if borgus:
        h['borgus'] = borgus
    url = HOST + '/argus/api/v1/client/getconf?' + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, data='localLabels=&gender=0'.encode(), headers=h, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=30)
        raw = r.read()
        try: raw = gzip.decompress(raw)
        except Exception: pass
        j = json.loads(raw)
        return r.status, j.get('Result'), j.get('Data', {}).get('Freshman', {})
    except urllib.error.HTTPError as e:
        b = e.read()
        try: b = gzip.decompress(b)
        except Exception: pass
        try: return e.code, json.loads(b).get('Result'), b[:120]
        except Exception: return e.code, b[:120], b''
    except Exception as e:
        return -1, str(e)[:120], b''

if __name__ == '__main__':
    bo = sys.argv[1] if len(sys.argv) > 1 else None
    ts = sys.argv[2] if len(sys.argv) > 2 else None
    st, res, extra = call(bo, ts)
    print('HTTP %s Result=%s' % (st, res))
    if isinstance(extra, dict) and extra:
        print('Freshman:', json.dumps(extra)[:200])
