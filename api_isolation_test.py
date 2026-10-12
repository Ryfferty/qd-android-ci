#!/usr/bin/env python3
"""api_isolation_test.py — 隔离测试: 有borgus vs 无borgus"""
import json, re, hashlib, base64, urllib.request, urllib.parse, urllib.error, gzip, time, sys
from Crypto.Cipher import DES3

log_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/borgus_output.log'
log = open(log_path).read()
m = re.search(r'\[BORGUS_DATA\] (\{.*\})', log)
if not m:
    print("NO_BORGUS_DATA")
    sys.exit(1)

data = json.loads(m.group(1))
borgus = data.get('borgus', '')
print(f"BORGUS: {borgus}")

# 原来成功的参数!
IMEI = '8acb7b94f48245c'
ts = str(int(time.time() * 1000))

# QDSign!
body = 'localLabels=&gender=0'
# ★ 正确的canon: 排序+小写!
query_canon = 'gender=0&locallabels='
md5_body = hashlib.md5(query_canon.encode()).hexdigest()
plain = f'Rv1rPTnczce|{ts}|0||1|7.9.480|1|{md5_body}|f189adc92b816b3e9da29ea304d4a7e4'
key = b'sewxf03hhz3ew9qcCXMHiDMk'
iv = b'sh331nt1'
pad = 8 - len(plain) % 8
if pad == 0: pad = 8
plain_padded = plain.encode() + bytes([pad]) * pad
enc = DES3.new(key, DES3.MODE_CBC, iv).encrypt(plain_padded)
qdsign = base64.b64encode(enc).decode()

# QDInfo!
def make_qdinfo():
    fields = [IMEI, '7.9.480', '720', '1184', '10000431', '12', '1', 'OnePlus_PKR110', '1956', '10000431', '4', '0', ts, '1', '', '', '', '', '0']
    plain_s = '|'.join(fields)
    pad_n = 8 - len(plain_s) % 8
    if pad_n == 0: pad_n = 8
    padded = plain_s.encode() + bytes([pad_n]) * pad_n
    key3 = bytes.fromhex('0821CAAD409B8402')
    iv3 = b'\x00' * 8
    from Crypto.Cipher import DES
    try:
        encrypted = DES3.new(key3 * 3, DES3.MODE_CBC, iv3).encrypt(padded)
    except ValueError:
        # 退化key → 用单DES!
        encrypted = DES.new(key3, DES.MODE_CBC, iv3).encrypt(padded)
    return base64.b64encode(encrypted).decode()

qdinfo = make_qdinfo()

headers = {
    'User-Agent': 'Mozilla/mobile QDReaderAndroid/7.9.480/1956/10000431/OnePlus',
    'Cookie': f'QDInfo={qdinfo}; ywkey=; ywguid=; appId=12; areaId=30; lang=cn; mode=normal; bar=36; qid=; qidth=; ',
    'QDInfo': qdinfo,
    'tstamp': ts,
    'QDSign': qdsign,
    'Referer': 'http://android.qidian.com',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept-Encoding': 'gzip',
}

url = 'https://bravev6.if.qidian.com/argus/api/v1/client/getconf?gender=0&locallabels='

def call_api(h, label):
    print(f"\n--- {label} ---")
    try:
        req = urllib.request.Request(url, data=body.encode(), headers=h, method='POST')
        r = urllib.request.urlopen(req, timeout=30)
        raw = r.read()
        try: raw = gzip.decompress(raw)
        except: pass
        resp = raw.decode('utf-8', errors='replace')
        j = json.loads(resp)
        print(f"Result: {j.get('Result')}")
        d = j.get('Data', {})
        fm = d.get('Freshman', {})
        if fm:
            print(f"  IsFreshman = {fm.get('IsFreshman')}")
            print(f"  ShowLimitFreePopup = {fm.get('ShowLimitFreePopup')}")
            print(f"  Source = {fm.get('Source')}")
        return j
    except urllib.error.HTTPError as e:
        b = e.read()
        try: b = gzip.decompress(b)
        except: pass
        print(f"HTTP {e.code}: {b.decode('utf-8', errors='replace')[:200]}")
    except Exception as e:
        print(f"Error: {e}")
    return None

# Test 1: 无borgus(原来能成功)
r1 = call_api(headers, "Test 1: WITHOUT borgus (original)")

# Test 2: 有borgus
headers2 = dict(headers)
headers2['borgus'] = borgus
r2 = call_api(headers2, "Test 2: WITH borgus")

# Test 3: 有borgus + getH的QDInfo
headers3 = dict(headers)
headers3['borgus'] = borgus
headers3['QDInfo'] = data.get('QDInfo', qdinfo)
headers3['Cookie'] = data.get('Cookie', headers['Cookie'])
headers3['tstamp'] = data.get('tstamp', ts)
headers3['User-Agent'] = data.get('User-Agent', headers['User-Agent'])
r3 = call_api(headers3, "Test 3: borgus + getH QDInfo/UA/TS")

# Test 4: 只用borgus(其他都是自己的)
headers4 = dict(headers)
headers4['borgus'] = borgus
r4 = call_api(headers4, "Test 4: only borgus added")

print("\n=== 总结 ===")
for i, r in enumerate([r1, r2, r3, r4], 1):
    if r:
        print(f"Test {i}: Result={r.get('Result')}")
    else:
        print(f"Test {i}: FAILED")
