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

# ★ 直接用argus_fetch(已验证能成功)!
import sys
sys.path.insert(0, '.')
import argus_fetch as A
import time

ts = str(int(time.time() * 1000))
params = {'localLabels': '', 'gender': '0'}
canon = A.canon(params)
qdsign = A.qdsign(canon, A.YW)
qdinfo = A.qdinfo(A.YW)

body = 'localLabels=&gender=0'

headers = {
    'User-Agent': 'Mozilla/mobile QDReaderAndroid/%s/%s/%s' % (A.APPVER, A.VC, A.ASRC),
    'Accept-Encoding': 'gzip',
    'Cookie': A.COOKIE,
    'QDInfo': qdinfo,
    'tstamp': ts,
    'QDSign': qdsign,
    'Referer': 'http://android.qidian.com',
    'Content-Type': 'application/x-www-form-urlencoded',
}

url = A.HOST + '/argus/api/v1/client/getconf?' + canon

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
headers3['QDInfo'] = data.get('QDInfo', '')
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
