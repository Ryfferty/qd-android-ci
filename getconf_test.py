#!/usr/bin/env python3
"""getconf_test.py — 用getH的borgus + 自算QDSign调getconf"""
import json, hashlib, base64, re, sys, os
import urllib.request, urllib.parse, urllib.error, gzip

# 读取frida输出!
log_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/geth_output.log'
log = open(log_path).read()

# 提取borgus/QDInfo/tstamp!
# 优先用PAIR0(多组调用的第一个)!
pair0 = None
for line in log.split('\n'):
    if line.startswith('[PAIR0]'):
        if 'borgus=' in line:
            pair0 = line
            break

if pair0:
    BORGUS = re.search(r'borgus=([a-f0-9]{32})', pair0).group(1)
    # QDInfo取最后一个(独立版本,不是Cookie里的)!
    qdinfos = re.findall(r'QDInfo=([^;\s]+)', pair0)
    QDINFO = qdinfos[-1] if qdinfos else qdinfos[0]
    TS = re.search(r'tstamp=(\d+)', pair0).group(1)
else:
    # 退而求其次: 第一个getH结果!
    BORGUS = re.search(r'borgus=([a-f0-9]{32})', log).group(1)
    qdinfos = re.findall(r'QDInfo=([^;\s]+)', log)
    QDINFO = qdinfos[-1] if qdinfos else None
    TS = re.search(r'tstamp=(\d+)', log).group(1)

print(f"BORGUS: {BORGUS}")
print(f"TSTAMP: {TS}")
print(f"QDINFO: {QDINFO[:50] if QDINFO else 'NONE'}...")

# 计算QDSign(已知算法)!
body = 'localLabels=&gender=0'
md5_body = hashlib.md5(body.encode()).hexdigest()

try:
    from Crypto.Cipher import DES3
    plain = f'Rv1rPTnczce|{TS}|0|||1|7.9.464|1|{md5_body}|f189adc92b816b3e9da29ea304d4a7e4'
    key = b'sewxf03hhz3ew9qcCXMHiDMk'
    iv = b'sh331nt1'
    pad = 8 - len(plain) % 8
    if pad == 0: pad = 8
    plain_padded = plain.encode() + bytes([pad]) * pad
    enc = DES3.new(key, DES3.MODE_CBC, iv).encrypt(plain_padded)
    qdsign = base64.b64encode(enc).decode()
    print(f"QDSign(computed): {qdsign[:30]}...")
except Exception as e:
    print(f"QDSign error: {e}")
    qdsign = None

# 发请求!
headers = {
    'User-Agent': 'Mozilla/mobile QDReaderAndroid/7.9.464/1906/1000009/redroid/getTabHeight_68',
    'Cookie': f'QDInfo={QDINFO}; ywkey=; ywguid=; appId=12; areaId=30; lang=cn; mode=normal; bar=36; qid=; qidth=; ',
    'QDInfo': QDINFO,
    'tstamp': TS,
    'cecelia': '',
    'borgus': BORGUS,
    'Content-Type': 'application/x-www-form-urlencoded',
    'Referer': 'http://android.qidian.com',
    'Accept-Encoding': 'gzip',
}
if qdsign:
    headers['QDSign'] = qdsign

url = 'https://bravev6.if.qidian.com/argus/api/v1/client/getconf?localLabels=&gender=0'

print(f"\n--- Calling getconf ---")
try:
    req = urllib.request.Request(url, data=body.encode(), headers=headers, method='POST')
    r = urllib.request.urlopen(req, timeout=30)
    raw = r.read()
    try: raw = gzip.decompress(raw)
    except: pass
    resp = raw.decode('utf-8', errors='replace')
    print(f"HTTP: {r.status}")
    print(f"★★★ RESPONSE: {resp[:500]}")
    
    # 解析FreshmanBean!
    try:
        j = json.loads(resp)
        print(f"\nResult: {j.get('Result')}")
        d = j.get('Data', {})
        fm = d.get('Freshman', {})
        if fm:
            print(f"\n★ FreshmanBean:")
            print(f"  IsFreshman = {fm.get('IsFreshman')}")
            print(f"  IsNewDevice = {fm.get('IsNewDevice')}")
            print(f"  ShowLimitFreePopup = {fm.get('ShowLimitFreePopup')}")
            print(f"  Source = {fm.get('Source')}")
        print(f"\nIsFreshmanLimitFree: {d.get('IsFreshmanLimitFree')}")
    except:
        pass
except urllib.error.HTTPError as e:
    body2 = e.read()
    try: body2 = gzip.decompress(body2)
    except: pass
    print(f"HTTP Error {e.code}: {body2.decode('utf-8', errors='replace')[:300]}")
except Exception as e:
    print(f"Error: {e}")
