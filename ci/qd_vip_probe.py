#!/usr/bin/env python3
# qd_vip_probe.py — 干净IP上首发 getvipcontent 真实判定 + 权限四读数
# 自包含, 只依赖 pycryptodome。用法: python3 qd_vip_probe.py
import json, base64, hashlib, time, urllib.request, urllib.parse, gzip
from Crypto.Cipher import DES3

YW='900074177981'; YWK='yw7YDyaQ56VT'
IMEI='457035494495022'; Q16='ac87c40987054ea7'
HOST='https://bravev6.if.qidian.com'
B='1049120379'; C='921135284'

def enc(d,k,iv):
    p=8-len(d)%8 or 8
    return DES3.new(k,DES3.MODE_CBC,iv).encrypt(d+bytes([p])*p)
B64=lambda b: base64.b64encode(b).decode()
def fire(path,params,note):
    canon='&'.join('%s=%s'%(a.lower(),v) for a,v in sorted(((a.lower(),x) for a,x in params.items())))
    ts=str(int(time.time()*1000))
    f=[IMEI,'7.9.472','720','1184','1000009','14','1','V2329A','1956','1000009','4',YW,ts,'1',Q16,'','','','0']
    k=b'0821CAAD409B8402'
    h={'User-Agent':'Mozilla/mobile QDReaderAndroid/7.9.472/1956/1000009','Accept-Encoding':'gzip',
       'Cookie':'ywguid=%s; ywkey=%s; appId=12; areaId=30'%(YW,YWK),
       'QDInfo':B64(enc('|'.join(f).encode(),k+k[:8],b'\x00'*8)),'tstamp':ts,
       'QDSign':B64(enc('|'.join(['Rv1rPTnczce',ts,YW,IMEI,'1','7.9.472','0',
         hashlib.md5(canon.encode()).hexdigest(),'f189adc92b816b3e9da29ea304d4a7e4']).encode(),
         bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68'),b'01234567')),
       'Referer':'http://android.qidian.com'}
    url=HOST+path+'?'+urllib.parse.urlencode(params)
    try:
        r=urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=25); raw=r.read(); code=r.status
    except urllib.error.HTTPError as e: raw=e.read(); code=e.code
    except Exception as e:
        print('[%s] EXC %s'%(note,str(e)[:100])); return None
    try: raw=gzip.decompress(raw)
    except: pass
    show=('★BIN%d head=%s'%(len(raw),raw[:24].hex())) if raw[:1]!=b'{' else raw[:170].decode('utf-8','replace')
    print('[%s] HTTP%s %s'%(note,code,show),flush=True)
    time.sleep(4)
    return raw

print('ip check:', urllib.request.urlopen('https://myip.ipip.net',timeout=10).read().decode()[:80])
fire('/argus/api/v2/bookcontent/getvipcontent',{'bookId':B,'chapterId':C},'★getvipcontent 首发判定')
fire('/argus/api/v2/bookcontent/safegetcontent',{'bookId':B,'chapterId':C},'safegetcontent 对照')
fire('/argus/api/v1/freshman/limitfreepopup',{},'limitfreepopup')
