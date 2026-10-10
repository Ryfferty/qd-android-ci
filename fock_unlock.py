#!/usr/bin/env python3
# fock_unlock.py — 起点 DownloadUrl 容器 纯协议解密 (2026-09-25 全链闭合版)
# 链: getkey + getcontentbatch(blob) → head AES-256-CBC(hk) → ivar3/ivar4
#     → 固定ASCII池 sel16 → dk=SHA256(sel16+userKey+bookId) → DES-CBC → GCM-CTR → COS直链 → zip正文
# 用法: python3 fock_unlock.py <bookId> <chapterId> [out.txt]
import sys, os, json, base64, hashlib, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'ci'))
os.environ['SESS'] = ''   # 匿名
import argus_fetch as af
from Crypto.Cipher import AES, DES

POOL = b'867f3f8c52916cba,b653750b67ca112a,bcfacdd59c862db0,a6b88e1324178bb6,89c99be68381f2f1'
SALT = "TAOO8ZUCX129QZU5"

def decrypt_blob(blob_b64, userKey, bookId):
    """v14 终结公式 (3 车真机现场对拍验证):
    head = AES-256-CBC(hk) 只取 blob[0:256];  DES-IN = head[128:256] + blob[256:] (后段原样透传!)
    dk   = SHA256(POOL[iv4*17:+16] + userKey + bookId)
    DES-CBC(dk[:8], iv=dk[:8]); pad∈[1,8] 合法则裁否则全长; GCM-CTR(iv=dk[:12], ctr=2 连续++)"""
    blob = base64.b64decode(blob_b64)
    hk = hashlib.sha256((userKey + SALT).encode()).digest()
    head = AES.new(hk, AES.MODE_CBC, hk[:16]).decrypt(blob[:256])
    def a(x):
        t = x.split(b'\x00')[0].strip()
        return int(t) if t else 0
    iv3, iv4 = a(head[:8]), a(head[8:16])
    if iv3 != 0x01de4727:
        print('!! ivar3=%s 非 0x1de4727 (未知版本分支)' % hex(iv3))
    sel = POOL[iv4*17: iv4*17+16]
    dk = hashlib.sha256(sel + userKey.encode() + str(bookId).encode()).digest()
    st1 = head[128:256] + blob[256:]
    s1 = DES.new(dk[:8], DES.MODE_CBC, dk[:8]).decrypt(st1)
    pad = s1[-1]
    s1u = s1[:-pad] if 1 <= pad <= 8 else s1
    ecb = AES.new(dk, AES.MODE_ECB)
    ks = b''.join(ecb.encrypt(dk[:12] + (2+i).to_bytes(4, 'big')) for i in range((len(s1u)+15)//16))
    fin = bytes(x ^ y for x, y in zip(s1u, ks))
    txt = fin.decode('latin1').split('\x00')[0]
    i = txt.find('http')
    url = txt[i:].strip() if i >= 0 else None
    return dk, url, fin

def main():
    book = sys.argv[1] if len(sys.argv) > 1 else '1049120379'
    cid  = sys.argv[2] if len(sys.argv) > 2 else '903350205'
    out  = sys.argv[3] if len(sys.argv) > 3 else '/tmp/unlock_out.txt'

    raw = af.aget('/argus/api/v3/bookcontent/getkey', {'bookId': book}, 'getkey')
    dd = json.loads(raw)['Data']
    print('Key=%s… Ver=%s' % ((dd.get('Key') or '')[:16], dd.get('Version')))

    j = af.getcontentbatch(book, cid, None)
    d = j.get('Data') or {}
    blob = d.get('DownloadUrl') or ''
    print('getcontentbatch Result=%s blob=%dB' % (j.get('Result'), len(blob)))
    if not blob:
        print('!! 无 DownloadUrl (无权限/非可读章)'); sys.exit(2)

    dk, url, fin = decrypt_blob(blob, af.IMEI, book)
    print('dk=%s' % dk.hex())
    if not url:
        print('解出失败 fin[:32]=%s' % fin[:32].hex()); sys.exit(3)
    print('URL=%s' % (url[:150] + ('…' if len(url) > 150 else '')))
    open(out, 'w').write(url)

    # 下载正文 zip
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception as e:
        print('下载失败: %s' % str(e)[:150]); sys.exit(4)
    zp = out.replace('.txt', '_body.zip')
    open(zp, 'wb').write(data)
    print('下载 %dB → %s' % (len(data), zp))
    print('magic=%s' % data[:8].hex())
    import zipfile, io
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        print('ZIP 内容(%d):' % len(names), names[:8])
        for n in names[:3]:
            b0 = z.read(n)
            print('--- %s (%dB):' % (n, len(b0)), b0[:180])
    except Exception as e:
        print('非标准zip:', e, '头48B:', data[:48])

if __name__ == '__main__':
    main()
