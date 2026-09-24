#!/usr/bin/env python3
# anon_payload.py — 同轮: anon getkey+getcontentbatch → fock_unlock 解 URL → 下载 zip → 提取 .qd payload
# 输出 params json: {userKey, book, cid, dk, md5, batch_key, nP, payload_b64}  (runner 本地全做完, 设备只当解密引擎)
import sys, os, json, base64, struct, urllib.request, zipfile, io, hashlib
_here = os.path.dirname(os.path.abspath(__file__))          # .../qidian_auto/ci
sys.path.insert(0, os.path.dirname(_here))                   # qidian_auto (fock_unlock)
sys.path.insert(1, _here)                                    # ci (argus_fetch)
os.environ['SESS'] = ''
import warnings; warnings.filterwarnings('ignore')

book = sys.argv[1] if len(sys.argv) > 1 else '1049120379'
cid = sys.argv[2] if len(sys.argv) > 2 else '903350205'
out = sys.argv[3] if len(sys.argv) > 3 else '/tmp/v16_params.json'

from fock_unlock import decrypt_blob
import argus_fetch as af  # SESS='' → 匿名; 用其 DEV_* 身份

raw = af.aget('/argus/api/v3/bookcontent/getkey', {'bookId': book}, 'getkey')
dd0 = json.loads(raw).get('Data') or {}
j = af.getcontentbatch(book, cid, None)
d = j.get('Data') or {}
blob = d.get('DownloadUrl') or ''
if not blob:
    print('NO blob:', json.dumps(j, ensure_ascii=False)[:200]); sys.exit(2)

dk, url, fin = decrypt_blob(blob, af.IMEI, book)
url = url.rstrip('\x00').strip()
print('URL ok=%s len=%d' % (url.startswith('https://'), len(url)), flush=True)
if not url.startswith('https://'):
    print('URL 解析失败 head=', fin[:40]); sys.exit(3)

data = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}), timeout=60).read()
z = zipfile.ZipFile(io.BytesIO(data))
name = [n for n in z.namelist() if n.endswith('.qd')][0]
qd = z.read(name)
nP = struct.unpack('<I', qd[4:8])[0]
payload = qd[8:8+nP]
print('zip=%dB .qd=%d payload=%d trailer=%s' % (len(data), len(qd), nP, qd[8+nP:].hex()), flush=True)

params = {
    'userKey': af.IMEI, 'book': book, 'cid': cid,
    'dk': dk.hex(), 'md5': d.get('Md5') or '', 'batch_key': d.get('Key') or '',
    'keypool_b64': dd0.get('Key') or '', 'Version': str(dd0.get('Version') or ''),
    'blob_b64': durl,
    'nP': int(nP), 'payload_b64': base64.b64encode(payload).decode(),
    'trailer_hex': qd[8+nP:].hex(), 'qd_name': name,
}
json.dump(params, open(out, 'w'))
print('saved', out, flush=True)
