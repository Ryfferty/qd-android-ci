#!/usr/bin/env python3
import zipfile, shutil, os
apk = 'q464.apk'
z = zipfile.ZipFile(apk)
names = [n for n in z.namelist() if '/arm64-v8a/' in n and ('libfock' in n or 'libnib' in n or 'libknobs' in n)]
print('抽出的库:', names)
for n in names:
    dst = '/tmp/' + n.split('/')[-1]
    open(dst, 'wb').write(z.read(n))
    print('  ->', dst, os.path.getsize(dst), 'B')
if os.path.exists('/tmp/libfock.so'):
    shutil.copy('/tmp/libfock.so', 'libfock.so')
    print('已就位 libfock.so')
