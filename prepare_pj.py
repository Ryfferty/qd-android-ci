#!/usr/bin/env python3
# prepare_pj.py — 把协议取到的 params 整理成设备端可用的 params.json（补 chapter_id）
import json
d = json.load(open('/tmp/params.json'))
d['chapter_id'] = '903350205'
d['book_id'] = '1049120379'
json.dump(d, open('/tmp/pj.json','w'))
print('准备推送 params: Key len=%d blob len=%d chapter=%s' % (
    len(d.get('Key','')), len(d.get('blob_b64','')), d['chapter_id']))
