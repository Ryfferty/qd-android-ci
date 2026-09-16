#!/usr/bin/env python3
# merge_params.py — 给 params.json 补上 chapter_id / book_id
import json, sys

BOOK = sys.argv[1] if len(sys.argv) > 1 else '1049120379'
CID = sys.argv[2] if len(sys.argv) > 2 else '903350205'

p = json.load(open('/tmp/params.json'))
p['chapter_id'] = CID
p['book_id'] = BOOK
json.dump(p, open('/tmp/params.json', 'w'))
short = {}
for k, v in p.items():
    short[k] = (v[:40] + '...len=%d' % len(v)) if isinstance(v, str) and len(v) > 40 else v
print('params:', short)
