#!/usr/bin/env python3
"""UI 辅助：dump / find_agree / find_id / text
用法:
  doit.py dump <xml>            列出全部节点（id/class/clickable/bounds/文本）
  doit.py find_agree <xml>      找协议复选框（勾选框）的坐标
  doit.py find_id <xml> <片段>   按 id 片段找坐标
  doit.py text <xml>            列可见文本 + 控件 id
"""
import re
import sys

cmd = sys.argv[1] if len(sys.argv) > 1 else 'text'
path = sys.argv[2] if len(sys.argv) > 2 else '/tmp/u.xml'
key = sys.argv[3] if len(sys.argv) > 3 else 'tvQQ'

try:
    t = open(path, encoding='utf-8', errors='replace').read()
except Exception:
    sys.exit(0)

NODE = re.compile(r'<node[^>]*>')


def attrs(node):
    d = {}
    for k in ('text', 'resource-id', 'class', 'clickable', 'bounds', 'checkable', 'checked', 'content-desc'):
        m = re.search(r'%s="([^"]*)"' % k, node)
        d[k] = m.group(1) if m else ''
    return d


def center(b):
    m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', b or '')
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return ((x1 + x2) // 2, (y1 + y2) // 2)


if cmd == 'dump':
    for n in NODE.findall(t):
        a = attrs(n)
        if a['resource-id'] or a['text'] or a['class'].endswith(('CheckBox', 'ImageView', 'TextView', 'Button')):
            c = center(a['bounds'])
            print('%-40s %-28s clickable=%-5s checkable=%-5s %s %s' % (
                a['resource-id'].split('/')[-1][:40], a['class'].split('.')[-1][:28],
                a['clickable'], a['checkable'], c, a['text'][:30]))

elif cmd == 'find_agree':
    # 优先 checkable=true
    for n in NODE.findall(t):
        a = attrs(n)
        if a['checkable'] == 'true':
            c = center(a['bounds'])
            if c:
                print('%d %d' % c)
                sys.exit(0)
    # 再看文本含"我已阅读"的节点附近的小方框（宽度<120 的可点击节点）
    for n in NODE.findall(t):
        a = attrs(n)
        if '我已阅读' in a['text'] or '用户服务协议' in a['text']:
            c = center(a['bounds'])
            if c:
                # 勾选框通常在文本左侧，往左偏 60px
                print('%d %d' % (max(0, c[0] - 380), c[1]))
                sys.exit(0)

elif cmd == 'find_id':
    pat = r'resource-id="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(key)
    for m in re.finditer(pat, t):
        x1, y1, x2, y2 = map(int, m.groups())
        print('%d %d' % ((x1 + x2) // 2, (y1 + y2) // 2))
        sys.exit(0)

elif cmd == 'text':
    txts = [x for x in re.findall(r'text="([^"]{1,60})"', t) if x.strip()]
    ids = [x.split('/')[-1] for x in re.findall(r'resource-id="([^"]{4,70})"', t)]
    print('文本:', txts[:30])
    print('控件 id:', ids[:30])
