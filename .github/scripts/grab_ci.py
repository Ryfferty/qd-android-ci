import json, re, os, sys, time, asyncio
from playwright.async_api import async_playwright

OUT = 'out'
UA = ('Mozilla/5.0 (Linux; Android 13; V2329A Build/TP1A.220624.014) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Version/4.0 Chrome/119.0.6045.66 Mobile Safari/537.36 QDReaderAndroid/7.9.472')

async def main():
    book = os.environ['BOOK_ID']
    ch_file = os.environ.get('CH_FILE', 'chapters.json')
    shard = int(os.environ.get('SHARD', '0'))
    shards = int(os.environ.get('SHARDS', '1'))
    tabs = int(os.environ.get('TABS', '4'))
    skip = int(os.environ.get('SKIP_TAIL', '0'))

    ck = json.load(open('cookies.json'))
    pcs = [{'name': c['name'], 'value': c['value'], 'domain': c.get('domain', ''),
            'path': c.get('path', '/'), 'secure': True, 'expires': -1,
            'httpOnly': False, 'sameSite': 'Lax'} for c in ck]

    D = json.load(open(ch_file))
    D = D.get('Data', D)
    name = D.get('BookName', book)
    chs = [c for c in D.get('Chapters', []) if c.get('V') == 1]
    usable = chs[:-skip] if skip else chs
    todo = usable[shard::shards] if shards > 1 else usable
    safe = re.sub(r'[\\/:*?"<>|]', '_', str(name))
    os.makedirs(OUT, exist_ok=True)
    print(f'{name}  shard {shard}/{shards}  本片 {len(todo)} 章 / 共 {len(usable)}  {tabs} 标签', flush=True)

    t0 = time.time(); ok = 0
    async with async_playwright() as p:
        br = await p.firefox.launch()
        ctx = await br.new_context(viewport={'width': 900, 'height': 1400}, user_agent=UA, locale='zh-CN')
        await ctx.add_cookies(pcs)
        sem = asyncio.Semaphore(tabs)

        async def one(c):
            nonlocal ok
            async with sem:
                pg = await ctx.new_page()
                try:
                    cid, order = c['C'], c['O']
                    await pg.goto(f'https://m.qidian.com/chapter/{book}/{cid}/', timeout=45000,
                                  wait_until='domcontentloaded')
                    txt, waited = '', 0.0
                    while waited < 14:
                        await pg.wait_for_timeout(500); waited += 0.5
                        if waited < 1.0: continue
                        try: txt = await pg.locator('#reader-content').first.inner_text(timeout=1500)
                        except Exception: txt = ''
                        if len(re.findall(r'[\u4e00-\u9fff]', txt)) > 800: break
                    cn = len(re.findall(r'[\u4e00-\u9fff]', txt))
                    body = await pg.inner_text('body')
                    if '此章节非限免章节' in body and cn < 500:
                        print(f'  ❌ O={order}', flush=True); return
                    txt = re.sub(r'(不再显示订阅提醒.*|APP看广告免费解锁本章.*|订阅本章.*|批量订阅.*)$', '', txt, flags=re.S)
                    with open(f'{OUT}/{safe}_{order:>08d}.txt', 'w', encoding='utf-8') as f:
                        f.write(f'{name}  第{order//1000}章  (id={cid}, 官方字数{c.get("W")})\n\n{txt}\n')
                    ok += 1
                    print(f'  ✓ O={order:>7} {cn}字', flush=True)
                except Exception as e:
                    print(f'  ✗ O={c.get("O")} {str(e)[:60]}', flush=True)
                finally:
                    await pg.close()

        await asyncio.gather(*[one(c) for c in todo])
        await ctx.close(); await br.close()
    el = time.time() - t0
    print(f'\n★ 成功 {ok}/{len(todo)}  耗时 {el:.0f}s  ⇒ {el/max(ok,1):.1f}s/章', flush=True)

asyncio.run(main())
