#!/usr/bin/env python3
# qqread_driver.py — QQ阅读 App 游客态 MITM 流量采集驱动 (子代理, 2026-10-19)
#
# 前置(runner上由 workflow bash 步骤完成, 照抄 qd-mitm-login.yml 接线):
#   redroid(localhost:5555) + com.qq.reader 已安装 + MITM 管道已接线
#   (iptables DNAT 172.17.0.0/16→宿主:8899 + 封UDP443 + mitmproxy CA 已进系统证书
#    + settings global http_proxy + mitmdump -w /tmp/all.flows 已在跑)
#
# 链路(全程不登录, 游客态是实验条件):
#   Phase A 首启: monkey 拉起 → 隐私/权限弹窗点掉(白名单文本: 同意/允许/我知道了…
#            黑名单绝不点: 登录/立即登录/一键登录) — 每轮 dump+截图留证
#   Phase B 书城自然流量: swipe 滑书城列表 ~90s
#   Phase C 搜索: deeplink uniteqqreader://nativepage/search?key=大生意人(已URL编码)
#            → dump(必要时点搜索) → 结果里点《大生意人》; 兜底 deeplink book/detail?bid=54425396
#   Phase D 书详情: 点 开始阅读/免费阅读 (兜底坐标 540,2200)
#   Phase E 读第1章(免费): 翻页 swipe×4, 每页截图
#   Phase F 撞第5章付费墙: 点屏幕中央开菜单 → 目录 → 点第5章(或连点下一章×5)
#            → 付费墙页面 dump+截图(只观察, 绝不点购买/登录)
#   Phase G 收尾: logcat 关键行落盘 → verdict
#
# 凭据纪律: 游客态无个人凭据; 上传的 flows 为游客流量(仍不含任何账号信息)。
# 用法: python3 ci/qqread_driver.py   (环境变量 QQREAD_BID / QQREAD_KEY 可覆盖)
import os, sys, json, time, re, subprocess

ADB_DEV = 'localhost:5555'
APP = 'com.qq.reader'
FLOWS = '/tmp/all.flows'
OUT = '/tmp/out'
DUMPS = os.path.join(OUT, 'ui_dumps')
BID = os.environ.get('QQREAD_BID') or '54425396'
KEY_ENC = os.environ.get('QQREAD_KEY_ENC') or '%E5%A4%A7%E7%94%9F%E6%84%8F%E4%BA%BA'  # 大生意人

VERDICT = {'bid': BID, 'phases': {}}

# 弹窗处理白名单(点) / 黑名单(绝不点, 游客态红线)
CONSENT_OK = ['同意并继续', '同意并进入', '同意', '允许', '仅在使用中允许', '我知道了', '知道了',
              '稍后再说', '以后再说', '暂不', '跳过', '立即体验', '开始使用', '进入书城', '不了，谢谢']
LOGIN_BLACK = ['登录', '注册', '手机号', '一键开通', '购买', '支付', '开通会员', '立即充值', '充值']

# UI 输入安全层(照抄 mitm_login_capture.py: input×2 → sendevent → 放弃, 永不抛)
_TOUCH_DEV = None
_UI_FAILS = {'input': 0, 'sendevent': 0}


def L(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def adb(*args, timeout=20):
    return subprocess.run(['adb', '-s', ADB_DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def sh(*args, timeout=20):
    return adb('shell', *args, timeout=timeout)


def _find_touch_dev():
    global _TOUCH_DEV
    if _TOUCH_DEV is not None:
        return _TOUCH_DEV or None
    _TOUCH_DEV = ''
    try:
        r = sh('getevent', '-pl', timeout=15)
        cur = None
        for line in (r.stdout or '').splitlines():
            line = line.strip()
            m = re.match(r'add device \d+: (/dev/input/event\d+)', line)
            if m:
                cur = m.group(1)
            if cur and 'ABS_MT_POSITION_X' in line:
                _TOUCH_DEV = cur
                break
    except Exception:
        pass
    return _TOUCH_DEV or None


def _sendevent_seq(cmds):
    dev = _find_touch_dev()
    if not dev:
        _UI_FAILS['sendevent'] += 1
        return False
    script = ' && '.join('sendevent %s %d %d %d' % (dev, t, c, v) for t, c, v in cmds)
    try:
        sh(script, timeout=25)
        return True
    except Exception:
        _UI_FAILS['sendevent'] += 1
        return False


def _sendevent_swipe(x1, y1, x2, y2, steps=8):
    cmds = [(3, 57, 100), (3, 53, x1), (3, 54, y1), (1, 330, 1), (0, 0, 0)]
    for i in range(1, steps + 1):
        cmds += [(3, 53, x1 + (x2 - x1) * i // steps), (3, 54, y1 + (y2 - y1) * i // steps), (0, 0, 0)]
    cmds += [(3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)]
    return _sendevent_seq(cmds)


def _sendevent_tap(x, y):
    return _sendevent_seq([(3, 57, 101), (3, 53, x), (3, 54, y), (1, 330, 1), (0, 0, 0),
                           (3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)])


def ui_swipe(x1, y1, x2, y2, ms=300):
    for attempt in (1, 2):
        try:
            sh('input', 'swipe', str(x1), str(y1), str(x2), str(y2), str(ms), timeout=30)
            return True
        except Exception:
            _UI_FAILS['input'] += 1
    ok = _sendevent_swipe(x1, y1, x2, y2)
    return ok


def ui_tap(x, y):
    for attempt in (1, 2):
        try:
            sh('input', 'tap', str(x), str(y), timeout=30)
            return True
        except Exception:
            _UI_FAILS['input'] += 1
    return _sendevent_tap(x, y)


def ui_key(code):
    try:
        sh('input', 'keyevent', str(code), timeout=25)
        return True
    except Exception:
        _UI_FAILS['input'] += 1
        return False


def pidof():
    try:
        out = (sh('pidof', APP, timeout=10).stdout or '').strip()
        return out.split()[0] if out else None
    except Exception:
        return None


def foreground():
    try:
        for line in (sh('dumpsys', 'window', timeout=12).stdout or '').splitlines():
            if 'mCurrentFocus' in line:
                return line.strip()[:160]
    except Exception:
        pass
    return '?'


def dump_name(tag):
    return os.path.join(DUMPS, '%02d_%s.xml' % (int(time.time()) % 100, tag))


def dump_ui(tag=''):
    xml = ''
    try:
        sh('uiautomator', 'dump', '/sdcard/u.xml', timeout=15)
        r = sh('cat', '/sdcard/u.xml', timeout=15)
        xml = r.stdout or ''
    except Exception:
        pass
    if xml and tag:
        try:
            open(dump_name(tag), 'w', encoding='utf-8', errors='replace').write(xml)
        except Exception:
            pass
    return xml


def nodes(xml):
    """所有节点的 (text, desc, id, bounds中心) 列表, 供文本匹配与证据。"""
    out = []
    for m in re.finditer(r'<node[^>]*>', xml or ''):
        seg = m.group(0)
        def attr(n):
            mm = re.search(r'%s="([^"]*)"' % n, seg)
            return mm.group(1) if mm else ''
        b = attr('bounds')
        bm = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', b)
        if not bm:
            continue
        x1, y1, x2, y2 = map(int, bm.groups())
        t, d, rid = attr('text'), attr('content-desc'), attr('resource-id')
        if t or d:
            out.append((t, d, rid, (x1 + x2) // 2, (y1 + y2) // 2, x2 - x1, y2 - y1))
    return out


def find_text(xml, *texts, contains=True):
    for t, d, rid, cx, cy, w, h in nodes(xml):
        for want in texts:
            hay = t or d
            if (want in hay) if contains else (hay == want):
                return want, cx, cy
    return None


def tap_text(xml, *texts, contains=True):
    hit = find_text(xml, *texts, contains=contains)
    if hit:
        want, x, y = hit
        ui_tap(x, y)
        return want
    return None


def tap_id(xml, *ids):
    for t, d, rid, cx, cy, w, h in nodes(xml):
        if not rid:
            continue
        for want in ids:
            if want in rid:
                ui_tap(cx, cy)
                return want
    return None


def screenshot(name):
    try:
        p = os.path.join(OUT, name)
        with open(p, 'wb') as f:
            f.write(subprocess.run(['adb', '-s', ADB_DEV, 'exec-out', 'screencap', '-p'],
                                   capture_output=True, timeout=30).stdout)
        return os.path.getsize(p)
    except Exception:
        return 0


def flows_kb():
    return os.path.getsize(FLOWS) // 1024 if os.path.exists(FLOWS) else 0


def keep_alive():
    if not pidof():
        L('[WD] App死→monkey复活')
        sh('monkey', '-p', APP, '-c', 'android.intent.category.LAUNCHER', '1', timeout=20)
        time.sleep(12)


# ═════════════ Phase A: 首启 + 弹窗点掉 ═════════════
PRIVACY_MARK = '欢迎使用QQ阅读'   # 隐私弹窗的特征文本(R1实证: 挂在一切页面之上)


def _privacy_up(xml):
    return PRIVACY_MARK in (xml or '') or '隐私政策' in (xml or '')[:3000]


def phase_launch():
    L('═══ Phase A: 首启(am start+monkey) + 隐私/权限弹窗处理(R1教训: 冷启动>80s, 弹窗晚到, 必须长等) ═══')
    sh('logcat', '-c', timeout=10)
    sh('am', 'start', '-n', '%s/%s' % (APP, 'com.qq.reader.activity.DefaultAliasActivity'), timeout=20)
    time.sleep(6)
    sh('monkey', '-p', APP, '-c', 'android.intent.category.LAUNCHER', '1', timeout=25)

    # 冷启动等待(pid 出现即继续, 最长 ~5min; R1实证 136MB App 冷启 > 80s)
    pid = None
    for i in range(60):
        pid = pidof()
        if pid:
            break
        time.sleep(5)
    L('[A] pid=%s (等了%d轮) fg=%s' % (pid, i, foreground()[:90]))
    VERDICT['phases']['A_pid'] = str(pid)

    # 弹窗循环: 白名单点, 黑名单绝不点; dump 全程留证
    # R1教训: 不以 pid 稳定门控弹窗循环 — 弹窗可能在冷启动 2-4 分钟后才出现
    dismissed = []
    quiet_rounds = 0
    main_seen = False
    for rnd in range(40):
        xml = dump_ui('consent%d' % rnd)
        if rnd % 3 == 0:
            screenshot('shot_consent_%02d.png' % rnd)
        if not xml:
            time.sleep(8)
            continue
        ns = nodes(xml)
        texts = [t for t, d, *_ in ns if t][:25]
        if rnd % 4 == 0:
            L('[A] 弹窗轮%d 可见文本: %s' % (rnd, json.dumps(texts, ensure_ascii=False)[:400]))
        hit = None
        for t, d, rid, cx, cy, w, h in ns:
            hay = (t or d).strip()
            if not hay:
                continue
            # 黑名单优先: 命中登录/支付词的按钮绝不点
            if any(b in hay for b in LOGIN_BLACK):
                continue
            for okw in CONSENT_OK:
                # 同意/允许类: 精确或短包含; 确保是按钮尺寸(面积不太小)
                if hay == okw or (len(okw) <= 3 and okw in hay and len(hay) <= 8):
                    hit = (hay, cx, cy)
                    break
            if hit:
                break
        if hit:
            L('[A] 弹窗轮%d 点[%s] @(%d,%d)' % (rnd, hit[0], hit[1], hit[2]))
            ui_tap(hit[1], hit[2])
            dismissed.append(hit[0])
            quiet_rounds = 0
            time.sleep(8)
            continue
        # 无可点弹窗: 隐私弹窗还在吗? App活着吗? 主界面到了吗?
        fg = foreground()
        if _privacy_up(xml):
            quiet_rounds = 0
            L('[A] 弹窗轮%d 隐私弹窗在但按钮没匹配到(文本=%s)' % (rnd, json.dumps(texts, ensure_ascii=False)[:200]))
            time.sleep(6)
            continue
        if not pidof():
            L('[A] 弹窗轮%d App死→monkey复活' % rnd)
            sh('monkey', '-p', APP, '-c', 'android.intent.category.LAUNCHER', '1', timeout=20)
            time.sleep(12)
            continue
        # App活+无弹窗: 主界面特征?
        main_hint = any(k in (t or d) for t, d, *_ in ns for k in ('书城', '书架', '搜索', '排行', '免费', '限免'))
        if main_hint:
            main_seen = True
            L('[A] ✓主界面已到(轮%d) fg=%s' % (rnd, fg[:80]))
            break
        quiet_rounds += 1
        L('[A] 弹窗轮%d 无目标(quiet=%d) fg=%s' % (rnd, quiet_rounds, fg[:70]))
        if quiet_rounds >= 6:
            L('[A] 6轮无弹窗无主界面特征 → 视为可继续(Flutter页dump文本少)')
            break
        time.sleep(7)
    VERDICT['consent_tapped'] = dismissed
    VERDICT['main_seen'] = main_seen
    L('[A] 弹窗处理完成: 点过%s main=%s' % (json.dumps(dismissed, ensure_ascii=False), main_seen))
    screenshot('shot_after_consent.png')
    return main_seen or pidof() is not None



# ═════════════ Phase B: 书城自然流量 ═════════════
def phase_bookstore():
    L('═══ Phase B: 书城自然浏览 ~90s ═══')
    t0 = time.time()
    n = 0
    while time.time() - t0 < 90:
        n += 1
        keep_alive()
        ui_swipe(540, 1700, 540, 650)
        if n % 3 == 1:
            screenshot('shot_store_%02d.png' % n)
        if n % 4 == 0:
            L('[B] t+%ds flows=%dKB fg=%s' % (time.time() - t0, flows_kb(), foreground()[:60]))
        time.sleep(9)
    dump_ui('store_end')
    L('[B] 书城窗结束 flows=%dKB' % flows_kb())
    VERDICT['phases']['B'] = 'ok flows=%dKB' % flows_kb()


# ═════════════ Phase C: 搜索《大生意人》 ═════════════
def deeplink(uri):
    r = sh('am', 'start', '-a', 'android.intent.action.VIEW', '-d', uri, APP, timeout=20)
    L('[DL] %s → %s' % (uri, (r.stdout or r.stderr).strip()[:120]))
    time.sleep(8)


def phase_search():
    L('═══ Phase C: 搜索《大生意人》(deeplink key=预填) ═══')
    keep_alive()
    deeplink('uniteqqreader://nativepage/search?key=%s' % KEY_ENC)
    xml = dump_ui('search_prefill')
    screenshot('shot_search_prefill.png')
    # 搜索框是否已预填(大生意人) — dump 里的 EditText text
    prefilled = find_text(xml, '大生意人') is not None
    L('[C] 预填=%s fg=%s' % (prefilled, foreground()[:80]))
    # 若未预填: 尝试 ASCII 书号搜索(兜底); 再不行直接走书详情 deeplink
    if not prefilled:
        L('[C] 未预填 → 尝试输入书号 %s (ASCII input text)' % BID)
        # 先点一下搜索框区域(顶部)
        ui_tap(540, 200)
        time.sleep(2)
        try:
            sh('input', 'text', BID, timeout=15)
            time.sleep(2)
        except Exception:
            pass
        xml = dump_ui('search_typed')
        prefilled = find_text(xml, BID) is not None
    # 触发搜索: 点"搜索"按钮或回车
    if prefilled:
        hit = tap_text(xml, '搜索') or (ui_key(66) and 'ENTER')
        L('[C] 触发搜索: %s' % hit)
        time.sleep(10)
        xml = dump_ui('search_results')
        screenshot('shot_search_results.png')
        # 结果里点《大生意人》
        got = tap_text(xml, '大生意人')
        L('[C] 结果点击: %s' % got)
        if got:
            time.sleep(10)
            VERDICT['phases']['C'] = 'ok via search'
            return True
    # 兜底: deeplink 直达书详情
    L('[C] 搜索路径未达 → deeplink book/detail?bid=%s' % BID)
    deeplink('uniteqqreader://nativepage/book/detail?bid=%s' % BID)
    time.sleep(8)
    xml = dump_ui('book_detail_deeplink')
    screenshot('shot_book_detail_deeplink.png')
    ok = find_text(xml, '大生意人') is not None
    VERDICT['phases']['C'] = ('ok via deeplink' if ok else 'uncertain') + (' (search=%s)' % prefilled)
    return ok


# ═════════════ Phase D: 书详情 → 开始阅读 ═════════════
def phase_book_detail():
    L('═══ Phase D: 书详情 → 进第1章 ═══')
    keep_alive()
    xml = dump_ui('book_detail')
    screenshot('shot_book_detail.png')
    ns = [(t, d, cx, cy) for t, d, rid, cx, cy, w, h in nodes(xml)]
    L('[D] 书详情可见文本: %s' % json.dumps([t for t, *_ in ns][:30], ensure_ascii=False)[:500])
    hit = tap_text(xml, '开始阅读', '免费阅读', '立即阅读', '继续阅读', '免费读')
    time.sleep(12)
    fg = foreground()
    if 'ReaderPage' not in fg:
        if not hit:
            L('[D] 文本未命中 → 坐标兜底 (540,2200)')
            ui_tap(540, 2200)
            hit = 'coord(540,2200)'
        time.sleep(12)
        fg = foreground()
    if 'ReaderPage' not in fg:
        # R1实证: deeplink 直达阅读页(绕过Flutter书详情的不确定性)
        L('[D] 仍未进阅读页 → deeplink readepage?bid=%s' % BID)
        deeplink('uniteqqreader://nativepage/client/readepage?bid=%s' % BID)
        time.sleep(14)
        fg = foreground()
        hit = (hit or '') + '+readepage_dl'
    L('[D] 进阅读后 fg=%s' % fg[:100])
    dump_ui('reader_entered')
    screenshot('shot_reader_entered.png')
    VERDICT['phases']['D'] = 'tap=%s fg=%s' % (hit, fg[:80])
    return 'ReaderPage' in fg or 'reader' in fg.lower()


# ═════════════ Phase E: 读第1章翻页 ═════════════
def phase_read_ch1():
    L('═══ Phase E: 第1章翻页×4 ═══')
    for i in range(4):
        keep_alive()
        ui_swipe(900, 1170, 150, 1170)   # 左翻=下一页
        time.sleep(6)
        screenshot('shot_ch1_page%d.png' % (i + 1))
        if i == 1:
            dump_ui('ch1_mid')
    L('[E] 翻页完 flows=%dKB' % flows_kb())
    VERDICT['phases']['E'] = 'ok flows=%dKB' % flows_kb()


# ═════════════ Phase F: 第5章付费墙 ═════════════
def phase_paywall():
    L('═══ Phase F: 目录→第5章(付费墙) ═══')
    keep_alive()
    # 开阅读菜单(点屏幕中央)
    ui_tap(540, 1170)
    time.sleep(3)
    xml = dump_ui('reader_menu')
    screenshot('shot_reader_menu.png')
    # 点 目录
    hit = tap_text(xml, '目录') or tap_id(xml, 'tvCatalog', 'btnCatalog')
    if hit:
        L('[F] 点了目录[%s]' % hit)
        time.sleep(5)
        xml = dump_ui('chapter_list')
        screenshot('shot_chapter_list.png')
        ns = [(t, d, cx, cy) for t, d, rid, cx, cy, w, h in nodes(xml)]
        L('[F] 目录前30项: %s' % json.dumps([t for t, *_ in ns][:30], ensure_ascii=False)[:600])
        # 找第5章(标题含"第5章"或"5章"开头), VIP标记无妨照点(撞付费墙正是目的)
        target = None
        for t, d, cx, cy in ns:
            hay = (t or d).strip()
            if re.match(r'^第\s*5\s*章', hay) or re.match(r'^0?5[\s\.、]', hay):
                target = (cx, cy)
                break
        if target is None:
            # 兜底: 目录列表第5项(列表项通常等高, 首项y附近+4*item_h)
            items = [(cy) for t, d, cx, cy in ns if t and 250 < cy < 1600]
            if items:
                items.sort()
                if len(items) >= 5:
                    target = (540, items[4])
        if target:
            L('[F] 点第5章 @%s' % (target,))
            ui_tap(*target)
            time.sleep(10)
            xml2 = dump_ui('ch5_paywall')
            screenshot('shot_ch5_paywall.png')
            ns2 = [(t or d) for t, d, rid, cx, cy, w, h in nodes(xml2) if (t or d)]
            L('[F] 第5章页面文本: %s' % json.dumps(ns2[:30], ensure_ascii=False)[:600])
            paywall_terms = [t for t in ns2 if any(k in t for k in ('VIP', '会员', '订阅', '购买', '书币', '起点币', '登录', '付费'))]
            VERDICT['phases']['F'] = 'paywall_terms=%s' % json.dumps(paywall_terms[:8], ensure_ascii=False)
            VERDICT['paywall_texts_seen'] = paywall_terms[:15]
            L('[F] 付费墙证据: %s' % json.dumps(paywall_terms[:10], ensure_ascii=False))
            return True
        L('[F] 目录里没找到第5章目标')
    else:
        L('[F] 菜单里没找到目录入口 → 改连点下一章')
    # 兜底: 菜单里连点下一章×5
    for i in range(5):
        ui_tap(540, 1170)
        time.sleep(2)
        xml = dump_ui('next_ch_menu%d' % i)
        hit = tap_text(xml, '下一章', '下一页') or tap_id(xml, 'tvNextChapter', 'btnNext')
        L('[F] 下一章轮%d: %s' % (i, hit))
        if not hit:
            break
        time.sleep(8)
        screenshot('shot_nextch_%d.png' % i)
    xml2 = dump_ui('after_nextch')
    screenshot('shot_after_nextch.png')
    ns2 = [(t or d) for t, d, rid, cx, cy, w, h in nodes(xml2) if (t or d)]
    VERDICT['phases']['F'] = 'fallback_nextch texts=%s' % json.dumps(ns2[:10], ensure_ascii=False)
    return True


# ═════════════ Phase G: 收尾 ═════════════
def phase_teardown():
    L('═══ Phase G: 收尾(logcat+verdict) ═══')
    try:
        r = sh('logcat', '-d', '-v', 'time', timeout=40)
        open(os.path.join(OUT, 'logcat_capture.txt'), 'w', errors='replace').write((r.stdout or '')[-400000:])
        key = [l for l in (r.stdout or '').splitlines()
               if re.search(r'qq\.reader|FATAL|AndroidRuntime|reader\.qq\.com|guest', l)]
        open(os.path.join(OUT, 'logcat_key_lines.txt'), 'w', errors='replace').write('\n'.join(key[:300]))
        L('[G] logcat: 全量%d行 关键%d行' % (len((r.stdout or '').splitlines()), len(key)))
    except Exception as e:
        L('[G] logcat 失败: %s' % str(e)[:80])
    VERDICT['flows_kb'] = flows_kb()
    VERDICT['foreground_final'] = foreground()[:120]
    VERDICT['ui_input_fails'] = dict(_UI_FAILS)
    json.dump(VERDICT, open(os.path.join(OUT, 'driver_verdict.json'), 'w'), ensure_ascii=False, indent=1)
    L('════ VERDICT ════ %s' % json.dumps(VERDICT, ensure_ascii=False)[:800])


def run_phase(name, fn):
    try:
        return fn()
    except Exception as e:
        L('[%s] ★阶段异常被隔离: %s: %s (继续)' % (name, type(e).__name__, str(e)[:200]))
        VERDICT['phases'][name] = 'CRASH %s: %s' % (type(e).__name__, str(e)[:120])
        return None


def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(DUMPS, exist_ok=True)
    L('=== qqread_driver start (pid=%d bid=%s) ===' % (os.getpid(), BID))
    run_phase('A', phase_launch)
    run_phase('B', phase_bookstore)
    run_phase('C', phase_search)
    run_phase('D', phase_book_detail)
    run_phase('E', phase_read_ch1)
    run_phase('F', phase_paywall)
    run_phase('G', phase_teardown)
    L('=== done flows=%dKB ===' % flows_kb())
    return 0


if __name__ == '__main__':
    sys.exit(main())
