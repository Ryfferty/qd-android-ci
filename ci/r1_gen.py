#!/usr/bin/env python3
"""r1_gen.py — r1 (/argus/api/v3/client/r1) i/r blob 解密/生成/密钥验证工具 (2026-10-15)

体制定案(证据链见 RECON/r1_key_hunt.md):
  - r/i = AES-128-CFB-128 (libknobs SetB knobs_12480967@arm32 0xd07c / arm64 0x140ac)
    unidbg 直调实证: 与标准 AES-128-CFB128 (PyCryptodome segment_size=128) 字节级全等
    (selftest 锚定向量 = unidbg 实测输出)。
  - 密钥不在 libknobs 内(keyexp 0内部调用者/无init_array/.bss 192B init后全零 — unidbg实证),
    由 VMP(l1.judian/libjiagu_vip) 外部经 dlsym 传入 → 必须设备侧 frida dump。
  - CFB-128 解密 block j>=1 不需要 IV(IV 只影响首 16B) → verify_key 无 IV 也能验证。

用法:
  python3 r1_gen.py selftest                     # 锚定向量自检(unidbg对拍+ECB互逆+oracle正反例+IV回收)
  python3 r1_gen.py verify --key <32hex> [--iv <32hex>]   # 解密全语料+结构报告
  python3 r1_gen.py harvest <collect.log> [--extra-keys pool.txt]
                                                 # v1+v2 全事件收割: 候选钥×(仓语料+本安装wire) oracle
                                                 # + (pt,ct) oracle + 材料面汇总(vmp/sora/armor/pref/memscan/sched…)
  python3 r1_gen.py oracle <collect.log> --pt <hex|@f> --ct <b64|hex|@f> [--extra-keys pool.txt]
                                                 # (pt,ct) 专道: 手工对齐明文/密文 → 全部候选钥滑移裁决
  python3 r1_gen.py canary <collect.log>         # hook存活性+SetB块原语语义判定(本地AES复算直调向量)
  python3 r1_gen.py enc --key <hex> --iv <hex> --pt <hex|@file>   # 生成密文(b64)
  python3 r1_gen.py dec --key <hex> [--iv <hex>] --ct <b64|hex|@file>
  python3 r1_gen.py ir [--device d4da|K] [--variant 536|608|648] [--key .. --iv .. --pt ..]
                                                 # full_fidelity_chain 接口: 重放(默认)/生成 wire-b64 (i,r)
"""
import argparse, base64, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, 'r1_corpus.json')

# ---------- AES-CFB128 (PyCryptodome, 缺库时纯Python回退) ----------
SBOX = None
def _init_sbox():
    global SBOX
    if SBOX: return
    p = q = 1
    SBOX = [0]*256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    SBOX[0] = 0x63

def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a

def _expand(key):
    _init_sbox()
    nk = len(key)//4
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4*(nk+7)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return w

def _enc_block(w, blk, rounds):
    _init_sbox()
    s = [blk[i] ^ bytes(w[i//4])[i%4] for i in range(16)]
    for rnd in range(1, rounds+1):
        s = [SBOX[b] for b in s]
        idx = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]
        s = [s[i] for i in idx]
        if rnd != rounds:
            ns = list(s)
            for c in range(4):
                a = s[4*c:4*c+4]
                t = a[0]^a[1]^a[2]^a[3]
                for r in range(4):
                    ns[4*c+r] = a[r] ^ t ^ _xtime(a[r] ^ a[(r+1)%4])
            s = ns
        base = 16*rnd
        s = [s[i] ^ bytes(w[(base+i)//4])[(base+i)%4] for i in range(16)]
    return bytes(s)

def aes_cfb128(key, iv, data, encrypt=True):
    """标准 AES-CFB-128; 与 libknobs knobs_12480967 字节级一致(unidbg实证)。
    注意: CFB 下 encrypt/decrypt 是不同变换(feedback=ct vs pt), 不可混用同一调用。
    纯Python实现(慢但零依赖); 有PyCryptodome时自动切换。"""
    try:
        from Crypto.Cipher import AES
        c = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return c.encrypt(data) if encrypt else c.decrypt(data)
    except ImportError:
        pass
    rounds = {16:10, 24:12, 32:14}[len(key)]
    w = _expand(key)
    out = bytearray()
    reg = bytearray(iv)
    for i in range(0, len(data), 16):
        ks = _enc_block(w, bytes(reg), rounds)
        chunk = data[i:i+16]
        for j, b in enumerate(chunk):
            o = b ^ ks[j]
            out.append(o)
            reg[j] = o if encrypt else b
    return bytes(out)

def cfb128_dec_noiv(key, ct):
    """从 block1 起解密(无需IV): P[j]=E_k(ct[j-1])^ct[j], j>=1 → 返回 ct[16:] 的明文。"""
    try:
        from Crypto.Cipher import AES
        out = b''
        for j in range(1, len(ct)//16):
            ks = AES.new(key, AES.MODE_ECB).encrypt(ct[(j-1)*16:j*16])
            out += bytes(a^b for a,b in zip(ks, ct[j*16:(j+1)*16]))
        return out
    except ImportError:
        rounds = {16:10, 24:12, 32:14}[len(key)]
        w = _expand(key)
        out = b''
        for j in range(1, len(ct)//16):
            ks = _enc_block(w, ct[(j-1)*16:j*16], rounds)
            out += bytes(a^b for a,b in zip(ks, ct[j*16:(j+1)*16]))
        return out

# ---------- AES-ECB 单块 (pt,ct oracle / IV 回收用; PyCryptodome 缺失时纯Python) ----------
INV_SBOX = None
def _init_inv_sbox():
    global INV_SBOX
    if INV_SBOX: return
    _init_sbox()
    INV_SBOX = [0]*256
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i

def _mul(a, b):
    _init_sbox()
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return r

def _inv_shiftrows(s):
    out = list(s)
    for r in range(1, 4):
        row = [s[4*c+r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            out[4*c+r] = row[c]
    return out

def _dec_block(w, blk, rounds):
    """等价逆密码 (equivalent inverse cipher), 与 _enc_block 互逆。"""
    _init_inv_sbox()
    base = 16*rounds
    s = [blk[i] ^ bytes(w[(base+i)//4])[(base+i)%4] for i in range(16)]
    for rnd in range(rounds-1, 0, -1):
        s = _inv_shiftrows(s)
        s = [INV_SBOX[b] for b in s]
        base = 16*rnd
        s = [s[i] ^ bytes(w[(base+i)//4])[(base+i)%4] for i in range(16)]
        ns = list(s)
        for c in range(4):
            a = s[4*c:4*c+4]
            ns[4*c+0] = _mul(a[0],14) ^ _mul(a[1],11) ^ _mul(a[2],13) ^ _mul(a[3],9)
            ns[4*c+1] = _mul(a[0],9)  ^ _mul(a[1],14) ^ _mul(a[2],11) ^ _mul(a[3],13)
            ns[4*c+2] = _mul(a[0],13) ^ _mul(a[1],9)  ^ _mul(a[2],14) ^ _mul(a[3],11)
            ns[4*c+3] = _mul(a[0],11) ^ _mul(a[1],13) ^ _mul(a[2],9)  ^ _mul(a[3],14)
        s = ns
    s = _inv_shiftrows(s)
    s = [INV_SBOX[b] for b in s]
    s = [s[i] ^ bytes(w[i//4])[i%4] for i in range(16)]
    return bytes(s)

def aes_ecb_enc(key, blk):
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_ECB).encrypt(blk)
    except ImportError:
        return _enc_block(_expand(key), blk, {16:10, 24:12, 32:14}[len(key)])

def aes_ecb_dec(key, blk):
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_ECB).decrypt(blk)
    except ImportError:
        return _dec_block(_expand(key), blk, {16:10, 24:12, 32:14}[len(key)])

# ---------- (pt,ct) oracle (采集点d): CFB-128 下 keystream=pt^ct, KS[j]=E_k(ct[j-1]) ----------
def oracle_ptct(pt, ct, key):
    """返回 (checked, matched)。matched>=1 且对齐正确 ⇒ 128bit级钥匙确认(零假阳性)。
    要求 pt/ct 从同一 block0 起对齐(同偏移截取即可, 不要求 len%16==0)。"""
    n = min(len(pt), len(ct))
    ks = bytes(a ^ b for a, b in zip(pt[:n], ct[:n]))
    checked = matched = 0
    for j in range(1, n // 16):
        expect = ks[j*16:(j+1)*16]
        if len(expect) < 16: break
        checked += 1
        if aes_ecb_enc(key, ct[(j-1)*16:j*16]) == expect:
            matched += 1
    return checked, matched

def recover_iv(pt, ct, key):
    """key 已确认且 pair 覆盖 block0 时: KS0=pt0^ct0=E_k(IV) → IV=D_k(KS0)。"""
    if len(pt) < 16 or len(ct) < 16: return None
    ks0 = bytes(a ^ b for a, b in zip(pt[:16], ct[:16]))
    return aes_ecb_dec(key, ks0)

def looks_b64(s, minlen=64):
    """wire/pref 值形状判定: b64(url-safe)且解码后≥minlen字节。返回 bytes 或 None。"""
    import re as _re
    if not s or len(s) < minlen: return None
    t = s.strip()
    if not _re.fullmatch(r'[A-Za-z0-9+/_\-]+={0,2}', t): return None
    try:
        raw = base64.b64decode(t.replace('-', '+').replace('_', '/') + '=' * (-len(t) % 4))
        return raw if len(raw) >= minlen else None
    except Exception:
        return None

# ---------- 语料 ----------
def load_corpus():
    c = json.load(open(CORPUS))
    out = []
    for dev in ('d4da', 'K'):
        seen = {}
        for x in c[dev]:
            r = bytes.fromhex(x['r'])
            k = (len(r), r)
            if k not in seen:
                seen[k] = True
                out.append({'dev': dev, 'len': len(r), 'r': r, 'i': bytes.fromhex(x['i']),
                            'o36': x['o36'], 'ts': x['ts']})
    return out

# ---------- 结构评估 ----------
def struct_report(pt, q36=None):
    rep = {}
    rep['printable'] = round(sum(1 for b in pt if 32 <= b < 127)/max(1,len(pt)), 3)
    runs, cur = [], bytearray()
    for b in pt:
        if 32 <= b < 127: cur.append(b)
        else:
            if len(cur) >= 8: runs.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= 8: runs.append(bytes(cur))
    rep['ascii_runs>=8'] = [r.decode()[:60] for r in runs[:12]]
    if q36:
        rep['qimei36_hits'] = pt.count(q36.encode())
    for mk in (b'o16=', b'o36=', b'guid=', b'qimei', b'runMode', b'obs_', b'{"', b'eth0'):
        if mk in pt: rep.setdefault('markers', []).append(mk.decode())
    return rep

def verify_key(key, iv=None, quiet=False):
    corpus = load_corpus()
    verdict = {'key': key.hex(), 'iv': iv.hex() if iv else None, 'blobs': []}
    for e in corpus:
        if iv:
            pt = aes_cfb128(key, iv, e['r'], encrypt=False)
        else:
            pt = b'\x00'*16 + cfb128_dec_noiv(key, e['r'])  # block0 未知(需IV)
        rep = struct_report(pt[16:] if not iv else pt, e['o36'] or None)
        verdict['blobs'].append({'dev': e['dev'], 'len': e['len'], **rep})
        # i blob 同key测试
        if iv:
            pti = aes_cfb128(key, iv, e['i'], encrypt=False)
            verdict.setdefault('i_blobs', []).append({'dev': e['dev'], **struct_report(pti)})
    if not quiet:
        print(json.dumps(verdict, ensure_ascii=False, indent=1))
    # 判定
    good = any(b.get('qimei36_hits', 0) > 0 or b['printable'] > 0.8 for b in verdict['blobs'])
    verdict['VERDICT'] = 'KEY-CONFIRMED' if good else 'no-signal'
    return verdict

# ---------- full_fidelity_chain 接口位: build_ir ----------
def _b64wire(raw):
    return base64.b64encode(raw).decode()

def build_ir(device='d4da', variant=608, key=None, iv=None, plaintext=None, i_plain=None,
             keyfile=None):
    """r1 (i, r) wire-b64 生成接口 — 供 ci/full_fidelity_chain.py load_r1_material() 切换用。

    模式:
      重放(默认, 现在可用): 从 r1_corpus.json 取指定设备/长度档的真实密文 → (i_b64, r_b64, src)
        —— 整包重放 Result:0 已被服务端实证(full_fidelity 阶段A实弹 10/10)。
      生成(key到手后): key/iv(hex或bytes) + plaintext/i_plain(bytes) → CFB-128 加密 → wire b64
        keyfile 缺省 sessions/r1_key.json ({"key":hex,"iv":hex,"pt_template":hex,...}, 凭据纪律:
        只落 sessions/, 不入文档)。plaintext 模板从 harvest 的 [CFB-PAIR] 事件归纳(§r1_key_hunt.md §7)。
    """
    if keyfile is None:
        keyfile = os.path.join(HERE, '..', 'sessions', 'r1_key.json')
    if key is None and os.path.exists(keyfile):
        try:
            kf = json.load(open(keyfile))
            key, iv = kf.get('key'), kf.get('iv')
        except Exception:
            pass
    if key is not None and plaintext is not None:
        kb = bytes.fromhex(key) if isinstance(key, str) else key
        vb = bytes.fromhex(iv) if isinstance(iv, str) else (iv or bytes(16))
        pb = bytes.fromhex(plaintext) if isinstance(plaintext, str) else plaintext
        ib = None
        if i_plain is not None:
            ib = bytes.fromhex(i_plain) if isinstance(i_plain, str) else i_plain
            ib = aes_cfb128(kb, vb, ib)
        rb = aes_cfb128(kb, vb, pb)
        return (_b64wire(ib) if ib else None), _b64wire(rb), 'r1_gen.build_ir(gen)'
    # 重放模式
    corpus = load_corpus()
    cands = [e for e in corpus if e['dev'] == device and e['len'] == variant]
    if not cands:
        cands = [e for e in corpus if e['len'] == variant] or corpus
    e = cands[0]
    return _b64wire(e['i']), _b64wire(e['r']), f'r1_gen.build_ir(replay:{e["dev"]}:{e["len"]})'

# ---------- collect.log 收割 ----------
HEXRE = re.compile(r'\b[0-9a-f]{32,}\b')

def collect_material(txt):
    """解析 [R1KEY]{json} 事件流 (hook v1+v2 全事件类型) → 结构化材料 dict。"""
    M = {'cands': {}, 'cands32': {}, 'ivs': {}, 'pairs': [], 'install': [],
         'vmp_calls': {}, 'vmp_bigrets': [], 'envjsons': [], 'soras': [],
         'armor': {}, 'prefs': [], 'filewrites': [], 'memscan': [], 'memscan_ct': {},
         'scheds': [], 'sbox': {}, 'execregions': 0, 'canaries': [], 'blks': [],
         'dlsyms': {}, 'knobs_lk': 0, 'legacy_wire': 0}
    for m in re.finditer(r'\[R1KEY\] (\{.*\})', txt):
        try: ev = json.loads(m.group(1))
        except Exception: continue
        e = ev.get('ev')
        if e == 'keyexp' and ev.get('key'):
            kb = bytes.fromhex(ev['key'])
            if len(kb) == 16:
                M['cands'][f"keyexp_{ev.get('suite','?')}_{kb[:4].hex()}"] = kb
            elif len(kb) in (24, 32):
                M['cands32'][f"keyexp_{ev.get('suite','?')}_{kb[:4].hex()}"] = kb
        elif e == 'cfb':
            for fld in ('ctx_key_off8', 'ctx_key_off16'):
                if ev.get(fld) and fld != '<bad>':
                    try:
                        kb = bytes.fromhex(ev[fld])
                        if len(kb) == 16: M['cands'][f"cfbctx_{fld}_{kb[:4].hex()}"] = kb
                    except ValueError: pass
            if ev.get('ctx'):
                try:
                    h = bytes.fromhex(ev['ctx'])
                    for off in (0, 8, 16, 24):
                        if len(h) >= off+16:
                            M['cands'][f"cfbctx_raw_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]
                except ValueError: pass
            if ev.get('reg_in') and ev['reg_in'] != '<bad>':
                try: M['ivs'][f"cfb_reg_{ev['reg_in'][:8]}"] = bytes.fromhex(ev['reg_in'])[:16]
                except ValueError: pass
            if ev.get('pt') and ev.get('ct'):
                try:
                    pt = bytes.fromhex(ev['pt']); ct = bytes.fromhex(ev['ct'])
                    if '<bad>' not in (ev['pt'], ev['ct']) and len(pt) >= 32:
                        M['pairs'].append((pt, ct, f"cfb:{ev.get('variant')}:{ev.get('dir')}"))
                except ValueError: pass
        elif e == 'blockprim':
            M['blks'].append(ev)
            for fld in ('ctx_key_off8', 'ctx_key_off16'):
                if ev.get(fld) and ev[fld] != '<bad>':
                    try:
                        kb = bytes.fromhex(ev[fld])
                        if len(kb) == 16: M['cands'][f"blkctx_{fld}_{kb[:4].hex()}"] = kb
                    except ValueError: pass
        elif e == 'ctr':
            if ev.get('ctx'):
                try:
                    h = bytes.fromhex(ev['ctx'])
                    for off in (8, 16):
                        if len(h) >= off+16: M['cands'][f"ctrctx_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]
                except ValueError: pass
        elif e == 'genenc' and ev.get('key32'):
            try:
                kb = bytes.fromhex(ev['key32'])
                M['cands'][f"genenc32_{kb[:4].hex()}"] = kb[:16]
                if len(kb) == 32:
                    M['cands'][f"genenc16_{kb[:4].hex()}"] = kb[16:32]
                    M['cands32'][f"genenc32full_{kb[:4].hex()}"] = kb
            except ValueError: pass
        elif e == 'bss' and ev.get('hex'):
            try:
                h = bytes.fromhex(ev['hex'])
                if h != bytes(len(h)):
                    for off in (0, 8, 16, 24):
                        if len(h) >= off+16:
                            M['cands'][f"bss_{ev.get('tag','?')}_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]
            except ValueError: pass
        elif e == 'schedscan' and ev.get('key'):
            try:
                kb = bytes.fromhex(ev['key'])
                where = f"{ev.get('range','?')}+{ev.get('off','?')}"
                M['scheds'].append({'bits': ev.get('bits'), 'key': kb.hex(), 'where': where,
                                    'tag': ev.get('tag')})
                if len(kb) == 16: M['cands'][f"sched128_{kb[:4].hex()}_{ev.get('tag','')}"] = kb
                elif len(kb) in (24, 32): M['cands32'][f"sched{ev.get('bits')}_{kb[:4].hex()}"] = kb
            except ValueError: pass
        elif e == 'canary':
            M['canaries'].append(ev)
        elif e == 'vmp':
            cm = f"{ev.get('cls')}.{ev.get('m')}"
            M['vmp_calls'][cm] = M['vmp_calls'].get(cm, 0) + 1
            r = ev.get('ret')
            if r and len(r) >= 400:
                M['vmp_bigrets'].append({'m': cm, 'len': len(r), 'head': r[:120]})
                raw = looks_b64(r.rstrip('…'), 64)
                if raw: M['install'].append({'r': raw, 'i': b'', 'o36': '', 'src': f"vmp_ret:{cm}"})
        elif e == 'envjson':
            M['envjsons'].append({'via': ev.get('via'), 'len': ev.get('len'),
                                  'json': ev.get('json', '')[:16384]})
        elif e in ('sora', 'sora_java'):
            v = ev.get('value') or ''
            M['soras'].append({'via': e, 'url': ev.get('url'), 'len': len(v),
                               'sha16': hashlib_sha16(v), 'value': v})
        elif e == 'armor':
            M['armor'][ev.get('in_sha16', '?')] = ev.get('out', '')
        elif e == 'pref_write':
            M['prefs'].append(ev)
            raw = looks_b64(ev.get('value', ''), 64)
            if raw and len(raw) in (72, 536, 608, 648) or (raw and 400 <= len(raw) <= 700):
                M['install'].append({'r': raw, 'i': b'', 'o36': '',
                                     'src': f"pref:{ev.get('file')}:{ev.get('key')}"})
        elif e == 'filewrite':
            M['filewrites'].append({'path': ev.get('path'), 'len': ev.get('len')})
        elif e == 'memscan':
            M['memscan'].append(ev)
            if ev.get('needle') == 'r_ct_wire' or ev.get('needle') == 'i_ct_wire':
                M['memscan_ct'][ev.get('off', '?')] = ev.get('needle')
        elif e == 'sslwire':
            try:
                rb = bytes.fromhex(ev['r']) if ev.get('r') else b''
                ib = bytes.fromhex(ev['i']) if ev.get('i') else b''
                if rb:
                    M['install'].append({'r': rb, 'i': ib, 'o36': ev.get('o36', ''),
                                         'o16': ev.get('o16', ''), 'src': 'sslwire',
                                         'ts': ev.get('t')})
            except ValueError: pass
        elif e == 'sboxhit':
            M['sbox'][ev.get('where', '?')] = ev.get('kind')
        elif e == 'execregion':
            M['execregions'] += 1
        elif e == 'dlsym':
            M['dlsyms'][ev.get('sym', '?')] = ev.get('mod')
        elif e == 'knobs_lk':
            M['knobs_lk'] += 1
        elif e in ('wire', 'ki_intercept', 'knw'):
            M['legacy_wire'] += 1
    # ── 兜底: cecelia v2 旧格式 ──
    for m in re.finditer(r'SETB_KEYEXP[^\n]*\n\s*a1ptr=\S+ mem=([0-9a-f]+)', txt):
        M['cands'].setdefault('legacy_keyexp_' + m.group(1)[:8], bytes.fromhex(m.group(1)[:32])[:16])
    for m in re.finditer(r'ctx_after_176B=([0-9a-f]{64,})', txt):
        h = bytes.fromhex(m.group(1))
        M['cands'].setdefault('legacy_ctx_off8_' + h[8:12].hex(), h[8:24])
        M['cands'].setdefault('legacy_ctx_off16_' + h[16:20].hex(), h[16:32])
    for m in re.finditer(r'\[KNOBS_BSS\][^\n]*?([0-9a-f]{384})', txt):
        h = bytes.fromhex(m.group(1))
        if h != bytes(192):
            M['cands'].setdefault('legacy_bss_off8_' + h[8:12].hex(), h[8:24])
            M['cands'].setdefault('legacy_bss_off16_' + h[16:20].hex(), h[16:32])
    return M

def hashlib_sha16(s):
    import hashlib
    return hashlib.sha256((s or '').encode(errors='replace')).hexdigest()[:16]

def verify_against(key, blob, q36=None):
    """单 blob 无IV解密结构评估 → rep dict (install-local oracle 用)。"""
    pt = b'\x00'*16 + cfb128_dec_noiv(key, blob)
    return struct_report(pt[16:], q36 or None)

def run_oracle_on_pairs(pairs, uniq, uniq32, extra=None):
    """(pt,ct) oracle: 全部候选钥过 keystream 校验。返回 CONFIRMED 列表。"""
    hits = []
    allkeys = [(n, k) for k, n in uniq.items()] + [(n, k) for k, n in (uniq32 or {}).items()]
    if extra:
        allkeys += [(f'extra_{k[:4].hex()}', k) for k in extra]
    for pt, ct, src in pairs:
        for kn, k in allkeys:
            if len(k) not in (16, 24, 32): continue
            checked, matched = oracle_ptct(pt, ct, k)
            if matched > 0:
                # IV 只在 pair 完整对齐(matched==checked, 覆盖block0)时可回收;
                # 滑移/部分对齐时 block0 关系不成立, 给 None 防误用
                iv = recover_iv(pt, ct, k) if matched == checked else None
                hits.append({'src': src, 'key': k.hex(), 'name': kn,
                             'matched': f'{matched}/{checked}',
                             'iv': iv.hex() if iv else None})
                print(f"  [PTCT-HIT] ★钥匙确认 key={k.hex()} ({kn}) pair={src} "
                      f"blocks={matched}/{checked} iv={iv.hex() if iv else '?(pair未含对齐block0)'}")
    return hits

def harvest(logpath, extra_keys_path=None):
    txt = open(logpath, errors='replace').read()
    M = collect_material(txt)

    # ── 材料面汇总 ──
    print(f"[harvest-v2] 事件面: vmp={sum(M['vmp_calls'].values())} "
          f"({len(M['vmp_calls'])}方法) envjson={len(M['envjsons'])} sora={len(M['soras'])} "
          f"armor={len(M['armor'])} pref_write={len(M['prefs'])} filewrite={len(M['filewrites'])} "
          f"sslwire_install_blobs={sum(1 for x in M['install'] if x['src']=='sslwire')} "
          f"memscan={len(M['memscan'])} sched={len(M['scheds'])} sbox={len(M['sbox'])} "
          f"exec={M['execregions']} canary={len(M['canaries'])} blockprim={len(M['blks'])} "
          f"dlsym={len(M['dlsyms'])} pairs={len(M['pairs'])}")
    if M['vmp_calls']:
        print("  [VMP] " + json.dumps(M['vmp_calls'], ensure_ascii=False))
    for br in M['vmp_bigrets'][:6]:
        print(f"  [VMP-BIGRET] {br['m']} len={br['len']} head={br['head'][:80]}")
    for ej in M['envjsons'][:2]:
        fkeys = sorted(set(re.findall(r'"([A-Za-z0-9_]{1,24})":', ej['json'])))[:24]
        print(f"  [ENVJSON] via={ej['via']} len={ej['len']} keys~{fkeys}")
    for s in M['soras'][:4]:
        print(f"  [SORA] via={s['via']} url={s.get('url')} len={s['len']} sha16={s['sha16']} (值在collect.log, 离线 knobs_toolkit.sora_decrypt→envJSON)")
    interesting_armor = [o for o in M['armor'].values() if re.search(r'o16|o36|qimei|guid|runMode|obs_|imei|android', o or '', re.I)]
    print(f"  [ARMOR] 词典{len(M['armor'])}条; 风控字段名样例: {interesting_armor[:14]}")
    for p in M['prefs'][:8]:
        print(f"  [PREF] {p.get('file')} key={p.get('key')} vlen={p.get('vlen')}")
    for f in M['filewrites'][:10]:
        print(f"  [FILEW] {f['path']} len={f['len']}")
    if M['memscan']:
        nd = {}
        for h in M['memscan']: nd[h.get('needle', '?')] = nd.get(h.get('needle', '?'), 0) + 1
        print(f"  [MEMSCAN] 命中分布: {json.dumps(nd, ensure_ascii=False)}")
        for h in M['memscan']:
            if h.get('needle') in ('o16_eq', 'o36_eq', 'o16_json', 'o36_json', 'qimei'):
                fwd = h.get('at_fwd', '')
                pr = sum(1 for i in range(0, min(len(fwd), 320), 2)
                         if 32 <= int(fwd[i:i+2] or '00', 16) < 127) / max(1, min(len(fwd), 320)//2)
                print(f"  [MEMSCAN-PT?] {h['needle']} {h.get('range')}+{h.get('off')} printable={pr:.2f} fwd={fwd[:120]}")
    for s in M['scheds'][:12]:
        print(f"  [SCHED] bits={s['bits']} key={s['key'][:32]}… where={s['where']} tag={s['tag']}")
    if M['sbox']:
        print(f"  [SBOX] AES实现定位: {json.dumps(M['sbox'], ensure_ascii=False)[:400]}")
    if M['dlsyms']:
        print(f"  [DLSYM] {json.dumps(M['dlsyms'], ensure_ascii=False)[:300]}")
    bursts = [b for b in M['blks'] if (b.get('burst') or 0) >= 8]
    if bursts:
        print(f"  [BLK-BURST] ★SetB块原语同线程≥8连发×{len(bursts)} (手搓CFB特征!) "
              f"首条: in16={bursts[0].get('in16')} ctx_key={bursts[0].get('ctx_key_off16')}")
    # canary 摘要 (语义判定: r1_gen.py canary <log>)
    for c in M['canaries'][:6]:
        print(f"  [CANARY] step={c.get('step')} ret={c.get('ret')} ct={str(c.get('ct'))[:34]} out16={str(c.get('out16'))[:34]}")

    # ── 候选钥 ──
    cands, ivs = M['cands'], M['ivs']
    uniq = {}
    for n, k in cands.items():
        if len(k) == 16: uniq.setdefault(k, n)
    uniq32 = {}
    for n, k in M['cands32'].items():
        if len(k) in (24, 32): uniq32.setdefault(k, n)
    extra = []
    if extra_keys_path:
        for line in open(extra_keys_path):
            line = line.strip().split('#')[0]
            if not line: continue
            try:
                kb = bytes.fromhex(line)
                if len(kb) in (16, 24, 32): extra.append(kb)
            except ValueError: pass
        print(f"[harvest] extra-keys 载入 {len(extra)} 把 (E档案静态池)")
    print(f"[harvest] unique key candidates: 16B={len(uniq)} 24/32B={len(uniq32)} "
          f"iv candidates: {len(ivs)}")

    # ── (pt,ct) oracle (采集点d) ──
    for pt, ct, src in M['pairs'][:8]:
        rep = struct_report(pt)
        print(f"  [CFB-PAIR] src={src} ptlen={len(pt)} printable={rep['printable']} "
              f"runs={rep.get('ascii_runs>=8', [])[:3]} markers={rep.get('markers')}")
    ptct_hits = run_oracle_on_pairs(M['pairs'], uniq, uniq32, extra)

    # ── 语料 oracle (仓内 r1_corpus.json) ──
    results = []
    corpus = load_corpus()
    install = [x for x in M['install'] if x.get('r') and len(x['r']) >= 64]
    # install-local: 同安装 wire r + 已知 o36 → 子串级精确 oracle (比仓语料更强)
    def score_all(key):
        best_q, best_p, best_src = 0, 0.0, ''
        for e in corpus:
            rep = verify_against(key, e['r'], e['o36'] or None)
            best_q = max(best_q, rep.get('qimei36_hits', 0))
            best_p = max(best_p, rep['printable'])
        for b in install:
            rep = verify_against(key, b['r'], b.get('o36') or None)
            if rep.get('qimei36_hits', 0) > best_q or rep['printable'] > best_p:
                best_src = b['src']
            best_q = max(best_q, rep.get('qimei36_hits', 0))
            best_p = max(best_p, rep['printable'])
        return best_q, best_p, best_src

    for k, kn in sorted(uniq.items(), key=lambda x: x[1]):
        q, pr, src = score_all(k)
        hit = q > 0 or pr > 0.8
        print(f"  [{'HIT ' if hit else '    '}] {kn} {k.hex()[:16]}…: qimei_hits={q} max_printable={pr:.2f}"
              + (f" via={src}" if src and hit else ""))
        if hit:
            for ivn, iv in list(ivs.items()) + [('zero', bytes(16))]:
                v2 = verify_key(k, iv, quiet=True)
                results.append((kn, k.hex(), ivn, iv.hex(), v2))
    for k, kn in sorted(uniq32.items(), key=lambda x: x[1]):
        q, pr, src = score_all(k)
        hit = q > 0 or pr > 0.8
        print(f"  [{'HIT ' if hit else '    '}] {kn}({len(k)*8}b) {k.hex()[:16]}…: qimei_hits={q} max_printable={pr:.2f}")
        if hit:
            results.append((kn, k.hex(), 'zero', bytes(16).hex(), verify_key(k, bytes(16), quiet=True)))

    if results:
        print("\n=== CONFIRMED (key, iv) pairs ===")
        for kn, kh, ivn, ivh, v in results:
            print(f"key={kh} ({kn}) iv={ivh} ({ivn})")
            print(json.dumps(v['blobs'], ensure_ascii=False)[:1200])
    if ptct_hits:
        print("\n=== PTCT-CONFIRMED (key, iv) via (pt,ct) oracle ===")
        for h in ptct_hits:
            print(json.dumps(h, ensure_ascii=False))
    if not results and not ptct_hits:
        print("\n[verdict] 本轮无 CONFIRMED — 材料面/命中分布见上; memscan 明文区与 sslwire 密文可离线人工对齐后走 `r1_gen.py oracle`")
    return results

# ---------- CLI ----------
def b64d(s):
    s = s.strip()
    from urllib.parse import unquote_plus
    s = unquote_plus(s)
    return base64.b64decode(s + '=' * (-len(s) % 4))

def read_val(v):
    if v.startswith('@'): return open(v[1:], 'rb').read().strip()
    return v.encode()

def read_bytes_val(v):
    """hex 或 b64 或 @file(hex/b64文本) → bytes"""
    raw = read_val(v)
    try: return bytes.fromhex(raw.decode())
    except (ValueError, UnicodeDecodeError): pass
    try: return b64d(raw.decode())
    except Exception: return raw

def cmd_oracle(logpath, ptval, ctval, extra_keys_path=None):
    """(pt,ct) oracle 专道: 手工对齐的明文/密文对 → 过 log 内全部候选钥(+extra池)。
    用法: r1_gen.py oracle <collect.log> --pt @pt.hex --ct <b64|hex> [--extra-keys pool.txt]"""
    pt = read_bytes_val(ptval)
    ct = read_bytes_val(ctval)
    txt = open(logpath, errors='replace').read()
    M = collect_material(txt)
    uniq = {}
    for n, k in M['cands'].items():
        if len(k) == 16: uniq.setdefault(k, n)
    uniq32 = {}
    for n, k in M['cands32'].items():
        uniq32.setdefault(k, n)
    extra = []
    if extra_keys_path:
        for line in open(extra_keys_path):
            line = line.strip().split('#')[0]
            try:
                kb = bytes.fromhex(line)
                if len(kb) in (16, 24, 32): extra.append(kb)
            except ValueError: pass
    print(f"[oracle] pt={len(pt)}B ct={len(ct)}B 候选: 16B={len(uniq)} 24/32B={len(uniq32)} extra={len(extra)}")
    hits = run_oracle_on_pairs([(pt, ct, 'cli')], uniq, uniq32, extra)
    if not hits:
        # 对齐容错: pt/ct 可能整体偏移 k 字节(memscan 截取起点≠block0) → 滑移 ±48B 重试
        print("[oracle] 直接对齐0命中 → 滑移重试(pt/ct 相对偏移 1..48B, 双向)")
        for shift in range(1, 49):
            for p2, c2, tag in ((pt[shift:], ct, f'pt+{shift}'), (pt, ct[shift:], f'ct+{shift}')):
                h = run_oracle_on_pairs([(p2, c2, tag)], uniq, uniq32, None)
                if h: return h
        print("[oracle] 滑移仍0命中: 钥不在候选池, 或 pt/ct 非同一 CFB-128 流 (体制假设需复核)")
    return hits

def cmd_canary(logpath):
    """canary 语义判定: 用本地纯Python AES 复算直调向量 →
    ① hook存活性(cfb canary ct==E流密文?) ② SetB块原语语义(E_k还是D_k? in-place还是out参?)"""
    txt = open(logpath, errors='replace').read()
    M = collect_material(txt)
    KEY = bytes.fromhex('0f1e2d3c4b5a69788796a5b4c3d2e1f0')
    PT = b'R1KEYHUNT_CANARY'
    IV = bytes(16)
    if not M['canaries']:
        print("[canary] log 内无 canary 事件 — hook 直调自检未发生(attach失败/脚本未跑?)")
        return
    exp_ct = aes_cfb128(KEY, IV, PT)
    exp_e = aes_ecb_enc(KEY, exp_ct[:16])
    exp_d = aes_ecb_dec(KEY, exp_ct[:16])
    for c in M['canaries']:
        step = c.get('step')
        if step == 'keyexp':
            ctx = c.get('ctx', '')
            ok = ctx[:32] == bytes.fromhex(KEY.hex()).hex() or KEY.hex() in ctx
            print(f"[canary] keyexp ret={c.get('ret')} ctx含原始key: {'PASS' if ok else 'FAIL'} → hook存活={'PASS' if ok else 'FAIL'}")
        elif step == 'cfb':
            got = c.get('ct', '')
            print(f"[canary] cfb ct==本地AES-CFB128复算: {'PASS(hook存活+CFB语义不变)' if got == exp_ct.hex() else 'FAIL'}")
            print(f"         got={got[:64]} exp={exp_ct.hex()[:64]}")
        else:   # SETB_BLK / SETB_BLKENC
            in16, out16, inplace = c.get('in16', ''), c.get('out16', ''), c.get('inplace', '')
            verdict = []
            if out16 == exp_e.hex(): verdict.append('out参=E_k(in) 加密向')
            if out16 == exp_d.hex(): verdict.append('out参=D_k(in) 解密向')
            if inplace == exp_e.hex(): verdict.append('in-place=E_k 加密向')
            if inplace == exp_d.hex(): verdict.append('in-place=D_k 解密向')
            if inplace == in16 and not verdict: verdict.append('未改动(x2非输出/入参布局不同)')
            print(f"[canary] {step} ret={c.get('ret')} → {'; '.join(verdict) if verdict else '语义未判定(对照 exp_e/exp_d 手工看)'}")
            print(f"         in={in16[:34]} out={out16[:34]} exp_e={exp_e.hex()[:34]} exp_d={exp_d.hex()[:34]}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['selftest', 'verify', 'harvest', 'enc', 'dec', 'ir', 'oracle', 'canary'])
    ap.add_argument('--key'); ap.add_argument('--iv')
    ap.add_argument('--pt'); ap.add_argument('--ct')
    ap.add_argument('--extra-keys')
    ap.add_argument('--device', default='d4da'); ap.add_argument('--variant', type=int, default=608)
    ap.add_argument('log', nargs='?')
    a = ap.parse_args()

    if a.cmd == 'selftest':
        KEY = bytes(range(0, 256, 17))          # 00 11 22 .. ff
        IV = bytes([0xA0 + i for i in range(16)])
        PT = b"QIDIAN_R1_CFB_SELFTEST_0123456789_abcdefghijklmn"
        EXPECT = "9e412ecb81f91af57885e8f4c825def679b00447b35a134bfed6b94916c62a275ff17d0a68433071383504b90240b0f3"
        ct = aes_cfb128(KEY, IV, PT)
        ok1 = ct.hex() == EXPECT
        back = aes_cfb128(KEY, IV, ct, encrypt=False)
        ok2 = back == PT
        noiv = cfb128_dec_noiv(KEY, ct)
        ok3 = noiv == PT[16:]
        # ECB enc/dec 互逆 + (pt,ct) oracle 正反用例 + IV 回收
        blk = PT[:16]
        ok4 = aes_ecb_dec(KEY, aes_ecb_enc(KEY, blk)) == blk
        ok5 = oracle_ptct(PT, ct, KEY) == (2, 2)          # 48B → block1,2 全中
        ok6 = oracle_ptct(PT, ct, bytes(16))[1] == 0      # 错钥 0 命中
        ok7 = recover_iv(PT, ct, KEY) == IV
        print(f"[selftest] cfb128 vs unidbg vector: {'PASS' if ok1 else 'FAIL'}")
        print(f"[selftest] roundtrip: {'PASS' if ok2 else 'FAIL'}")
        print(f"[selftest] no-iv decrypt(block1+): {'PASS' if ok3 else 'FAIL'}")
        print(f"[selftest] ecb enc/dec 互逆(纯Python路径): {'PASS' if ok4 else 'FAIL'}")
        print(f"[selftest] (pt,ct) oracle 正例2/2: {'PASS' if ok5 else 'FAIL'}")
        print(f"[selftest] (pt,ct) oracle 反例0命中: {'PASS' if ok6 else 'FAIL'}")
        print(f"[selftest] IV 回收 D_k(pt0^ct0)==IV: {'PASS' if ok7 else 'FAIL'}")
        sys.exit(0 if all((ok1, ok2, ok3, ok4, ok5, ok6, ok7)) else 1)

    if a.cmd == 'harvest':
        harvest(a.log, a.extra_keys); return

    if a.cmd == 'oracle':
        if not (a.log and a.pt and a.ct):
            print("用法: r1_gen.py oracle <collect.log> --pt <hex|@f> --ct <b64|hex|@f> [--extra-keys pool.txt]")
            sys.exit(2)
        hits = cmd_oracle(a.log, a.pt, a.ct, a.extra_keys)
        print("ORACLE_VERDICT:", "KEY-CONFIRMED " + json.dumps(hits, ensure_ascii=False) if hits else "no-signal")
        return

    if a.cmd == 'canary':
        cmd_canary(a.log); return

    if a.cmd == 'ir':
        pt = None
        if a.pt:
            raw = read_val(a.pt)
            try: pt = bytes.fromhex(raw.decode())   # CLI 约定: hex 明文 (或 @file 内 hex)
            except (ValueError, UnicodeDecodeError): pt = raw  # 非hex → 原样bytes
        i_b64, r_b64, src = build_ir(device=a.device, variant=a.variant,
                                     key=a.key, iv=a.iv, plaintext=pt)
        print(json.dumps({'src': src, 'i': i_b64, 'r': r_b64, 'i_len': len(i_b64) if i_b64 else 0,
                          'r_len': len(r_b64)}, ensure_ascii=False))
        return

    key = bytes.fromhex(a.key)
    iv = bytes.fromhex(a.iv) if a.iv else None
    if a.cmd == 'verify':
        v = verify_key(key, iv)
        print("VERDICT:", v['VERDICT'])
    elif a.cmd == 'enc':
        pt = read_val(a.pt)
        try: pt = bytes.fromhex(pt.decode())
        except (ValueError, UnicodeDecodeError): pass
        print(base64.b64encode(aes_cfb128(key, iv or bytes(16), pt)).decode())
    elif a.cmd == 'dec':
        raw = read_val(a.ct)
        try: ct = b64d(raw.decode())
        except Exception: ct = bytes.fromhex(raw.decode())
        pt = aes_cfb128(key, iv or bytes(16), ct, encrypt=False)
        sys.stdout.write(pt.hex() + "\n")
        sys.stdout.write(repr(pt) + "\n")

if __name__ == '__main__':
    main()
