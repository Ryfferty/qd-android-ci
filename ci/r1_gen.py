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
  python3 r1_gen.py selftest                     # 锚定向量自检(unidbg对拍)
  python3 r1_gen.py verify --key <32hex> [--iv <32hex>]   # 解密全语料+结构报告
  python3 r1_gen.py harvest <collect.log>        # 从 CI frida 日志提取 key/iv/ctx/bss 候选并自动 verify
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
def harvest(logpath):
    txt = open(logpath, errors='replace').read()
    cands = {}   # name -> bytes (16B key candidates)
    ivs = {}     # name -> bytes (16B IV/reg candidates)

    # ── 主通道: [R1KEY] {json} (hook_r1_keyhunt.js v1) ──
    for m in re.finditer(r'\[R1KEY\] (\{.*\})', txt):
        try: ev = json.loads(m.group(1))
        except Exception: continue
        if ev.get('ev') == 'keyexp' and ev.get('key'):
            kb = bytes.fromhex(ev['key'])
            cands[f"keyexp_{ev.get('suite','?')}_{kb[:4].hex()}"] = kb[:16]
        elif ev.get('ev') == 'cfb':
            for fld in ('ctx_key_off8', 'ctx_key_off16'):
                if ev.get(fld):
                    kb = bytes.fromhex(ev[fld])
                    cands[f"cfbctx_{fld}_{kb[:4].hex()}"] = kb
            if ev.get('ctx'):
                h = bytes.fromhex(ev['ctx'])
                for off in (0, 8, 16, 24):
                    if len(h) >= off+16: cands[f"cfbctx_raw_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]
            if ev.get('reg_in'): ivs[f"cfb_reg_{ev['reg_in'][:8]}"] = bytes.fromhex(ev['reg_in'])
            # 直接对照: pt/ct 齐了就是完整四元组 — 立即结构验证
            if ev.get('pt') and ev.get('ct'):
                pt = bytes.fromhex(ev['pt'])
                rep = struct_report(pt)
                print(f"  [CFB-PAIR] dir={ev.get('dir')} len={ev.get('len')} pt_printable={rep['printable']} "
                      f"runs={rep.get('ascii_runs>=8', [])[:3]} markers={rep.get('markers')}")
        elif ev.get('ev') == 'ctr':
            if ev.get('ctx'):
                h = bytes.fromhex(ev['ctx'])
                for off in (8, 16): cands[f"ctrctx_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]
        elif ev.get('ev') == 'genenc' and ev.get('key32'):
            kb = bytes.fromhex(ev['key32'])
            cands[f"genenc32_{kb[:4].hex()}"] = kb[:16]
            cands[f"genenc16_{kb[:4].hex()}"] = kb[16:32] if len(kb) == 32 else kb[:16]
        elif ev.get('ev') == 'bss' and ev.get('hex'):
            h = bytes.fromhex(ev['hex'])
            if h != bytes(192):
                for off in (0, 8, 16, 24):
                    cands[f"bss_{ev.get('tag','?')}_off{off}_{h[off:off+4].hex()}"] = h[off:off+16]

    # ── 兜底: cecelia v2 旧格式 ──
    for m in re.finditer(r'SETB_KEYEXP[^\n]*\n\s*a1ptr=\S+ mem=([0-9a-f]+)', txt):
        cands.setdefault('legacy_keyexp_' + m.group(1)[:8], bytes.fromhex(m.group(1)[:32])[:16])
    for m in re.finditer(r'ctx_after_176B=([0-9a-f]{64,})', txt):
        h = bytes.fromhex(m.group(1))
        cands.setdefault('legacy_ctx_off8_' + h[8:12].hex(), h[8:24])
        cands.setdefault('legacy_ctx_off16_' + h[16:20].hex(), h[16:32])
    for m in re.finditer(r'\[KNOBS_BSS\][^\n]*?([0-9a-f]{384})', txt):
        h = bytes.fromhex(m.group(1))
        if h != bytes(192):
            cands.setdefault('legacy_bss_off8_' + h[8:12].hex(), h[8:24])
            cands.setdefault('legacy_bss_off16_' + h[16:20].hex(), h[16:32])

    # 去重
    uniq = {}
    for n, k in cands.items():
        if len(k) == 16: uniq.setdefault(k, n)
    print(f"[harvest] unique 16B key candidates: {len(uniq)}, iv candidates: {len(ivs)}")
    results = []
    for k, kn in sorted(uniq.items(), key=lambda x: x[1]):
        v = verify_key(k, quiet=True)
        hit = v['VERDICT'] == 'KEY-CONFIRMED'
        q = max((b.get('qimei36_hits', 0) for b in v['blobs']), default=0)
        pr = max(b['printable'] for b in v['blobs'])
        print(f"  [{'HIT ' if hit else '    '}] {kn} {k.hex()[:16]}…: qimei_hits={q} max_printable={pr:.2f}")
        if hit:
            for ivn, iv in list(ivs.items()) + [('zero', bytes(16))]:
                v2 = verify_key(k, iv, quiet=True)
                results.append((kn, k.hex(), ivn, iv.hex(), v2))
    if results:
        print("\n=== CONFIRMED (key, iv) pairs ===")
        for kn, kh, ivn, ivh, v in results:
            print(f"key={kh} ({kn}) iv={ivh} ({ivn})")
            print(json.dumps(v['blobs'], ensure_ascii=False)[:1200])
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['selftest', 'verify', 'harvest', 'enc', 'dec', 'ir'])
    ap.add_argument('--key'); ap.add_argument('--iv')
    ap.add_argument('--pt'); ap.add_argument('--ct')
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
        print(f"[selftest] cfb128 vs unidbg vector: {'PASS' if ok1 else 'FAIL'}")
        print(f"[selftest] roundtrip: {'PASS' if ok2 else 'FAIL'}")
        print(f"[selftest] no-iv decrypt(block1+): {'PASS' if ok3 else 'FAIL'}")
        sys.exit(0 if (ok1 and ok2 and ok3) else 1)

    if a.cmd == 'harvest':
        harvest(a.log); return

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
