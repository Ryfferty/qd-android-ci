#!/usr/bin/env python3
"""ibex_gen_v2.py — ibex 风控头从零生成器 (2026-10-15, 取代 ibex_template.py 模板改写法)

═══ 结构定案(源码+438真值样本双证) ═══
链路: search.cihai(ctx)  [com.yuewen.nib, classes10.dex]
  1. mmr(filesDir+"/c") → 64KB加密档案(libknobs采集写入, vh/a.java→NativeWrapper.a(ctx,json))
     缺失/坏 → fallback '{}'
  2. judian(json) → String[64] (Subscript枚举索引)
  3. TextUtils.join('|') → NativeWrapper.a() = URLSAFE|NO_WRAP Base64(lk(bytes))

64字段 = [0]'5'常量 + [1]System.currentTimeMillis() + 29个optString + 32个bool('1'/'0')
       + [61]NativeWrapper.hav()(libnib烧录值, arm64-480='7.9.480', v7a='7.9.472')
默认值: [12]COUNT_CAS缺省'0', [56]PLATFORM缺省'android', bool缺省'0', 其余''。

═══ 长度档定案(438样本全验证) ═══
明文长N → lk()双层加密, 每层PKCS#7。cipher由crc2=CRC32(hexpart)分派:
  c1 = DES if crc2&1 else AES;  c2 = DES if (crc2>>4)&1 else AES
hexpart=H2(H2(H1(pt))), H由CRC32(pt)分派{MD2,MD4,MD5} ⇒ 明文含ms时间戳 ⇒ 档位准随机。
  N=124(空档案):  DES→128, AES→128 (c1无关); c2=DES→136+32→b64=224, c2=AES→144+32→236
  N=354(redroid全档案,guid=''): c1=DES→360(c2任意→368)→400→536; AES→368; c2=DES→376→408→544; c2=AES→384→416→556
  N=366(全档案+12位guid): DES/AES都→368; c2=DES→544, c2=AES→556 (536不可能!)
∴ 536/544/556差异不是字段引起, 是CRC32密码分派; 字段只决定明文长度N。
概率: P(536)=1/2, P(544)=P(556)=1/4 (N=354); 实测167:106:100 ✓

═══ 状态字段结论(问题4答案, 详见RECON/ibex_field_map_full.md) ═══
- 64字段中【没有】firstInstall/注册态/冷启动计数/安装时间/累计登录字段。
- 唯一时间字段=[1]当前ms; 唯一登录态字段=[53]GUID(登录后≈3s内被knobs写为ywguid, 新设备='')。
- COUNT_CAS[12]=4 在全新安装与登录老设备完全相同(常量, 非累计)。
- App冷启动前~2s /c未写入 → ibex=空档案(124B/224|236ch), ptlogin注册链SDK-init会缓存此ibex复用。
"""
import base64
import json
import os
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lk_full import lk  # noqa: E402  (83/83验证的lk纯Python)

# ── Subscript枚举64项 (classes10/sources/com/yuewen/nib/Subscript.java 定案) ──
# type: 'const'|'ts'|'hav'|'str'|'str0'(缺省'0')|'stra'(缺省'android')|'bool'
SUBSCRIPT = [
    (0,  'VERSION',                        'const'),
    (1,  'TIMESTAMP',                      'ts'),
    (2,  'PLUGIN_CHARACTER',               'str'),    # obs_pluginCharacter
    (3,  'ANDROIDBOOT_HARDWARE',           'str'),    # getprop androidboot.hardware
    (4,  'RO_SETUPWIZARD_MODE',            'str'),
    (5,  'RO_SECUREBOOT_LOCKSTATE',        'str'),
    (6,  'RO_BOOT_FLASH_LOCKED',           'str'),
    (7,  'VENDOR_BOOT_VBMETA_DEVICE_STATE','str'),
    (8,  'VENDOR_BOOT_VERIFIEDBOOTSTATE',  'str'),
    (9,  'RO_BOOT_VBMETA_DEVICE_STATE',    'str'),
    (10, 'SYS_OEM_UNLOCK_ALLOWED',         'str'),
    (11, 'SYS_LOCKSETTINGS_REMOTEAUTH_ENABLE', 'str'),
    (12, 'COUNT_CAS',                      'str0'),   # obs_countCAS, JSON缺省'0'
    (13, 'IS_CHECK_ZYGISK_BY_MAP',         'bool'),
    (14, 'PROP_SERIAL',                    'str'),    # ro.serialno
    (15, 'IS_XPOSED_BY_CLASS',             'bool'),
    (16, 'IS_XPOSED_BY_STACK',             'bool'),
    (17, 'IS_XPOSED_BY_MAPS',              'bool'),
    (18, 'IS_XPOSED_BY_CAS',               'bool'),
    (19, 'IS_PATCH_BY_RESOURCE_PATH',      'bool'),
    (20, 'IS_ROOT_BY_PATH',                'bool'),
    (21, 'IS_ROOT_BY_PACKAGE_NAME',        'bool'),
    (22, 'IS_ROOT_BY_MAGISK',              'bool'),
    (23, 'IS_ROOT_BY_ATTR',                'bool'),
    (24, 'ANDROIDBOOT_VERIFIEDSTATE',      'str'),
    (25, 'IS_ACCESSIBILITY_ENABLE',        'bool'),
    (26, 'IS_AUTO_JS_BY_ACCESSIBILITY',    'bool'),
    (27, 'IS_FRIDA_BY_PORT',               'bool'),
    (28, 'IS_FRIDA_BY_FD',                 'bool'),
    (29, 'IS_FRIDA_BY_TASK',               'bool'),
    (30, 'IS_INLINE_BY_FUNCS_ARM',         'bool'),
    (31, 'IS_EMULATOR_BY_CPU_INFO',        'bool'),
    (32, 'IS_EMULATOR_BY_FILE',            'bool'),
    (33, 'IS_EMULATOR_BY_ETH0',            'bool'),
    (34, 'IS_MULTI_BOX_BY_PKG',            'bool'),
    (35, 'IS_MULTI_BOX_BY_FILE_STR',       'bool'),
    (36, 'IS_MULTI_BOX_BY_PARENT_DIR',     'bool'),
    (37, 'IS_MULTI_BOX_BY_UID',            'bool'),
    (38, 'IS_UIAUTOMATOR_BY_PKG',          'bool'),
    (39, 'IS_APP_TOOL_BY_PKG',             'bool'),
    (40, 'IS_SCRCPY_BY_NET_STAT',          'bool'),
    (41, 'IS_ADB_BY_SYSTEM_PROPERTIES',    'bool'),
    (42, 'IS_VMOS_BY_WIFI',                'bool'),
    (43, 'IS_VMOS_BY_PACKAGE_NAME',        'bool'),
    (44, 'IS_VMOS_BY_PROPERTY',            'bool'),
    (45, 'IS_ATX',                         'bool'),
    (46, 'DEVICE_MODEL',                   'str'),    # 'MODEL (PRODUCT)'格式
    (47, 'DEVICE_BRAND',                   'str'),
    (48, 'DEVICE_BOARD',                   'str'),
    (49, 'DEVICE_MANUFACTURER',            'str'),
    (50, 'DEVICE_HOST',                    'str'),
    (51, 'DEVICE_CPU_ABI',                 'str'),
    (52, 'DEVICE_CPU_ABI2',                'str'),    # API21+恒''
    (53, 'GUID',                           'str'),    # ywguid; 未登录=''
    (54, 'QIMEI',                          'str'),    # /c里'qimei'键; 实测=qimei36值!
    (55, 'QIMEI36',                        'str'),
    (56, 'PLATFORM',                       'stra'),   # 缺省'android'
    (57, 'PACKAGE_NAME',                   'str'),
    (58, 'DEVICE_HASH',                    'str'),    # obs_devicePartsHash(native算, 镜像级常量)
    (59, 'HAS_SUSPICIOUS_DYLIB',           'str'),
    (60, 'SIGNATURE_MD5_FROM_SVC',         'str'),    # APK签名MD5(服务端下发常量)
    (61, 'HOST_APP_VERSION',               'hav'),    # libnib hav()烧录值
    (62, 'IS_LSP_BY_STACK',                'bool'),
    (63, 'LOAD_LIB',                       'str'),
]
FIELD_NAMES = [n for _, n, _ in SUBSCRIPT]

# ── redroid11_arm64 (CI真机, 438样本实证) 设备常量 ──
REDROID = dict(
    model='redroid11_arm64 (redroid_arm64)',   # MODEL (PRODUCT)
    brand='redroid', board='unknown', manufacturer='redroid', host='build0',
    cpu_abi='arm64-v8a', cpu_abi2='', serial='00000001',
    device_hash='fbf2d18bafd7967bec86a04c513f06b4',      # 镜像级常量(全部5台redroid qimei相同)
    signature_md5='adf3951748a3ecbc6ff8f5b62a4337da',    # q480 APK签名MD5(全设备相同)
    count_cas='4',
    # redroid诚实风控态(真App在redroid上实测输出, 服务端接受):
    flags=dict(root_by_path=1, emulator_by_eth0=1, adb_by_system_properties=1),
    props=dict(),  # redroid上[3..11]/[24]全空
)
HAV_480_ARM64 = '7.9.480'   # arm64 libnib烧录; v7a为'7.9.472'
PACKAGE = 'com.qidian.QDReader'

_BOOL_KEYS = {  # profile['flags']键名 → 字段索引
    'check_zygisk_by_map': 13, 'xposed_by_class': 15, 'xposed_by_stack': 16,
    'xposed_by_maps': 17, 'xposed_by_cas': 18, 'patch_by_resource_path': 19,
    'root_by_path': 20, 'root_by_package_name': 21, 'root_by_magisk': 22,
    'root_by_attr': 23, 'accessibility_enable': 25, 'auto_js_by_accessibility': 26,
    'frida_by_port': 27, 'frida_by_fd': 28, 'frida_by_task': 29,
    'inline_by_funcs_arm': 30, 'emulator_by_cpu_info': 31, 'emulator_by_file': 32,
    'emulator_by_eth0': 33, 'multi_box_by_pkg': 34, 'multi_box_by_file_str': 35,
    'multi_box_by_parent_dir': 36, 'multi_box_by_uid': 37, 'ui_automator_by_pkg': 38,
    'app_tool_by_pkg': 39, 'scrcpy_by_net_stat': 40, 'adb_by_system_properties': 41,
    'vmos_by_wifi': 42, 'vmos_by_package_name': 43, 'vmos_by_property': 44,
    'atx': 45, 'lsp_by_stack': 62,
}
_PROP_IDX = {'androidboot_hardware': 3, 'setupwizard_mode': 4, 'secureboot_lockstate': 5,
             'boot_flash_locked': 6, 'vendor_vbmeta_device_state': 7,
             'vendor_verifiedbootstate': 8, 'boot_vbmeta_device_state': 9,
             'oem_unlock_allowed': 10, 'remoteauth_enable': 11, 'verifiedstate': 24}


def judian(p, ts_ms=None):
    """64字段展开(=search.judian语义)。p: 设备档案dict; ts_ms缺省=now。"""
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    arr = [''] * 64
    arr[0] = p.get('version_const', '5')
    arr[1] = str(ts_ms)
    arr[12] = str(p.get('count_cas', '0') or '0')
    arr[14] = p.get('serial', '')
    arr[2] = p.get('plugin_character', '')
    arr[46] = p.get('model', '')
    arr[47] = p.get('brand', '')
    arr[48] = p.get('board', '')
    arr[49] = p.get('manufacturer', '')
    arr[50] = p.get('host', '')
    arr[51] = p.get('cpu_abi', '')
    arr[52] = p.get('cpu_abi2', '')
    arr[53] = p.get('guid', '')
    arr[54] = p.get('qimei', '')
    arr[55] = p.get('qimei36', '')
    arr[56] = p.get('platform', 'android') or 'android'
    arr[57] = p.get('package', '')  # optString无默认: 空档案('{}')时=''
    arr[58] = p.get('device_hash', '')
    arr[59] = p.get('has_suspicious_dylib', '')
    arr[60] = p.get('signature_md5', '')
    arr[61] = p.get('hav', HAV_480_ARM64)
    for k, idx in _BOOL_KEYS.items():
        arr[idx] = '1' if p.get('flags', {}).get(k, 0) else '0'
    for k, idx in _PROP_IDX.items():
        arr[idx] = p.get('props', {}).get(k, '')
    return arr


def joined(p, ts_ms=None):
    return '|'.join(judian(p, ts_ms))


def gen_ibex(p, ts_ms=None, target_len=None, ts_search_span=20000):
    """ibex = Base64(lk(join('|', judian)))。
    target_len∈{224,236,536,544,556}: 在ts_ms附近搜ms值命中指定长度档(档位由CRC分派,准随机)。"""
    if target_len is None:
        return lk(joined(p, ts_ms))
    t0 = ts_ms if ts_ms is not None else int(time.time() * 1000)
    for dt in range(ts_search_span):
        for t in ({t0 + dt, t0 - dt} if dt else {t0}):
            s = lk(joined(p, t))
            if len(s) == target_len:
                return s
    raise RuntimeError(f'no ts within ±{ts_search_span}ms hits len {target_len}')


def profile_empty():
    """App冷启动前~2s(knobs未写/c)的真值形态: mmr失败→'{}'→全默认。65样本实证。"""
    return {'count_cas': '0'}


def profile_redroid(qimei36, qimei=None, guid='', **over):
    """redroid CI全新设备档案(226条fresh-install真值同款)。guid: 登录后填ywguid。"""
    p = dict(REDROID)
    p.update(dict(qimei36=qimei36, qimei=qimei or qimei36, guid=guid,
                  package=PACKAGE, hav=HAV_480_ARM64))
    p['flags'] = dict(REDROID['flags'])
    p['props'] = dict(REDROID['props'])
    for k, v in over.items():
        if k in ('flags', 'props'):
            p[k].update(v)
        else:
            p[k] = v
    return p


def profile_clean_phone(qimei36, model, brand, board, manufacturer, host,
                        serial, qimei=None, guid='', cpu_abi='arm64-v8a',
                        device_hash='', signature_md5=REDROID['signature_md5'],
                        **over):
    """零售真机档案(★无真机ibex语料, 按redroid形态外推, 未经字节级验证★)。
    风控flag全0, bootloader锁态prop给正品值。device_hash算法在libknobs native未逆,
    真机值未知——留空或抓真机/c解密(nib_mmr.py)。"""
    p = dict(model=f'{model}' if '(' in model else model, brand=brand, board=board,
             manufacturer=manufacturer, host=host, cpu_abi=cpu_abi, cpu_abi2='',
             serial=serial, qimei36=qimei36, qimei=qimei or qimei36, guid=guid,
             package=PACKAGE, hav=HAV_480_ARM64, count_cas='4',
             device_hash=device_hash, signature_md5=signature_md5,
             flags={},  # 零售机全0
             props={'boot_flash_locked': '1', 'vendor_vbmeta_device_state': 'locked',
                    'vendor_verifiedbootstate': 'green', 'boot_vbmeta_device_state': 'locked',
                    'secureboot_lockstate': 'locked', 'oem_unlock_allowed': '0',
                    'remoteauth_enable': '0'})
    p.update(over)
    return p


# ── 解码(验收/分析用) ──
def lk_decode(b64):
    from Crypto.Cipher import AES, DES
    data = base64.b64decode(b64.replace('-', '+').replace('_', '/'))
    binary, key = data[:-32], data[-32:]
    crc2 = zlib.crc32(key)
    c2 = DES.new(key[:8], DES.MODE_CBC, iv=key[:8]) if (crc2 >> 4) & 1 else \
        AES.new(key[:32], AES.MODE_CBC, iv=key[:16])
    inter_raw = c2.decrypt(binary)
    inter = inter_raw[:-inter_raw[-1]]
    c1 = DES.new(key[:8], DES.MODE_CBC, iv=key[:8]) if crc2 & 1 else \
        AES.new(key[:32], AES.MODE_CBC, iv=key[:16])
    padded = c1.decrypt(inter)
    return padded[:-padded[-1]]


def parse_ibex(b64):
    pt = lk_decode(b64)
    f = pt.split(b'|')
    assert len(f) == 64, f'field count {len(f)}'
    return {FIELD_NAMES[i]: f[i].decode('utf-8', 'replace') for i in range(64)}


def predict_len(pt_len, c1, c2):
    """明文长+密码组合 → ibex字符长(档位公式)。"""
    def pad(n, b):
        return n + (b - n % b if n % b else b)
    n = pad(pt_len, 8 if c1 == 'DES' else 16)
    n = pad(n, 8 if c2 == 'DES' else 16)
    return 4 * -(-(n + 32) // 3)


def profile_from_decoded(d):
    """解码字段 → 生成器profile参数(逆映射, 验收用)。"""
    flags = {}
    inv = {v: k for k, v in _BOOL_KEYS.items()}
    for i in range(64):
        if i in inv and d[FIELD_NAMES[i]] == '1':
            flags[inv[i]] = 1
    props = {}
    invp = {v: k for k, v in _PROP_IDX.items()}
    for i in range(64):
        if i in invp and d[FIELD_NAMES[i]] != '':
            props[invp[i]] = d[FIELD_NAMES[i]]
    return dict(version_const=d['VERSION'], count_cas=d['COUNT_CAS'],
                serial=d['PROP_SERIAL'], plugin_character=d['PLUGIN_CHARACTER'],
                model=d['DEVICE_MODEL'], brand=d['DEVICE_BRAND'], board=d['DEVICE_BOARD'],
                manufacturer=d['DEVICE_MANUFACTURER'], host=d['DEVICE_HOST'],
                cpu_abi=d['DEVICE_CPU_ABI'], cpu_abi2=d['DEVICE_CPU_ABI2'],
                guid=d['GUID'], qimei=d['QIMEI'], qimei36=d['QIMEI36'],
                platform=d['PLATFORM'], package=d['PACKAGE_NAME'],
                device_hash=d['DEVICE_HASH'], has_suspicious_dylib=d['HAS_SUSPICIOUS_DYLIB'],
                signature_md5=d['SIGNATURE_MD5_FROM_SVC'], hav=d['HOST_APP_VERSION'],
                flags=flags, props=props)


# ── 全语料验收: 解真值→profile→重编码→逐字节比对 ──
def _find_ibex(obj):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() == 'ibex' and isinstance(v, str) and len(v) > 100:
                out.append(v)
            else:
                out += _find_ibex(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _find_ibex(v)
    return out


def verify_corpus(verbose=False):
    import re
    R = '/home/ryz/projects/qidian'
    srcs = []
    d = json.load(open(f'{R}/evidence/mitm-login-38600816609/headers_extract.json'))
    srcs += [('mitm-login-K', v) for v in _find_ibex(d)]
    d = json.load(open(f'{R}/qd-android-ci/collected_risk_materials.json'))
    for run in d['runs']:
        srcs += [(f"fresh-{run['run_id']}", v) for v in _find_ibex(run)]
    d = json.load(open(f'{R}/qidian_auto/evidence/ostar-sign/cecelia_samples.json'))
    srcs += [('cecelia-d4da', v) for v in _find_ibex(d)]
    d = json.load(open(f'{R}/qidian_auto/ci/r1_all_flows.json'))
    srcs += [('r1_all_flows', v) for v in _find_ibex(d)]
    for p in [f'{R}/qidian_auto/sessions/qr_e3_ibex_probe.json',
              f'{R}/qidian_auto/evidence/qr_register_real_ibex_test.log']:
        if os.path.exists(p):
            s = open(p, errors='ignore').read()
            srcs += [(os.path.basename(p), m) for m in
                     re.findall(r'"?ibex"?\s*[:=]\s*"([A-Za-z0-9_\-]{100,600}={0,2})"', s)]

    ok = fail = 0
    from collections import Counter
    tiers = Counter()
    for corpus, ib in srcs:
        try:
            dec = parse_ibex(ib)
            prof = profile_from_decoded(dec)
            ts = int(dec['TIMESTAMP'])
            rebuilt = lk(joined(prof, ts))
            tiers[(len(lk_decode(ib)), len(ib))] += 1
            if rebuilt == ib:
                ok += 1
            else:
                fail += 1
                if verbose:
                    print(f'FAIL {corpus} len={len(ib)} ts={ts}')
        except Exception as e:
            fail += 1
            if verbose:
                print(f'ERR {corpus}: {e}')
    print(f'验收: {ok}/{ok + fail} byte-exact  tiers(pt_len,ibex_len)={dict(tiers)}')
    return ok, fail


if __name__ == '__main__':
    if '--verify' in sys.argv:
        ok, fail = verify_corpus(verbose=True)
        sys.exit(0 if fail == 0 else 1)
    # demo: redroid全新设备 + 空档案 + 指定长度档
    q36 = sys.argv[1] if len(sys.argv) > 1 else '864cc236f463a93cf5ad6ae4100018d1aa04'
    for name, prof in [('empty(冷启动0-2s)', profile_empty()),
                       ('redroid-fresh(全新安装)', profile_redroid(q36)),
                       ('redroid-login(已登录)', profile_redroid(q36, guid='900074427064'))]:
        ib = gen_ibex(prof)
        d = parse_ibex(ib)
        print(f'{name:24s} len={len(ib):3d} pt={len(lk_decode(ib)):3d} '
              f'q36={d["QIMEI"][:12]}… guid={d["GUID"]!r} cas={d["COUNT_CAS"]}')
    ib536 = gen_ibex(profile_redroid(q36), target_len=536)
    ib556 = gen_ibex(profile_redroid(q36), target_len=556)
    print(f'target_len=536 → {len(ib536)}; target_len=556 → {len(ib556)}')
