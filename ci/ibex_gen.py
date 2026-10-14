#!/usr/bin/env python3
"""ibex_gen.py — ibex风控令牌纯Python生成 ★libnib三件套合体★

链路(AsyncMainYWLoginSDKTask→search.cihai→NativeWrapper.a=lk):
  1. 设备安全档案JSON(mmr从filesDir+/c读,默认{}) →
  2. judian(): 按Subscript 64项索引展开数组 →
  3. join('|') →
  4. lk()加密 → ibex

全部算法来自libnib(已100%破解): StringArmor解密+lk()
"""
import json, sys, time, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lk_full import lk

# Subscript 64项(索引→JSON键名, 源码定案)
# bool型字段: search()返回'1'(true)/'0'(false)
FIELDS = [
    ('obs_pluginCharacter',                      'str'),   # 0之上是VERSION='5'
    ('obs_androidboot.hardware',                'str'),   # 3
    ('obs_ro.setupwizard.mode',                 'str'),   # 4
    ('obs_ro.secureboot.lockstate',             'str'),   # 5
    ('obs_ro.boot.flash.locked',                'str'),   # 6
    ('obs_vendor.boot.vbmeta.device_state',     'str'),   # 7
    ('obs_vendor.boot.verifiedbootstate',       'str'),   # 8
    ('obs_ro.boot.vbmeta.device_state',         'str'),   # 9
    ('obs_sys.oem_unlock_allowed',              'str'),   # 10
    ('obs_sys.locksettings.remoteauth.enable',  'str'),   # 11
    ('obs_countCAS',                            'str_def0'), # 12 default'0'
    ('obs_isCheckZygiskByMap',                  'bool'),  # 13
    ('obs_propSerial',                          'str'),   # 14
    ('obs_isXposedByClass',                     'bool'),  # 15
    ('obs_isXposedByStack',                     'bool'),  # 16
    ('obs_isXposedByMaps',                      'bool'),  # 17
    ('obs_isXposedByCAS',                       'bool'),  # 18
    ('obs_isPatchByResourcePath',               'bool'),  # 19
    ('obs_isRootByPath',                        'bool'),  # 20
    ('obs_isRootByPackageName',                 'bool'),  # 21
    ('obs_isRootByMagisk',                      'bool'),  # 22
    ('obs_isRootByAttr',                        'bool'),  # 23
    ('obs_androidboot.verifiedstate',           'str'),   # 24
    ('obs_isAccessibilityEnable',               'bool'),  # 25
    ('obs_isAutoJsByAccessibility',             'bool'),  # 26
    ('obs_isFridaByPort',                       'bool'),  # 27
    ('obs_isFridaByFd',                         'bool'),  # 28
    ('obs_isFridaByTask',                       'bool'),  # 29
    ('obs_isInlineByFuncsArm',                  'bool'),  # 30
    ('obs_isEmulatorByCpuInfo',                 'bool'),  # 31
    ('obs_isEmulatorByFile',                    'bool'),  # 32
    ('obs_isEmulatorByEth0',                    'bool'),  # 33
    ('obs_isMultiBoxByPkg',                     'bool'),  # 34
    ('obs_isMultiBoxByFileStr',                 'bool'),  # 35
    ('obs_isMultiBoxByParentDir',               'bool'),  # 36
    ('obs_isMultiBoxByUid',                     'bool'),  # 37
    ('obs_isUiAutomatorByPkg',                  'bool'),  # 38
    ('obs_isAppToolByPkg',                      'bool'),  # 39
    ('obs_isScrcpyByNetStat',                   'bool'),  # 40
    ('obs_isAdbBySystemProperties',             'bool'),  # 41
    ('obs_isVMOSByWifi',                        'bool'),  # 42
    ('obs_isVMOSByPackageName',                 'bool'),  # 43
    ('obs_isVMOSByProperty',                    'bool'),  # 44
    ('obs_isAtx',                               'bool'),  # 45
    ('obs_deviceModel',                         'str'),   # 46
    ('obs_deviceBrand',                         'str'),   # 47
    ('obs_deviceBoard',                         'str'),   # 48
    ('obs_deviceManufacturer',                  'str'),   # 49
    ('obs_deviceHost',                          'str'),   # 50
    ('obs_deviceCPU_ABI',                       'str'),   # 51
    ('obs_deviceCPU_ABI2',                      'str'),   # 52
    ('guid',                                    'str'),   # 53
    ('qimei',                                   'str'),   # 54
    ('qimei36',                                 'str'),   # 55
    ('platform',                                'str_def_android'), # 56
    ('obs_packageName',                         'str'),   # 57
    ('obs_devicePartsHash',                     'str'),   # 58
    ('obs_hasSuspiciousDylib',                  'str'),   # 59
    ('obs_signatureMd5FromSvc',                 'str'),   # 60
    ('__HOST_APP_VERSION__',                    'hav'),   # 61 = NativeWrapper.hav()
    ('obs_isLspByStack',                        'bool'),  # 62
    ('obs_loadLib',                             'str'),   # 63
]

# Subscript.index→上表偏移: [0]VERSION [1]TIMESTAMP 是头两项(非JSON字段)
# FIELDS[i] 对应 Subscript index = i+2


def build_device_json(qimei16, qimei36, imei=None, model="23127PN0CC",
                      brand="Xiaomi", board="pangu", manufact="Xiaomi",
                      host="pangu", cpu_abi="arm64-v8a", cpu_abi2="armeabi-v7a",
                      guid="", package="com.qidian.QDReader",
                      plugin_char="", serial=""):
    """构造干净设备的档案JSON(等价mmr读到的/c文件)"""
    return {
        "obs_pluginCharacter": plugin_char,
        "obs_androidboot.hardware": "qcom",
        "obs_ro.setupwizard.mode": "1",
        "obs_ro.secureboot.lockstate": "locked",
        "obs_ro.boot.flash.locked": "1",
        "obs_vendor.boot.vbmeta.device_state": "locked",
        "obs_vendor.boot.verifiedbootstate": "green",
        "obs_ro.boot.vbmeta.device_state": "locked",
        "obs_sys.oem_unlock_allowed": "0",
        "obs_sys.locksettings.remoteauth.enable": "0",
        "obs_countCAS": "0",
        "obs_isCheckZygiskByMap": False,
        "obs_propSerial": serial,
        "obs_isXposedByClass": False,
        "obs_isXposedByStack": False,
        "obs_isXposedByMaps": False,
        "obs_isXposedByCAS": False,
        "obs_isPatchByResourcePath": False,
        "obs_isRootByPath": False,
        "obs_isRootByPackageName": False,
        "obs_isRootByMagisk": False,
        "obs_isRootByAttr": False,
        "obs_androidboot.verifiedstate": "green",
        "obs_isAccessibilityEnable": False,
        "obs_isAutoJsByAccessibility": False,
        "obs_isFridaByPort": False,
        "obs_isFridaByFd": False,
        "obs_isFridaByTask": False,
        "obs_isInlineByFuncsArm": False,
        "obs_isEmulatorByCpuInfo": False,
        "obs_isEmulatorByFile": False,
        "obs_isEmulatorByEth0": False,
        "obs_isMultiBoxByPkg": False,
        "obs_isMultiBoxByFileStr": False,
        "obs_isMultiBoxByParentDir": False,
        "obs_isMultiBoxByUid": False,
        "obs_isUiAutomatorByPkg": False,
        "obs_isAppToolByPkg": False,
        "obs_isScrcpyByNetStat": False,
        "obs_isAdbBySystemProperties": False,
        "obs_isVMOSByWifi": False,
        "obs_isVMOSByPackageName": False,
        "obs_isVMOSByProperty": False,
        "obs_isAtx": False,
        "obs_deviceModel": model,
        "obs_deviceBrand": brand,
        "obs_deviceBoard": board,
        "obs_deviceManufacturer": manufact,
        "obs_deviceHost": host,
        "obs_deviceCPU_ABI": cpu_abi,
        "obs_deviceCPU_ABI2": cpu_abi2,
        "guid": guid,
        "qimei": qimei16,
        "qimei36": qimei36,
        "platform": "android",
        "obs_packageName": package,
        "obs_devicePartsHash": "",
        "obs_hasSuspiciousDylib": "",
        "obs_signatureMd5FromSvc": "",
        "obs_isLspByStack": False,
        "obs_loadLib": "",
    }


def judian(j, ts_ms=None, hav="7.9.480"):
    """展开64项数组(=search.judian)"""
    arr = [""] * 64
    arr[0] = "5"                        # VERSION(judian常量)
    arr[1] = str(ts_ms or int(time.time() * 1000))  # TIMESTAMP
    for i, (key, typ) in enumerate(FIELDS):
        idx = i + 2
        if typ == 'bool':
            arr[idx] = "1" if j.get(key, False) else "0"
        elif typ == 'str_def0':
            arr[idx] = str(j.get(key, "0") or "0")
        elif typ == 'str_def_android':
            arr[idx] = str(j.get(key, "android") or "android")
        elif typ == 'hav':
            arr[idx] = hav              # NativeWrapper.hav()
        else:
            v = j.get(key, "")
            arr[idx] = str(v) if v is not None else ""
    return arr


def gen_ibex(device_json=None, ts_ms=None, hav="7.9.480", **dev_kwargs):
    """ibex = lk(join('|', judian(json))) — 三库算法合体"""
    j = device_json or build_device_json(**dev_kwargs)
    arr = judian(j, ts_ms=ts_ms, hav=hav)
    joined = "|".join(arr)
    return lk(joined)


if __name__ == '__main__':
    # 测试: 新qimei的干净设备!
    qimei36 = "78e6826613361d862355760010001481aa0d"
    ibex = gen_ibex(qimei16=qimei36[:16], qimei36=qimei36)
    print(f"ibex({len(ibex)}ch): {ibex[:60]}...")
    print(f"\n★ ibex生成器就绪! (StringArmor+lk双100%算法)")
    # 打印字段布局!
    j = build_device_json(qimei16=qimei36[:16], qimei36=qimei36)
    arr = judian(j)
    for i, v in enumerate(arr):
        name = FIELDS[i-2][0] if 2 <= i < 64 else ['VERSION','TIMESTAMP'][i]
        print(f"  [{i:2d}] {name:40s} = {v[:30]}")
