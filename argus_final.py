#!/usr/bin/env python3
# argus_final.py — 用【设备真实身份】取 Key + 密文（纯协议）
# 用法: Q16=<设备真实QIMEI16> python3 argus_final.py
import os, sys
# 注入身份后再调用原脚本
q16 = os.environ.get('Q16') or os.environ.get('DEV_ANDROID_ID') or ''
if not q16:
    print('缺少 Q16（设备真实 QIMEI16）'); sys.exit(1)
os.environ['DEV_ANDROID_ID'] = q16      # ← QDInfo 的 Q 字段
os.environ.setdefault('DEV_IMEI', q16)
os.environ.setdefault('DEV_MODEL', 'redroid11_arm64')
print('使用身份: Q=%s IMEI=%s MODEL=%s' % (os.environ['DEV_ANDROID_ID'], os.environ['DEV_IMEI'], os.environ['DEV_MODEL']))
sys.argv = ['argus_fetch.py']
exec(compile(open('argus_fetch.py').read(), 'argus_fetch.py', 'exec'))
