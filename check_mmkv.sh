#!/usr/bin/env bash
B=localhost:5555
echo "=== MMKV 目录 ==="
adb -s $B shell "ls -la /data/data/com.qidian.QDReader/files/mmkv/ 2>/dev/null"
echo
echo "=== pref_utils 里的 pref_fock_key 周边（十六进制+可打印）==="
adb -s $B shell "cat /data/data/com.qidian.QDReader/files/mmkv/pref_utils 2>/dev/null" > /tmp/pref_utils.bin
ls -la /tmp/pref_utils.bin
python3 - <<'PYEOF'
d = open('/tmp/pref_utils.bin','rb').read()
print('大小', len(d))
i = d.find(b'pref_fock_key')
print('pref_fock_key 偏移', i)
if i >= 0:
    seg = d[i:i+400]
    print('--- 该段可打印字符 ---')
    import re
    for m in re.finditer(rb'[\x20-\x7e]{6,}', seg):
        print('  @%d: %s' % (m.start(), m.group().decode('ascii','replace')))
    print('--- 十六进制前 160 字节 ---')
    print(' ', d[i:i+160].hex())
PYEOF
echo
echo "=== 找 JSON 形态的键值对 ==="
python3 - <<'PYEOF'
import re
d = open('/tmp/pref_utils.bin','rb').read()
for m in re.finditer(rb'\{[^{}]{0,200}\}', d):
    print('  JSON@%d: %s' % (m.start(), m.group().decode('utf-8','replace')[:200]))
PYEOF
