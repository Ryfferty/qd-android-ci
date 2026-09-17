# Ghidra headless 后置脚本：反编译指定地址的函数
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
addrs = os.environ.get('TARGET_ADDRS', 'a7b8').split(',')
prog = getCurrentProgram()
dec = DecompInterface()
dec.openProgram(prog)
mon = ConsoleTaskMonitor()
fm = prog.getFunctionManager()
space = prog.getAddressFactory().getDefaultAddressSpace()
for a in addrs:
    a = a.strip()
    if not a:
        continue
    try:
        v = int(a, 16)
    except Exception:
        continue
    addr = space.getAddress(v)
    f = fm.getFunctionAt(addr)
    print('=' * 70)
    if f is None:
        # 尝试反汇编后再取
        try:
            disassemble(addr)
            f = createFunction(addr, None)
        except Exception:
            pass
    if f is None:
        print('### 0x%x : 未能识别为函数' % v)
        continue
    print('### 0x%x  %s  (%d bytes)' % (v, f.getName(), f.getBody().getNumAddresses()))
    r = dec.decompileFunction(f, 120, mon)
    if r and r.decompileCompleted():
        print(r.getDecompiledFunction().getC())
    else:
        print('### 反编译失败')
