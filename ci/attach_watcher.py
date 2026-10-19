#!/usr/bin/env python3
"""attach_watcher.py — R8: 常驻快速 attacher (472 keyhunt 线, 2026-10-19)

R7 postmortem (run 39200505484): SIGSTOP 冻结 → frida CLI "Failed to attach:
process not found"(frida-server 无法对冻结进程完成附身) ⇒ 冻结路线死;
frida CLI(含 Python 解释器启动) ~1-1.5s 使武装恒晚于 r 加密(+1.3~1.7s)。
本守护进程预载 frida 设备句柄与脚本源常驻: 捕到新 pid 后 attach+load
仅 ~0.3-0.6s —— 捕捉(+0.1~0.4s) + EARLY_DELAY(避 LSPlant init 窗) +
attach+load ⇒ armed 压在 r 加密(+1.3~1.7s)之前。
App anti-frida 自杀(exit(0), R6 实证)→JPush sticky 复活(~0.7-2.7s)→
再捕→再挂, 循环到 hold 耗尽; 每循环=一次新 r 加密捕获机会。

自适应延迟: 初始 800ms(避 LSPlant); 每轮无 cfb 事件则下探 200ms(逼近
r 加密窗), 连续 3 轮连 script_loaded 都没到(疑 LSPlant 崩)则回弹 400ms;
一旦 cfb>0 锁定当前延迟。

不做任何 am start(驱动器/D-看门狗的 skip-gate 与 JPush 复活负责启动);
只捕新 pid、附身、装载、等死。

用法: ci/attach_watcher.py <hold_secs> [old_pid_to_skip]
env: SPAWN_SCRIPT(默认 hook_r1_keyhunt_472.js) EARLY_DELAY_MS(默认 800)
     CFB_CHECK(默认 1: 自适应延迟开关)
输出: [ATTACH]/[R1KEY] 行追加 /tmp/keyhunt_collect.log(console.log 路由)
"""
import frida
import os
import subprocess
import sys
import threading
import time

HOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 4800
OLD = (sys.argv[2] if len(sys.argv) > 2 else '').strip()
APP = 'com.qidian.QDReader'
B = 'localhost:5555'
LOG = '/tmp/keyhunt_collect.log'
ADAPT = os.environ.get('CFB_CHECK', '1') == '1'
DELAY = float(os.environ.get('EARLY_DELAY_MS', '800')) / 1000.0
DELAY_MAX = 0.8
DELAY_MIN = 0.0
DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.environ.get('SPAWN_SCRIPT', 'hook_r1_keyhunt_472.js')
with open(os.path.join(DIR, SCRIPT), 'r') as f:
    JS = f.read()


def log(msg):
    with open(LOG, 'a') as f:
        f.write('[ATTACH] %d %s\n' % (int(time.time()), msg))


def pidof():
    try:
        out = subprocess.run(['adb', '-s', B, 'shell', 'pidof', APP],
                             capture_output=True, timeout=15).stdout.decode('utf-8', 'ignore')
        parts = out.split()
        return parts[0] if parts else ''
    except Exception:
        return ''


def cfb_total():
    try:
        with open(LOG, 'r', errors='ignore') as f:
            return sum(1 for line in f if '"ev":"cfb"' in line or '"ev": "cfb"' in line)
    except Exception:
        return 0


def js_alive(pid):
    """R10: 验证脚本真的在目标进程里跑起来了 (R9 教训: pid 4863 script.load() 返回
    成功但零 console 输出 = '僵尸装载', 该进程的 armed 状态不可信)。只扫日志尾部 64KB。"""
    try:
        with open(LOG, 'rb') as f:
            f.seek(0, 2)
            sz = f.tell()
            f.seek(max(0, sz - 65536))
            tail = f.read().decode('utf-8', 'ignore')
        return ('"ev":"script_loaded"' in tail or '"ev": "script_loaded"' in tail) \
            and ('"pid":%s,' % pid) in tail
    except Exception:
        return False


device = frida.get_device_manager().add_remote_device('127.0.0.1:14771')
deadline = time.time() + HOLD
log('fast watcher R8 up (hold=%ds script=%s early_delay=%.2fs adapt=%s skip_pid=%s)'
    % (HOLD, SCRIPT, DELAY, ADAPT, OLD))


def make_on_message(pid):
    def on_message(message, data):
        try:
            if message.get('type') == 'log':
                with open(LOG, 'a') as f:
                    f.write(str(message.get('payload', '')) + '\n')
            elif message.get('type') == 'error':
                with open(LOG, 'a') as f:
                    f.write('[R1KEY] script-error pid=%s %s\n'
                            % (pid, message.get('description', '')))
        except Exception:
            pass
    return on_message


seen = set()
if OLD:
    seen.add(OLD)
fail_streak = 0
while time.time() < deadline:
    pid = pidof()
    if not pid or pid in seen:
        time.sleep(0.12)
        continue
    seen.add(pid)
    t_catch = time.time()
    # EARLY_DELAY: 等 LSPlant init 窗(自适应)
    if DELAY > 0:
        end = t_catch + DELAY
        while time.time() < end and time.time() < deadline:
            time.sleep(min(0.1, max(0.0, end - time.time())))
    loaded = False
    try:
        session = device.attach(int(pid))
        script = session.create_script(JS)
        script.on('message', make_on_message(pid))
        detached = threading.Event()
        session.on('detached', lambda *a, **kw: detached.set())
        script.load()
        loaded = True
        # R10: 等真实 script_loaded 事件 (最多 6s) — 区分"真武装"与 R9 式僵尸装载
        t_alive = time.time()
        alive = False
        while time.time() - t_alive < 6:
            if js_alive(pid):
                alive = True
                break
            time.sleep(0.3)
        log('fast-attach pid=%s script_loaded ✓ (+%.2fs from catch, delay=%.2fs, js_alive=%s)'
            % (pid, time.time() - t_catch, DELAY, alive))
        dead_miss = 0
        while not detached.is_set() and time.time() < deadline:
            time.sleep(0.3)
            # R10: 挂死/换代会话检测 (R9 教训: 4863 挂满全程, watcher 干等 6 分钟) —
            # 每 ~2s 查一次 pidof: 新 pid 出现(进程换代但 detach 未触发) → 切换;
            # pid 消失且 16s 无 detach → 放弃该会话回主循环。
            if int(time.time() * 2) % 4 == 0:
                cur = pidof()
                if cur and cur != pid:
                    log('watch: pid %s 已被新 pid %s 替换(会话未detach) — 切换' % (pid, cur))
                    break
                if not cur:
                    dead_miss += 1
                    if dead_miss >= 8:
                        log('watch: pid %s 已死但会话未detach — 放弃, 回主循环' % pid)
                        break
                else:
                    dead_miss = 0
        if detached.is_set():
            log('session(pid=%s) detached — 等复活(检测自杀被吞/系统杀)' % pid)
    except frida.ProcessNotFoundError:
        log('fast-attach pid=%s: process not found (中途死, delay=%.2fs) — 继续捕' % (pid, DELAY))
    except Exception as e:
        log('fast-attach pid=%s failed: %s (+%.2fs, delay=%.2fs) — 继续'
            % (pid, str(e)[:100], time.time() - t_catch, DELAY))
    # 自适应延迟调节
    if ADAPT:
        if cfb_total() > 0:
            pass  # 已命中, 锁定当前延迟
        elif loaded:
            fail_streak = 0
            DELAY = max(DELAY_MIN, DELAY - 0.2)
            log('adaptive: 无cfb, 延迟下探→%.2fs' % DELAY)
        else:
            fail_streak += 1
            if fail_streak >= 3:
                DELAY = min(DELAY_MAX, DELAY + 0.4)
                fail_streak = 0
                log('adaptive: 连败3轮(疑LSPlant/早attach崩), 延迟回弹→%.2fs' % DELAY)
log('fast watcher exit (hold 耗尽)')
