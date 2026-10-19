#!/bin/bash
# attach_qd.sh — R8: 首挂(bash 慢速安全) + 常驻快速 attacher(python 守护) (472 LSPatch 线, 2026-10-19)
# 历史(逐轮实证):
#   R4: 首启 LSPatch 解包竞态自崩(pm clear 后每次首启必崩一次, 二启踩落盘解包即活),
#       门控无重试=死锁 → R5 加重试环(见 attach_qd.sh.bak.r5.20261019)。
#   R5(39144212644)/R6(39148639350):
#     - 重试环工作: attempt1 吃首崩, attempt2 活 — 保留。
#     - R6 禁 canary 直调自杀后活窗找回, 但 cfb=0 真因浮出:
#       ① r 的 i/r 加密在每个进程启动 +1.3~2.2s 一次性发生(先于任何 attach);
#       ② 主进程在业务 init 期**反 frida 静默自杀 exit(0)**(R6 logcat 铁证:
#         "Process 2069 exited cleanly (0)"=点同意后65ms; "Process 2723 exited
#         cleanly (0)"=attach后~2.3s; 无 tombstone/ANR);
#       ③ JPush sticky 服务 ~0.7-2.7s 自动复活("Start proc … for service
#         JPushExtendService"), **复活进程在 +1.3~1.7s 重算新 r 上 wire**。
#     ⇒ 自杀→复活循环 = 无限次 r 加密捕获机会, 谁能在复活进程 +1.3s 前武装钩谁赢。
#   R6b(A4 未提交版, 本文件前版): watcher 思路对但 pid 轮询 1s+沉淀 0.4s+CLI ~1s
#     ⇒ 钩就绪 +1.5~3s 恒输 r 加密 +1.3~1.7s。
# R7(本版) = R6b watcher + **冻结注入**:
#   复活/新进程在设备内 pidof@50ms 捕捉 → 出生即 kill -STOP(app 时钟不走) →
#   冻结态起 frida 会话(ptrace 注入与脚本装载在冻住的目标上完成, script_loaded
#   探测即武装完成判据) → kill -CONT → app 恢复时钩已全挂 → r 加密(+1.3~2.2s)被
#   cfb 挂点捕获 → 随后 anti-frida 自杀 → 会话死 → watcher 等下一个复活 → 循环。
#   冻结注入若不成立(frida 不能在 STOP 态完成装载), 退化为 pulse: CONT 后探 5s
#   (注入与 app 赛跑, 每循环一次重掷), 再失败则清场逼复活重试。
#   首挂(Phase 1)保持慢速安全(沉淀 2s 过 LSPlant 窗, R5/R6 实证安全): 首挂的 r
#   本来就追不上, 捕获全交给 watcher 的复活循环。
# 用法: ci/attach_qd.sh [hold_secs]
HOLD=${1:-4800}
SCRIPT=${SPAWN_SCRIPT:-hook_r1_keyhunt_472.js}
ATTEMPTS=${ATTACH_ATTEMPTS:-3}
SETTLE_FIRST=${ATTACH_SETTLE_FIRST:-2}
DIR=$(cd "$(dirname "$0")/.." && pwd)
APP=com.qidian.QDReader
B=localhost:5555
LOG=/tmp/keyhunt_collect.log
FRIDA_PAT="frida -H 127.0.0.1:14771 -p "

pidof_app() { adb -s $B shell pidof $APP 2>/dev/null | tr -d '\r\n '; }

exec 9>/tmp/attach_qd.lock
if ! flock -n 9; then
  echo "[ATTACH] $(date +%s) another gate holds lock — skip(仍 am start 放行, 复活进程由持锁 watcher 接管)" >> $LOG
  adb -s $B shell am start -n $APP/.ui.activity.SplashActivity 2>/dev/null
  exit 0
fi
DEADLINE=$(( $(date +%s) + HOLD ))
echo "[ATTACH] $(date +%s) gate R8 (hold=${HOLD}s script=$SCRIPT settle_first=${SETTLE_FIRST}s) → phase1 首挂 + phase2 常驻 fast watcher" >> $LOG
pkill -f "$FRIDA_PAT" 2>/dev/null

# ── 起 background frida 会话(单次) ──
start_session() {   # $1=pid → 0=script_loaded 探测成功
  local PID=$1 MARK OK w
  MARK=$(wc -l < $LOG)
  echo "[ATTACH] $(date +%s) 后台会话 attach pid $PID" >> $LOG
  # 会话子壳关 fd9(不持锁), 会话由 watcher/driver pkill 收尾
  ( (sleep $HOLD; echo) | timeout $((HOLD+10)) \
      frida -H 127.0.0.1:14771 -p $PID -l "$DIR/$SCRIPT" \
      >> $LOG 2>&1 ) 9>&- &
  OK=""
  for w in $(seq 1 15); do
    sleep 1
    if tail -n +$((MARK+1)) $LOG 2>/dev/null | grep -q '"ev":"script_loaded"'; then
      OK=1; break
    fi
    pgrep -f "$FRIDA_PAT$PID" >/dev/null 2>&1 || break
  done
  [ -n "$OK" ] && return 0 || return 1
}



# ═══ Phase 1: 首挂(R5 同款重试环 — 首崩热身 + 沉淀 2s 过 LSPlant 窗, 慢速安全) ═══
PID=""
for a in $(seq 1 $ATTEMPTS); do
  adb -s $B shell am start -n $APP/.ui.activity.SplashActivity 2>/dev/null
  PID=""
  for i in $(seq 1 20); do
    PID=$(pidof_app)
    [ -n "$PID" ] && break
    sleep 0.5
  done
  if [ -z "$PID" ]; then
    echo "[ATTACH] attempt $a/$ATTEMPTS: 10s无pid — 重试" >> $LOG
    sleep 3; continue
  fi
  sleep $SETTLE_FIRST   # LSPatch/LSPosed 装载沉淀(MetaLoader→DexKit 实证<1s)
  LIVE=$(pidof_app)
  if [ "$LIVE" != "$PID" ]; then
    echo "[ATTACH] attempt $a/$ATTEMPTS: pid $PID 沉淀期死(首启LSPatch自崩, live='$LIVE') — 重试" >> $LOG
    sleep 3; continue
  fi
  if start_session "$PID"; then
    echo "[ATTACH] $(date +%s) session up (pid=$PID script_loaded ✓ attempt $a) hold=${HOLD}s" >> $LOG
    break
  fi
  echo "[ATTACH] attempt $a/$ATTEMPTS: attach失败(15s无script_loaded) — 清场重试" >> $LOG
  pkill -f "$FRIDA_PAT$PID" 2>/dev/null
  adb -s $B shell kill -CONT $PID 2>/dev/null   # 冻结残留保险
  adb -s $B shell am force-stop $APP 2>/dev/null
  sleep 3
  PID=""
done
if [ -z "$PID" ]; then
  echo "[ATTACH] $(date +%s) all $ATTEMPTS first-boot attempts failed" >> $LOG
  exit 1
fi

# ═══ Phase 2: R8 常驻快速 attacher(替换 R6b/R7 watcher) ═══
# R7 实证: frida-server 无法对 SIGSTOP 冻结进程附身("process not found")⇒冻结路线死;
# frida CLI 启动 ~1-1.5s 恒输 r 加密(+1.3~1.7s)⇒ 换常驻守护(python frida 模块, 设备
# 句柄+脚本预载, attach+load ~0.3-0.6s + 自适应 EARLY_DELAY 避 LSPlant 窗)。
# 守护进程接管所有后续进程(anti-frida 自杀→JPush 复活循环逐个收割, 每循环一次
# r 加密捕获机会); exec 后本门控即守护进程(fd9 锁随行, skip-gate 只做 am start)。
echo "[ATTACH] $(date +%s) phase2 → exec 常驻 fast watcher R8 (pid=$PID 跳过)" >> $LOG
exec python3 "$DIR/ci/attach_watcher.py" "$HOLD" "$PID"
