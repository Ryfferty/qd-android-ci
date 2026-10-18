#!/bin/bash
# attach_qd.sh — R5: frida attach 门控 + 首崩重试 (472 LSPatch 线, 2026-10-18)
# 背景(R4 run 39140196310 logcat 实证):
#   pm clear 后首启 = LSPatch-MetaLoader 自崩, 与 frida 无关:
#     "Error when loading liblspatch.so" → NoClassDefFoundError(boot class loader)
#     → ExceptionInInitializerError → 进程 376ms 死(此刻 attach 尚未发生)
#   同 run 二次启动(数据保留) LSPatch 完整立起:
#     "Bootstrap loader from embedment" → LocalApplicationService → DexKit 全过。
#   ⇒ 首崩=装载器惰性解包竞态; 第二次 am start 踩着首崩完成的解包即活(重试=热身)。
#   R4 铁证: [ATTACH] pid=2009 (poll try 1) → sleep 2 → 进程已死 →
#   "Failed to attach: unable to find process with pid 2009" 且门控无重试 → 全轮报废。
# 早期背景(R2 run 39136753310): frida -f spawn 期注入 agent → LSPlant
#   "Failed to init runtime" → loader 崩(ClassNotFound QDApplication) ⇒ spawn 与
#   LSPlant 不两立; attach(业务期进场, LSPlant 已装完)是历史验证模式
#   (qidian_auto frida_attach_sora.py 系在 472 破解版全跑通)。
# 模式: 每次尝试 [am start → poll pid(10s) → 沉淀2s → 存活复验 → 后台起 attach 会话
#   → 探测15s script_loaded]; pid死/attach失败 → 清场重试(默认3次)。
#   成功=script_loaded 出现, 会话后台持有到 hold/被pkill, 门控 exit 0。
#   flock 互斥: D看门狗12s连呼时只有一个门控在重试, 后到者跳过。
# 用法: ci/attach_qd.sh [hold_secs]  (脚本=${SPAWN_SCRIPT:-hook_r1_keyhunt_472.js},
#   尝试数=${ATTACH_ATTEMPTS:-3}, 输出追加 /tmp/keyhunt_collect.log)
HOLD=${1:-4800}
SCRIPT=${SPAWN_SCRIPT:-hook_r1_keyhunt_472.js}
ATTEMPTS=${ATTACH_ATTEMPTS:-3}
DIR=$(cd "$(dirname "$0")/.." && pwd)
APP=com.qidian.QDReader
B=localhost:5555
LOG=/tmp/keyhunt_collect.log
exec 9>/tmp/attach_qd.lock
if ! flock -n 9; then
  echo "[ATTACH] $(date +%s) another gate holds lock — skip" >> $LOG
  exit 0
fi
echo "[ATTACH] $(date +%s) gate (hold=${HOLD}s script=$SCRIPT attempts=$ATTEMPTS)" >> $LOG
# 清陈旧会话(目标进程已死者; 每次门控对应一次新启动)
pkill -f "frida -H 127.0.0.1:14771 -p " 2>/dev/null
for a in $(seq 1 $ATTEMPTS); do
  adb -s $B shell am start -n $APP/.ui.activity.SplashActivity
  PID=""
  for i in $(seq 1 20); do
    PID=$(adb -s $B shell pidof $APP 2>/dev/null | tr -d '\r\n ')
    [ -n "$PID" ] && break
    sleep 0.5
  done
  if [ -z "$PID" ]; then
    echo "[ATTACH] attempt $a/$ATTEMPTS: 10s无pid — 重试" >> $LOG
    sleep 3; continue
  fi
  sleep 2   # LSPatch/LSPosed 装载沉淀(MetaLoader→DexKit 实证<1s)
  LIVE=$(adb -s $B shell pidof $APP 2>/dev/null | tr -d '\r\n ')
  if [ "$LIVE" != "$PID" ]; then
    echo "[ATTACH] attempt $a/$ATTEMPTS: pid $PID 沉淀期死(首启LSPatch自崩, live='$LIVE') — 重试" >> $LOG
    sleep 3; continue
  fi
  MARK=$(wc -l < $LOG)
  echo "[ATTACH] attempt $a/$ATTEMPTS: 后台会话 attach pid $PID" >> $LOG
  # 会话子壳关 fd9(不持锁), 门控 exit 后会话由驱动器 pkill/hold 收尾
  ( (sleep $HOLD; echo) | timeout $((HOLD+10)) \
      frida -H 127.0.0.1:14771 -p $PID -l "$DIR/$SCRIPT" \
      >> $LOG 2>&1 ) 9>&- &
  OK=""
  for w in $(seq 1 15); do
    sleep 1
    if tail -n +$((MARK+1)) $LOG 2>/dev/null | grep -q '"ev":"script_loaded"'; then
      OK=1; break
    fi
    pgrep -f "frida -H 127.0.0.1:14771 -p $PID" >/dev/null 2>&1 || break
  done
  if [ -n "$OK" ]; then
    echo "[ATTACH] $(date +%s) session up (pid=$PID script_loaded ✓ attempt $a) hold=${HOLD}s" >> $LOG
    exit 0
  fi
  echo "[ATTACH] attempt $a/$ATTEMPTS: attach失败(15s无script_loaded) — 清场重试" >> $LOG
  pkill -f "frida -H 127.0.0.1:14771 -p $PID" 2>/dev/null
  adb -s $B shell am force-stop $APP 2>/dev/null
  sleep 3
done
echo "[ATTACH] $(date +%s) all $ATTEMPTS attempts failed" >> $LOG
exit 1
