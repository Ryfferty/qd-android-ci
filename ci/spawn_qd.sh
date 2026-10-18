#!/bin/bash
# spawn_qd.sh — R10: frida spawn 门控 (2026-10-18)
# 背景: R9实测(run 39111566448) — script-load级检测+frida-server重启5轮仍失败
#   (script-load-hang / early-exit / alloc-crash 三形态), 壳(libjiagu)对后期主进程的
#   反注入与服务器无关=进程级 ⇒ attach 路线退役。
# 本脚本: frida -f 在进程创建瞬间装载 hook (壳武装之前) — Phase A 冷启动 r1 突发
#   + Phase C 登录窗 r1 (648族checkEnv/keyexp) 双覆盖。
# 用法: ci/spawn_qd.sh [hold_secs]   (脚本=hook_r1_keyhunt_v2.js, 输出追加到 /tmp/keyhunt_collect.log)
HOLD=${1:-4800}
SCRIPT=${SPAWN_SCRIPT:-hook_r1_keyhunt_v2.js}   # R12: 可env覆盖(scanonly诊断=判"钩子死锁"vs"壳冻结")
DIR=$(cd "$(dirname "$0")/.." && pwd)
echo "[SPAWN] $(date +%s) frida -f gate (hold=${HOLD}s script=$SCRIPT)" >> /tmp/keyhunt_collect.log
( (sleep $HOLD; echo) | timeout $((HOLD+10)) \
    frida -H 127.0.0.1:14771 -f com.qidian.QDReader -l "$DIR/$SCRIPT" \
    >> /tmp/keyhunt_collect.log 2>&1 )
echo "[SPAWN] $(date +%s) gate session ended" >> /tmp/keyhunt_collect.log
