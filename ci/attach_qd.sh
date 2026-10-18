#!/bin/bash
# attach_qd.sh — R4: frida attach 门控 (472 LSPatch 线, 2026-10-18)
# 背景(R2 run 39136753310 logcat 实证): frida -f spawn 在进程创建期注入 agent →
#   LSPatch 的 LSPlant(ART hook 引擎) "Failed to init runtime" → LSPatch loader 崩
#   (NoSuchFieldError AppBindData#compatInfo) → ClassNotFound QDApplication → app 死。
#   同 run 的 am start 裸启进程(pid 2729) LSPosed 全链跑通: deoptimizing →
#   startBootstrapHook → 装载 QDReaderHook 模块 → DexKit。 ⇒ spawn 期 frida-agent 与
#   LSPlant 不两立; attach(业务期进场, LSPlant 已装完)是历史验证模式
#   (qidian_auto frida_attach_sora.py 系在 472 破解版全跑通)。
# 模式: am start → 轮询 pid → 沉淀2s(LSPatch init 实证0.8s内完成) → frida -p attach
#   装载脚本 → [READY] 由脚本发(隐私页门控放行点同意 → r1 keyexp 冷启动突发被钩覆盖)。
# 用法: ci/attach_qd.sh [hold_secs]   (脚本=${SPAWN_SCRIPT:-hook_r1_keyhunt_472.js},
#   输出追加 /tmp/keyhunt_collect.log; 由 mitm_login_capture.py QD_SPAWN_MODE=attach 驱动)
HOLD=${1:-4800}
SCRIPT=${SPAWN_SCRIPT:-hook_r1_keyhunt_472.js}
DIR=$(cd "$(dirname "$0")/.." && pwd)
APP=com.qidian.QDReader
B=localhost:5555
echo "[ATTACH] $(date +%s) gate (hold=${HOLD}s script=$SCRIPT)" >> /tmp/keyhunt_collect.log
adb -s $B shell am start -n $APP/.ui.activity.SplashActivity
PID=""
for i in $(seq 1 60); do
  PID=$(adb -s $B shell pidof $APP 2>/dev/null | tr -d '\r\n ')
  [ -n "$PID" ] && break
  sleep 0.5
done
echo "[ATTACH] pid=$PID (poll try ${i})" >> /tmp/keyhunt_collect.log
if [ -z "$PID" ]; then
  echo "[ATTACH] no pid after 30s — abort" >> /tmp/keyhunt_collect.log
  exit 1
fi
sleep 2   # LSPatch/LSPosed 装载沉淀(MetaLoader→DexKit 实证<1s)
( (sleep $HOLD; echo) | timeout $((HOLD+10)) \
    frida -H 127.0.0.1:14771 -p $PID -l "$DIR/$SCRIPT" \
    >> /tmp/keyhunt_collect.log 2>&1 )
echo "[ATTACH] $(date +%s) session ended (pid=$PID)" >> /tmp/keyhunt_collect.log
