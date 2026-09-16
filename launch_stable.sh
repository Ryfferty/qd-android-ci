#!/usr/bin/env bash
# launch_stable.sh — 反复拉起 App，直到它稳定存活，并可选等待进入目标 Activity
# 用法: launch_stable.sh <pkg> <activity> [期望Activity片段] [最大尝试]
set +e
PKG=${1:-com.qidian.QDReader}
ACT=${2:-com.qidian.QDReader/.ui.activity.SplashActivity}
WANT=${3:-GuidanceActivity}
MAX=${4:-12}
B=localhost:5555

wait_alive() {  # 返回 pid 或空
  for _ in 1 2 3 4 5 6; do
    P=$(adb -s $B shell pidof $PKG 2>/dev/null | tr -d '\r')
    [ -n "$P" ] && { echo "$P"; return 0; }
    sleep 5
  done
  echo ""
}

for i in $(seq 1 $MAX); do
  echo "--- launch try $i ---"
  adb -s $B shell "am start -n $ACT" >/dev/null 2>&1
  P=$(wait_alive)
  if [ -z "$P" ]; then
    echo "    am start 没起来，试 monkey"
    adb -s $B shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
    P=$(wait_alive)
  fi
  echo "    pid=[$P]"
  [ -z "$P" ] && continue

  # 存活 10 秒算稳定
  sleep 10
  P2=$(adb -s $B shell pidof $PKG 2>/dev/null | tr -d '\r')
  if [ -z "$P2" ]; then
    echo "    起来后又退出，重试"
    continue
  fi

  # 检查当前 Activity
  CUR=$(adb -s $B shell "dumpsys activity activities 2>/dev/null | grep mResumedActivity | head -1" | tr -d '\r')
  echo "    当前: $CUR"
  if [ -n "$WANT" ] && echo "$CUR" | grep -q "$WANT"; then
    echo "  ✓ 已到 $WANT，pid=$P2"
    echo "STABLE_PID=$P2"
    exit 0
  fi
  if [ -z "$WANT" ]; then
    echo "  ✓ 稳定存活，pid=$P2"
    echo "STABLE_PID=$P2"
    exit 0
  fi
  # 还没到目标 Activity，再等一会
  sleep 15
  CUR=$(adb -s $B shell "dumpsys activity activities 2>/dev/null | grep mResumedActivity | head -1" | tr -d '\r')
  echo "    再等后: $CUR"
  if echo "$CUR" | grep -q "$WANT"; then
    echo "  ✓ 已到 $WANT，pid=$P2"
    echo "STABLE_PID=$P2"
    exit 0
  fi
done
echo "LAUNCH_FAILED"
exit 1
