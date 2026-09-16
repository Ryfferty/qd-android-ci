#!/usr/bin/env bash
# 直接写入隐私同意状态，跳过弹窗点击
set +e
B=localhost:5555
PKG=com.qidian.QDReader
UID=$(adb -s $B shell "dumpsys package $PKG | grep userId= | head -1" | tr -d '\r' | sed 's/.*userId=//;s/ .*//')
echo "app uid=$UID"
cat > /tmp/app_sp.xml <<'XML'
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <boolean name="is_agree_privacy" value="true" />
</map>
XML
adb -s $B push /tmp/app_sp.xml /data/local/tmp/app_sp.xml
adb -s $B shell "mkdir -p /data/data/$PKG/shared_prefs"
adb -s $B shell "cp /data/local/tmp/app_sp.xml /data/data/$PKG/shared_prefs/app_sp.xml"
adb -s $B shell "chown u0_a116:u0_a116 /data/data/$PKG/shared_prefs/app_sp.xml 2>/dev/null; chmod 660 /data/data/$PKG/shared_prefs/app_sp.xml"
adb -s $B shell "ls -la /data/data/$PKG/shared_prefs/app_sp.xml"
echo "--- 内容确认 ---"
adb -s $B shell "cat /data/data/$PKG/shared_prefs/app_sp.xml"
