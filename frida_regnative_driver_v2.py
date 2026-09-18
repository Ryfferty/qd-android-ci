#!/usr/bin/env python3
"""frida_regnative_driver_v2.py — spawn 模式驱动，确保从 App 启动起就 hook
用法: python3 frida_regnative_driver_v2.py
"""
import frida, sys, time, json, os

def main():
    # 找脚本
    for p in ["hook_regnative_v2.js", "ci/hook_regnative_v2.js"]:
        if os.path.exists(p):
            with open(p) as f:
                js = f.read()
            print(f"Loaded script: {p}", flush=True)
            break
    else:
        print("ERROR: hook_regnative_v2.js not found")
        sys.exit(1)

    device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")

    # spawn 模式：在 App 启动前注入
    pkg = "com.qidian.QDReader"
    print(f"Spawning {pkg}...", flush=True)
    try:
        pid = device.spawn([pkg])
        print(f"Spawned PID={pid}", flush=True)
    except Exception as e:
        print(f"Spawn failed: {e}, trying attach...", flush=True)
        # fallback: attach 已运行的进程
        for p in device.enumerate_processes():
            if p.name == pkg:
                pid = p.pid
                break
        else:
            print("ERROR: process not found")
            sys.exit(1)

    session = device.attach(pid)

    results = []
    def on_message(msg, data):
        if msg['type'] == 'send':
            payload = msg['payload']
            if isinstance(payload, dict) and 'm' in payload:
                print(payload['m'], flush=True)
                results.append(payload['m'])
            else:
                print(json.dumps(payload), flush=True)
                results.append(json.dumps(payload))
        elif msg['type'] == 'error':
            print(f"ERROR: {msg.get('description','')}", flush=True)
            results.append(f"ERROR: {msg.get('description','')}")

    script = session.create_script(js)
    script.on('message', on_message)
    script.load()

    # 如果是 spawn 模式，现在 resume
    try:
        device.resume(pid)
        print("Resumed process", flush=True)
    except:
        pass

    # 收集 90 秒（App 启动 + 初始化 + 可能的延迟注册）
    print("收集 90 秒...", flush=True)
    time.sleep(90)

    with open("/tmp/regnative_result.txt", "w") as f:
        f.write("\n".join(results))
    print("=== 结果已写入 /tmp/regnative_result.txt ===", flush=True)

if __name__ == "__main__":
    main()
