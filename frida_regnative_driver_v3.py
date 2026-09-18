#!/usr/bin/env python3
"""frida_regnative_driver_v3.py — attach 模式，am start 后立即 attach
用法: python3 frida_regnative_driver_v3.py
"""
import frida, sys, time, json, os

def main():
    for p in ["hook_regnative_v3.js", "ci/hook_regnative_v3.js"]:
        if os.path.exists(p):
            with open(p) as f:
                js = f.read()
            print(f"Loaded: {p}", flush=True)
            break
    else:
        print("ERROR: script not found"); sys.exit(1)

    device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    pkg = "com.qidian.QDReader"

    # 找已运行的进程
    pid = None
    for p in device.enumerate_processes():
        if p.name == pkg:
            pid = p.pid
            break

    if pid is None:
        print(f"{pkg} not running, waiting...", flush=True)
        for _ in range(10):
            time.sleep(2)
            for p in device.enumerate_processes():
                if p.name == pkg:
                    pid = p.pid
                    break
            if pid:
                break

    if pid is None:
        print("ERROR: process not found"); sys.exit(1)

    print(f"Attaching to PID={pid}", flush=True)
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

    print("收集 90 秒...", flush=True)
    time.sleep(90)

    with open("/tmp/regnative_result.txt", "w") as f:
        f.write("\n".join(results))
    print("=== 结果已写入 ===", flush=True)

if __name__ == "__main__":
    main()
