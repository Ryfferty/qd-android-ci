#!/usr/bin/env python3
"""frida_regnative_driver.py — Python frida API 驱动 hook_regnative.js
用法: python3 frida_regnative_driver.py <PID>
"""
import frida, sys, time, json, os

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    # 找脚本文件
    for p in ["hook_regnative.js", "ci/hook_regnative.js"]:
        if os.path.exists(p):
            with open(p) as f:
                js = f.read()
            break
    else:
        print("ERROR: hook_regnative.js not found")
        sys.exit(1)

    device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")

    if pid is None:
        for p in device.enumerate_processes():
            if p.name == "com.qidian.QDReader":
                pid = p.pid
                break

    if pid is None:
        print("ERROR: com.qidian.QDReader not found")
        sys.exit(1)

    print(f"Attaching to PID={pid}")
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

    # 保持 60 秒收集 RegisterNatives 调用
    print("收集 60 秒...", flush=True)
    time.sleep(60)

    # 写结果
    with open("/tmp/regnative_result.txt", "w") as f:
        f.write("\n".join(results))
    print("=== 结果已写入 /tmp/regnative_result.txt ===", flush=True)

if __name__ == "__main__":
    main()
