#!/usr/bin/env python3
"""frida_oracle_driver.py — App 稳定后 attach，执行 oracle 解密
用法: python3 frida_oracle_driver.py <PID>
"""
import frida, sys, time, json, os

def main():
    if len(sys.argv) < 2:
        print("ERROR: need PID argument"); sys.exit(1)
    
    pid = int(sys.argv[1])
    
    for p in ["hook_fock_oracle_v3.js", "ci/hook_fock_oracle_v3.js", "hook_fock_oracle_v2.js", "ci/hook_fock_oracle_v2.js", "hook_fock_oracle.js", "ci/hook_fock_oracle.js"]:
        if os.path.exists(p):
            with open(p) as f:
                js = f.read()
            print(f"Loaded: {p}", flush=True)
            break
    else:
        print("ERROR: script not found"); sys.exit(1)

    device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")

    print(f"Attaching to PID={pid}", flush=True)
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"Attach failed: {e}", flush=True)
        sys.exit(1)

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

    print("收集 60 秒...", flush=True)
    time.sleep(60)

    with open("/tmp/fock_oracle_result.txt", "w") as f:
        f.write("\n".join(results))
    print("=== 结果已写入 ===", flush=True)

if __name__ == "__main__":
    main()
