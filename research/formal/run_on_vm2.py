#!/usr/bin/env python3
"""
run_on_vm2.py — 在 VM Desktop 上直接跑 run_all.sh（tarball 解包到 Desktop 根，
没有 formal_verification/ 子目录），轮询日志并拉回产物。

用法:
  python run_on_vm2.py           # 启动 run_all.sh 并轮询
  python run_on_vm2.py --pull    # 只拉回已有产物（不启动）
"""

import os, sys, time, socket

HOST = "192.168.231.128"
PORT = 22
USERNAME = "cloud"
PASSWORD = "123456"
DESKTOP = "/home/cloud/Desktop"
LOG = f"{DESKTOP}/run_all_live.log"


def tcp_ok(host, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        s.close()
        return False


def main():
    pull_only = "--pull" in sys.argv

    try:
        import paramiko
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "-q", "paramiko"])
        import paramiko

    if not tcp_ok(HOST, PORT):
        print(f"[ERROR] {HOST}:{PORT} 不可达")
        sys.exit(1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=15)
    print(f"[OK] 已连接 {USERNAME}@{HOST}")

    # 检查 Desktop 上的文件
    i, o, e = ssh.exec_command(
        f"ls -la {DESKTOP}/run_all.sh {DESKTOP}/tamarin_ubuntu_pkg {DESKTOP}/cryptoverif_ubuntu_pkg 2>&1"
    )
    print("--- Desktop 文件检查 ---")
    print(o.read().decode())
    if e.read().decode().strip():
        print("ERR:", e.read().decode().strip())

    if not pull_only:
        # 检查是否已在跑
        i, o, e = ssh.exec_command("pgrep -f 'run_all.sh' >/dev/null && echo RUNNING || echo NOTRUNNING")
        if o.read().decode().strip() == "RUNNING":
            print("[WARN] run_all.sh 已在运行，不重复启动")
        else:
            # 清空旧日志，nohup 启动
            ssh.exec_command(f"rm -f {LOG}")
            i, o, e = ssh.exec_command(
                f"cd {DESKTOP} && nohup ./run_all.sh > {LOG} 2>&1 & echo $!"
            )
            pid = o.read().decode().strip()
            print(f"[OK] 已启动 run_all.sh (nohup), pid={pid}")

    # 轮询日志
    print(f"轮询 {LOG} 中 ...")
    last_size = 0
    done = False
    while not done:
        i, o, e = ssh.exec_command(f"test -f {LOG} && wc -c < {LOG} || echo 0")
        size = int(o.read().decode().strip() or "0")
        if size > last_size:
            i, o, e = ssh.exec_command(f"tail -c +{last_size+1} {LOG}")
            chunk = o.read().decode()
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()
            last_size = size
        i, o, e = ssh.exec_command("pgrep -f 'run_all.sh' >/dev/null && echo RUNNING || echo DONE")
        status = o.read().decode().strip()
        if status == "DONE":
            # 再等 3 秒确认
            time.sleep(3)
            i, o, e = ssh.exec_command(f"test -f {LOG} && wc -c < {LOG} || echo 0")
            final = int(o.read().decode().strip() or "0")
            if final == last_size:
                done = True
        time.sleep(3)

    # 拉回产物
    print("\n--- 拉回产物 ---")
    sftp = ssh.open_sftp()
    local_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ["run_all_live.log", "tamarin_output.txt",
                 "cryptoverif_output.txt", "formal_verification_summary.txt"]:
        remote = f"{DESKTOP}/{name}"
        local = os.path.join(local_dir, name)
        try:
            sftp.get(remote, local)
            print(f"  {name} -> {local} ({os.path.getsize(local):,} bytes)")
        except IOError as exc:
            print(f"  {name}: 缺失 ({exc})")
    sftp.close()
    ssh.close()
    print("\n[DONE]")


if __name__ == "__main__":
    main()