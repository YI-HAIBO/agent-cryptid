#!/usr/bin/env python3
"""
run_on_vm.py — 连到 VM，解包并跑 run_all.sh，实时回传输出

用法:
  python run_on_vm.py            # 解包 + 跑完整 run_all.sh
  python run_on_vm.py --unpack   # 只解包，不跑验证
"""

import os, sys, socket, time

HOST = "192.168.231.128"
PORT = 22
USERNAME = "cloud"
PASSWORD = "123456"
REMOTE_DIR = "/home/cloud/Desktop"


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
    only_unpack = "--unpack" in sys.argv

    try:
        import paramiko
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "paramiko"])
        import paramiko

    if not tcp_ok(HOST, PORT):
        print(f"[ERROR] {HOST}:{PORT} 不可达")
        sys.exit(1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=15)
    print(f"[OK] 已连接 {USERNAME}@{HOST}")

    stdin, stdout, stderr = ssh.exec_command(
        f"cd {REMOTE_DIR} && tar xzf ubuntu_formal_verification.tar.gz && ls -la formal_verification/"
    )
    out = stdout.read().decode()
    err = stderr.read().decode()
    print("--- 解包结果 ---")
    print(out)
    if err.strip():
        print("STDERR:", err.strip())

    if only_unpack:
        ssh.close()
        return

    # 跑 run_all.sh，后台 nohup 并把日志写到 VM 上，我们轮询
    print("\n--- 启动 run_all.sh (nohup) ---")
    ssh.exec_command(
        f"cd {REMOTE_DIR}/formal_verification && nohup ./run_all.sh > run_all_live.log 2>&1 & echo $!"
    )
    time.sleep(1)

    # 轮询日志
    print("轮询 run_all_live.log 中 ... (Ctrl-C 退出，脚本继续在 VM 上跑)")
    last_size = 0
    try:
        while True:
            stdin, stdout, stderr = ssh.exec_command(
                f"test -f {REMOTE_DIR}/formal_verification/run_all_live.log && wc -c < {REMOTE_DIR}/formal_verification/run_all_live.log || echo 0"
            )
            size = int(stdout.read().decode().strip() or "0")
            if size > last_size:
                stdin, stdout, stderr = ssh.exec_command(
                    f"tail -c +{last_size+1} {REMOTE_DIR}/formal_verification/run_all_live.log"
                )
                chunk = stdout.read().decode()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                last_size = size
            # 检查进程是否还活着
            stdin, stdout, stderr = ssh.exec_command(
                f"pgrep -f run_all.sh >/dev/null && echo RUNNING || echo DONE"
            )
            status = stdout.read().decode().strip()
            if status == "DONE" and size >= last_size:
                # 再等 2 秒确认没有新输出
                time.sleep(2)
                stdin, stdout, stderr = ssh.exec_command(
                    f"test -f {REMOTE_DIR}/formal_verification/run_all_live.log && wc -c < {REMOTE_DIR}/formal_verification/run_all_live.log || echo 0"
                )
                final_size = int(stdout.read().decode().strip() or "0")
                if final_size == last_size:
                    break
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[用户中断] 脚本仍在 VM 上运行，稍后可再连")

    # 拉回完整日志
    print("\n--- 拉回完整日志 ---")
    sftp = ssh.open_sftp()
    remote_log = f"{REMOTE_DIR}/formal_verification/run_all_live.log"
    local_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_all_vm.log")
    try:
        sftp.get(remote_log, local_log)
        print(f"日志已保存: {local_log}")
    except IOError as e:
        print(f"[WARN] 拉回日志失败: {e}")
    sftp.close()
    ssh.close()


if __name__ == "__main__":
    main()