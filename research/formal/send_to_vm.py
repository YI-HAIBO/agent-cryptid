#!/usr/bin/env python3
"""
send_to_vm.py — 一键把形式化验证包传到 Ubuntu VM

用法:
  python send_to_vm.py

依赖: paramiko (自动安装: pip install paramiko)
"""

import os, sys, socket

# ---------- 配置（按需修改） ----------
HOST = "192.168.231.128"
PORT = 22
USERNAME = "cloud"
PASSWORD = "123456"
REMOTE_DIR = "/home/cloud/Desktop"
# ----------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_FILE = os.path.join(SCRIPT_DIR, "ubuntu_formal_verification.tar.gz")
REMOTE_PATH = REMOTE_DIR.rstrip("/") + "/ubuntu_formal_verification.tar.gz"

# ---------- 环境预检 ----------
def check_env():
    """确保 paramiko 可用，不可用则尝试安装"""
    try:
        import paramiko
        return paramiko
    except ImportError:
        print("[*] paramiko 未安装，正在安装...")
        import subprocess
        exe = sys.executable
        subprocess.check_call([exe, "-m", "pip", "install", "-q", "paramiko"])
        import paramiko
        print("[*] paramiko 安装完成")
        return paramiko

# ---------- TCP 连通性测试 ----------
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

# ---------- 主流程 ----------
def main():
    print("=" * 55)
    print("  agent-cryptid formal verification — file transfer")
    print("=" * 55)
    print(f"  Local:  {LOCAL_FILE}")
    print(f"  Remote: {REMOTE_PATH}")
    print(f"  Target: {USERNAME}@{HOST}:{PORT}")
    print()

    # 1. 检查本地文件
    if not os.path.exists(LOCAL_FILE):
        print(f"[ERROR] 本地文件不存在: {LOCAL_FILE}")
        sys.exit(1)
    local_size = os.path.getsize(LOCAL_FILE)
    print(f"[1/4] 本地文件: {local_size:,} bytes")

    # 2. TCP 连通性
    print(f"[2/4] 测试 {HOST}:{PORT} 连通性...")
    if not tcp_ok(HOST, PORT):
        print(f"[ERROR] 无法连接 {HOST}:{PORT}")
        print("  可能原因: VM 没开机 / 防火墙拦了 SSH / 不在同一网段")
        print("  请确认 VM 的 IP 和 SSH 端口正确")
        sys.exit(1)
    print("  OK")

    # 3. SFTP 上传
    paramiko = check_env()
    print(f"[3/4] 连接 {USERNAME}@{HOST} ...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=15)
        print("  已连接")

        sftp = ssh.open_sftp()
        print(f"  上传中 -> {REMOTE_PATH} ...")

        # 确保远程目录存在
        try:
            sftp.stat(REMOTE_DIR)
        except IOError:
            sftp.makedirs(REMOTE_DIR)

        sftp.put(LOCAL_FILE, REMOTE_PATH)
        remote_size = sftp.stat(REMOTE_PATH).st_size
        sftp.close()
        ssh.close()

        if remote_size == local_size:
            print(f"  上传成功! 远程: {remote_size:,} bytes")
        else:
            print(f"[WARN] 大小不匹配: 本地 {local_size:,} vs 远程 {remote_size:,}")

    except Exception as e:
        print(f"[ERROR] 上传失败: {e}")
        try:
            ssh.close()
        except Exception:
            pass
        sys.exit(1)

    # 4. 完成
    print(f"[4/4] 完成!")
    print()
    print("在 VM 上运行:")
    print(f"  cd {REMOTE_DIR}")
    print("  tar xzf ubuntu_formal_verification.tar.gz")
    print("  cd formal_verification")
    print("  ./run_all.sh")
    print()
    print("=" * 55)


if __name__ == "__main__":
    main()