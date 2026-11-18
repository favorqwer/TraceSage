#!/usr/bin/env python3
"""
benign_traffic_generator.py
Windows 宿主机外部跨主机良性流量与运维备份发生器
持续向物理机A 的 ubuntu (100.86.108.4) 注入合规 HTTP/API 流量与 SSH/SCP 备份
"""

import os
import sys
import time
import signal
import random
import argparse
import subprocess
from datetime import datetime
import urllib.request
import urllib.parse
import json

RUNNING = True

def handle_signal(sig, frame):
    global RUNNING
    print(f"\n[{datetime.now()}] 收到终止信号，正在平稳停止流量发生器...", flush=True)
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def send_http_request(target_ip):
    # 随机选择端点：Nginx 静态、PHP 探针、Tomcat 端口
    choice = random.random()
    try:
        if choice < 0.4:
            # Nginx 首页
            url = f"http://{target_ip}/"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BenignClient/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                _ = resp.read()
            return "Nginx:GET /: 200"
        elif choice < 0.75:
            # PHP 探针接口 (GET / POST)
            if random.random() < 0.5:
                url = f"http://{target_ip}/probe.php?action=status_check&rnd={random.randint(1000, 9999)}"
                req = urllib.request.Request(url, headers={"User-Agent": "BenignMonitor/2.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                return f"PHP:GET probe.php: {data.get('status')}"
            else:
                url = f"http://{target_ip}/probe.php?action=metric_push"
                payload = json.dumps({"client": "windows_host", "metric": "cpu_load", "val": round(random.uniform(0.1, 0.8), 2)}).encode()
                req = urllib.request.Request(url, data=payload, headers={"User-Agent": "BenignReporter/1.0", "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                return f"PHP:POST probe.php: {data.get('status')}"
        else:
            # Tomcat 8080
            url = f"http://{target_ip}:8080/"
            req = urllib.request.Request(url, headers={"User-Agent": "TomcatProbe/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                _ = resp.read()
            return "Tomcat:GET :8080: 200"
    except Exception as e:
        return f"HTTP 异常: {e}"

def perform_ssh_backup(target_ip, backup_dir):
    try:
        os.makedirs(backup_dir, exist_ok=True)
        # 1. SSH 远程系统健康巡检
        cmd_ssh = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", f"ubuntu@{target_ip}", "uptime; free -m; df -h /; vmstat 1 2"]
        res_ssh = subprocess.run(cmd_ssh, capture_output=True, text=True, check=True)
        first_line = res_ssh.stdout.strip().splitlines()[0] if res_ssh.stdout else "ok"

        # 2. SCP 归档日志拉取
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        local_dest = os.path.join(backup_dir, f"nginx_access_{ts}.log")
        cmd_scp = ["scp", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", f"ubuntu@{target_ip}:/var/log/nginx/access.log", local_dest]
        subprocess.run(cmd_scp, capture_output=True, text=True, check=True)

        size = os.path.getsize(local_dest) if os.path.exists(local_dest) else 0
        return True, f"SSH: {first_line} | SCP 归档拉取成功 ({size} 字节)"
    except Exception as e:
        return False, f"SSH/SCP 备份失败: {e}"

def main():
    parser = argparse.ArgumentParser(description="Windows 宿主机外部跨主机良性流量与备份发生器")
    parser.add_argument("--duration", type=int, default=3600, help="总执行时长（秒），默认 3600")
    parser.add_argument("--target-ip", type=str, default="100.86.108.4", help="受害者机 Tailscale IP")
    parser.add_argument("--ssh-interval", type=int, default=300, help="SSH/SCP 备份间隔（秒），默认 300 (5分钟)")
    parser.add_argument("--backup-dir", type=str, default="tmp/remote_backups", help="Windows 本地备份存储目录")
    args = parser.parse_args()

    start_time = time.time()
    last_ssh_time = start_time
    http_count = 0
    ssh_count = 0

    log(f"流量发生器已启动，目标: {args.target_ip}，计划时长: {args.duration} 秒 ({args.duration/60:.1f} 分钟)")
    log(f"SSH/SCP 备份周期: 每 {args.ssh_interval} 秒一次，归档目录: {args.backup_dir}")

    # 启动时先执行一次初次健康核验与拉取
    ok, msg = perform_ssh_backup(args.target_ip, args.backup_dir)
    ssh_count += 1
    log(f"[初始备份 #{ssh_count}] {msg}")

    while RUNNING and (time.time() - start_time < args.duration):
        now = time.time()
        elapsed = now - start_time

        # 1. 触发 HTTP 业务请求
        res_http = send_http_request(args.target_ip)
        http_count += 1
        if http_count % 30 == 0:
            log(f"[HTTP #{http_count}] {res_http} | 进度: {int(elapsed)}s/{args.duration}s ({(elapsed/args.duration)*100:.1f}%)")

        # 2. 检查是否到达 SSH/SCP 周期
        if now - last_ssh_time >= args.ssh_interval:
            ok, msg = perform_ssh_backup(args.target_ip, args.backup_dir)
            ssh_count += 1
            log(f"[定时备份 #{ssh_count}] {msg}")
            last_ssh_time = now

        # 随机平缓等待 1.5 ~ 4.0 秒
        time.sleep(random.uniform(1.5, 4.0))

    total_elapsed = time.time() - start_time
    log(f"流量发生器完成，实际耗时: {total_elapsed:.1f} 秒，累计 HTTP 请求: {http_count} 次，累计 SSH/SCP 备份: {ssh_count} 次")

if __name__ == "__main__":
    main()
