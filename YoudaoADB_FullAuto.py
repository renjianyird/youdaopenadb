import os
import sys
import json
import hashlib
import socket
import threading
import http.server
import socketserver
import re
import time
import requests
from scapy.all import sniff, IP, TCP, Raw

# ==========================================================
# 【终极可用版】完全对齐教程 · 抓包必中 · 不玩花样
# ==========================================================

CAPTURED = {
    "host": "",
    "deltaUrl": "",
    "segmentMd5": [],
    "endPos": []
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ------------------------------------------------------------------------------
# 【抓包回调：最暴力、最稳、不丢包】
# 只要是 checkVersion 的响应，一律捕获
# ------------------------------------------------------------------------------
def packet_callback(pkt):
    if not (IP in pkt and TCP in pkt and Raw in pkt):
        return False

    try:
        raw_data = pkt[Raw].load
        data = raw_data.decode("utf-8", errors="ignore")

        # 抓 Host
        if "checkVersion" in data:
            host_line = re.search(r'Host:\s*([^\r\n]+)', data)
            if host_line:
                CAPTURED["host"] = host_line.group(1).strip()

        # 抓更新响应（只要包含 deltaUrl 就抓）
        if "deltaUrl" in data and '"status":1000' in data:
            json_match = re.search(r'(\{.*\})', data, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                j = json.loads(json_str)
                ver = j["data"]["version"]
                CAPTURED["deltaUrl"] = ver.get("deltaUrl", "")
                CAPTURED["segmentMd5"] = ver.get("segmentMd5", [])
                CAPTURED["endPos"] = ver.get("endPos", [])
                print("[INFO] 抓到更新包地址！")
                return True
    except Exception:
        pass
    return False

def step1_capture():
    print("\n==============================================")
    print("                步骤1：开始抓包")
    print("    请：词典笔连热点 → 设置 → 检查更新")
    print("==============================================")
    
    try:
        # 抓所有包，不过滤，不搞复杂
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=120)
    except Exception as e:
        print(f"[错误] 抓包失败：{str(e)}")
        print("→ 请用管理员权限运行")
        print("→ 请安装 Npcap 驱动")
        return False

    if not CAPTURED["deltaUrl"]:
        print("[错误] 未抓到更新包地址！")
        return False
    if not CAPTURED["host"]:
        print("[错误] 未抓到OTA服务器地址！")
        return False

    print(f"[成功] 抓到更新地址：{CAPTURED['deltaUrl'][:60]}...")
    return True

# ------------------------------------------------------------------------------
# 步骤2：下载固件
# ------------------------------------------------------------------------------
def step2_download():
    print("\n=== 步骤2：下载固件 ===")
    try:
        resp = requests.get(CAPTURED["deltaUrl"], stream=True, timeout=120)
        with open("update.bin", "wb") as f:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
        print("[成功] 固件已保存：update.bin")
        return "update.bin"
    except Exception as e:
        print(f"[错误] 下载失败：{e}")
        return None

# ------------------------------------------------------------------------------
# 步骤3：提取 MD5
# ------------------------------------------------------------------------------
def step3_extract_md5(filename):
    print("\n=== 步骤3：提取原始MD5 ===")
    try:
        with open(filename, "rb") as f:
            data = f.read()
        matches = re.findall(rb"[0-9a-fA-F]{32}", data)
        if not matches:
            print("[错误] 未找到MD5")
            return None
        old_md5 = matches[0].decode().lower()
        print(f"[成功] 原始MD5：{old_md5}")
        return old_md5
    except Exception as e:
        print(f"[错误] 读取失败：{e}")
        return None

# ------------------------------------------------------------------------------
# 步骤4：修改固件
# ------------------------------------------------------------------------------
def step4_patch(filename, old_md5, pwd):
    print("\n=== 步骤4：修改固件密码 ===")
    try:
        new_md5 = hashlib.md5((pwd + "\n").encode()).hexdigest()
        with open(filename, "rb") as f:
            buf = f.read()
        old_bytes = bytes.fromhex(old_md5)
        new_bytes = bytes.fromhex(new_md5)
        if old_bytes not in buf:
            print("[错误] 原始MD5不匹配")
            return None, None
        new_buf = buf.replace(old_bytes, new_bytes)
        with open("patched.bin", "wb") as f:
            f.write(new_buf)
        new_sha = hashlib.sha256(new_buf).hexdigest()
        print("[成功] 新固件：patched.bin")
        return "patched.bin", new_sha
    except Exception as e:
        print(f"[错误] 修改失败：{e}")
        return None, None

# ------------------------------------------------------------------------------
# 步骤5：本地服务器
# ------------------------------------------------------------------------------
def step5_start_server(local_ip, fw_path, sha256):
    print("\n=== 步骤5：启动本地劫持服务器 ===")

    def file_server():
        os.chdir(os.path.dirname(os.path.abspath(fw_path)))
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler) as httpd:
            httpd.serve_forever()

    def ota_server():
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                url = f"http://{local_ip}:8080/{os.path.basename(fw_path)}"
                res = {
                    "status": 1000,
                    "msg": "success",
                    "data": {
                        "version": {
                            "deltaUrl": url,
                            "fullUrl": url,
                            "segmentMd5": CAPTURED["segmentMd5"],
                            "endPos": CAPTURED["endPos"],
                            "sha256sum": sha256,
                            "force": 1
                        }
                    }
                }
                self.wfile.write(json.dumps(res).encode())
            def log_message(self, *args):
                pass
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer(("0.0.0.0", 80), Handler) as httpd:
            httpd.serve_forever()

    threading.Thread(target=file_server, daemon=True).start()
    threading.Thread(target=ota_server, daemon=True).start()

    print("[成功] 服务器已启动！")
    print(f"→ 设备 HOSTS：{local_ip}    {CAPTURED['host']}")
    print("→ 词典笔点击：检查更新 → 升级")

# ------------------------------------------------------------------------------
# 主程序
# ------------------------------------------------------------------------------
def main():
    os.system("title 有道词典笔ADB工具 · 终极可用版")
    print("======================================================")
    print("             有道词典笔ADB开启工具")
    print("           完全对齐教程 · 抓包必成功版")
    print("======================================================")
    ip = get_local_ip()
    print(f"本机IP：{ip}")

    if not step1_capture():
        os.system("pause")
        return
    fw = step2_download()
    if not fw:
        os.system("pause")
        return
    old_md5 = step3_extract_md5(fw)
    if not old_md5:
        os.system("pause")
        return
    pwd = input("\n设置ADB密码：").strip()
    if not pwd:
        print("[错误] 密码不能为空")
        os.system("pause")
        return
    new_fw, sha = step4_patch(fw, old_md5, pwd)
    if not new_fw:
        os.system("pause")
        return
    step5_start_server(ip, new_fw, sha)

    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"[异常] {e}")
        os.system("pause")
