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
from scapy.all import sniff, IP, TCP, Raw

# ==========================================================
# 最终版 · 完全对齐你给的教程
# 只抓包 → 直接用原始响应 → 不自己发任何请求
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
# 步骤1：抓包（完全按教程：只抓一次，直接取响应，不重发）
# ------------------------------------------------------------------------------
def packet_callback(pkt):
    if not (IP in pkt and TCP in pkt and Raw in pkt):
        return False
    try:
        data = pkt[Raw].load.decode("utf-8", "ignore")
        
        # 记录 OTA 域名
        if "checkVersion" in data:
            lines = data.splitlines()
            for line in lines:
                if line.startswith("Host:"):
                    CAPTURED["host"] = line.split()[1]

        # 直接从服务器真实响应里取地址（教程核心）
        if "{" in data and '"status":1000' in data and '"version"' in data:
            json_part = re.search(r"\{.*\}", data, re.DOTALL)
            if not json_part:
                return False
            j = json.loads(json_part.group(0))
            ver = j["data"]["version"]
            CAPTURED["deltaUrl"] = ver.get("deltaUrl", "")
            CAPTURED["segmentMd5"] = ver.get("segmentMd5", [])
            CAPTURED["endPos"] = ver.get("endPos", [])
            return True
    except Exception:
        pass
    return False

def step1_capture():
    print("\n=== 步骤1：抓包获取更新包地址（教程原版）===")
    print("提示：词典笔连电脑热点 → 设置 → 检查更新")
    try:
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=90)
    except Exception as e:
        print(f"[错误] 抓包失败：{str(e)}")
        print("请用管理员权限运行，并确保安装 Npcap 驱动")
        return False

    if not CAPTURED["deltaUrl"]:
        print("[错误] 未抓到更新包地址，请重试检查更新")
        return False
    if not CAPTURED["host"]:
        print("[错误] 未获取到OTA服务器地址")
        return False

    print(f"[成功] 抓到更新地址：{CAPTURED['deltaUrl'][:50]}...")
    return True

# ------------------------------------------------------------------------------
# 步骤2：下载固件
# ------------------------------------------------------------------------------
def step2_download():
    print("\n=== 步骤2：下载更新包 ===")
    url = CAPTURED["deltaUrl"]
    if not url:
        print("[错误] 下载地址为空")
        return None

    try:
        import requests
        resp = requests.get(url, stream=True, timeout=180)
        resp.raise_for_status()
        total_size = int(resp.headers.get("content-length", 0))
        with open("update.bin", "wb") as f:
            downloaded = 0
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    print(f"下载中：{downloaded}/{total_size} bytes", end="\r")
        print("\n[成功] 固件已保存为 update.bin")
        return "update.bin"
    except Exception as e:
        print(f"\n[错误] 下载失败：{str(e)}")
        return None

# ------------------------------------------------------------------------------
# 步骤3：提取 MD5
# ------------------------------------------------------------------------------
def step3_extract_md5(filename):
    print("\n=== 步骤3：提取原始密码 MD5 ===")
    try:
        with open(filename, "rb") as f:
            data = f.read()
        matches = re.findall(rb"[0-9a-fA-F]{32}", data)
        if not matches:
            print("[错误] 未找到 MD5")
            return None
        old_md5 = matches[0].decode().lower()
        print(f"[成功] 原始 MD5：{old_md5}")
        return old_md5
    except Exception as e:
        print(f"[错误] 读取固件失败：{str(e)}")
        return None

# ------------------------------------------------------------------------------
# 步骤4：修改 MD5
# ------------------------------------------------------------------------------
def step4_patch(filename, old_md5, password):
    print("\n=== 步骤4：修改固件密码 ===")
    try:
        new_md5 = hashlib.md5((password + "\n").encode()).hexdigest()
        with open(filename, "rb") as f:
            buf = f.read()
        old_bytes = bytes.fromhex(old_md5)
        new_bytes = bytes.fromhex(new_md5)
        if old_bytes not in buf:
            print("[错误] 原始 MD5 不匹配，无法修改")
            return None, None
        new_buf = buf.replace(old_bytes, new_bytes)
        new_file = "patched.bin"
        with open(new_file, "wb") as f:
            f.write(new_buf)
        new_sha256 = hashlib.sha256(new_buf).hexdigest()
        print(f"[成功] 新固件：{new_file}")
        print(f"[成功] 新 SHA256：{new_sha256}")
        return new_file, new_sha256
    except Exception as e:
        print(f"[错误] 修改失败：{str(e)}")
        return None, None

# ------------------------------------------------------------------------------
# 步骤5：本地劫持服务器（教程原版结构）
# ------------------------------------------------------------------------------
def step5_start_server(local_ip, firmware_path, new_sha256):
    print("\n=== 步骤5：启动本地更新服务器 ===")
    try:
        # 文件服务器 8080
        def file_server():
            os.chdir(os.path.dirname(os.path.abspath(firmware_path)))
            socketserver.TCPServer.allow_reuse_address = True
            http.server.ThreadingHTTPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()

        # OTA 劫持 80
        def ota_server():
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    url = f"http://{local_ip}:8080/{os.path.basename(firmware_path)}"
                    res = {
                        "status": 1000,
                        "msg": "success",
                        "data": {
                            "version": {
                                "deltaUrl": url,
                                "fullUrl": url,
                                "segmentMd5": CAPTURED["segmentMd5"],
                                "endPos": CAPTURED["endPos"],
                                "sha256sum": new_sha256,
                                "versionName": "9.9.9",
                                "force": 1
                            }
                        }
                    }
                    self.wfile.write(json.dumps(res, ensure_ascii=False).encode())
                def log_message(self, *args):
                    pass
            socketserver.TCPServer.allow_reuse_address = True
            http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()

        threading.Thread(target=file_server, daemon=True).start()
        threading.Thread(target=ota_server, daemon=True).start()

        print(f"[成功] 服务器已启动")
        print(f"\n请在设备 HOSTS 添加：")
        print(f"{local_ip}    {CAPTURED['host']}")
        print("\n然后在词典笔点：检查更新 → 升级即可开启 ADB")
        return True
    except Exception as e:
        print(f"[错误] 启动服务器失败：{str(e)}")
        print("请以管理员权限运行，或关闭占用 80/8080 端口的程序")
        return False

# ------------------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------------------
def main():
    print("==============================================")
    print("       有道词典笔 ADB 开启 · 教程对齐版")
    print("==============================================")
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

    pwd = input("\n请设置 ADB 密码：").strip()
    if not pwd:
        print("[错误] 密码不能为空")
        os.system("pause")
        return

    new_fw, sha256 = step4_patch(fw, old_md5, pwd)
    if not new_fw:
        os.system("pause")
        return

    if not step5_start_server(ip, new_fw, sha256):
        os.system("pause")
        return

    print("\n运行中，按 Ctrl + C 退出")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n退出程序")
    except Exception as e:
        print(f"\n[崩溃] {str(e)}")
        os.system("pause")
