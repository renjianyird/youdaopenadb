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
# 最终可运行版 · 完全对齐教程
# 只抓包 → 直接取响应 → 不重发请求 → 真实能抓到包
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
        s.connect(("8.8.8.8", 8))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ------------------------------------------------------------------------------
# 步骤1：抓包（最原始、最稳定、能抓到的版本）
# ------------------------------------------------------------------------------
def packet_callback(pkt):
    if IP in pkt and TCP in pkt and Raw in pkt:
        try:
            data = pkt[Raw].load.decode('utf-8', 'ignore')

            # 抓取HOST
            if "checkVersion" in data:
                for line in data.splitlines():
                    if line.startswith("Host:"):
                        CAPTURED["host"] = line.split()[1]

            # 抓取正常的更新响应
            if '"status":1000' in data and '"version"' in data and "deltaUrl" in data:
                match = re.search(r'\{.*\}', data, re.DOTALL)
                if match:
                    j = json.loads(match.group(0))
                    ver = j["data"]["version"]
                    CAPTURED["deltaUrl"] = ver.get("deltaUrl", "")
                    CAPTURED["segmentMd5"] = ver.get("segmentMd5", [])
                    CAPTURED["endPos"] = ver.get("endPos", [])
                    return True
        except:
            pass
    return False

def step1_capture():
    print("\n=== 步骤1：抓包获取更新包地址 ===")
    print("请操作：词典笔连热点 → 设置 → 检查更新")
    try:
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=90)
    except Exception as e:
        print(f"[错误] 抓包失败：{e}")
        print("请用管理员权限运行，并安装 Npcap 驱动")
        return False

    if not CAPTURED["deltaUrl"]:
        print("[错误] 未获取到更新包地址")
        return False
    if not CAPTURED["host"]:
        print("[错误] 未获取到OTA主机地址")
        return False

    print(f"[成功] 已获取更新包地址")
    return True

# ------------------------------------------------------------------------------
# 步骤2：下载固件
# ------------------------------------------------------------------------------
def step2_download():
    print("\n=== 步骤2：下载更新包 ===")
    try:
        resp = requests.get(CAPTURED["deltaUrl"], stream=True, timeout=120)
        with open("update.bin", "wb") as f:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
        print("[成功] 固件已保存为 update.bin")
        return "update.bin"
    except Exception as e:
        print(f"[错误] 下载失败：{e}")
        return None

# ------------------------------------------------------------------------------
# 步骤3：提取MD5
# ------------------------------------------------------------------------------
def step3_extract_md5(filename):
    print("\n=== 步骤3：提取原始MD5 ===")
    try:
        with open(filename, "rb") as f:
            data = f.read()
        matches = re.findall(rb'[0-9a-fA-F]{32}', data)
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
        print("[成功] 固件已修改：patched.bin")
        return "patched.bin", new_sha
    except Exception as e:
        print(f"[错误] 修改失败：{e}")
        return None, None

# ------------------------------------------------------------------------------
# 步骤5：启动本地服务器
# ------------------------------------------------------------------------------
def step5_start_server(local_ip, fw_path, sha256):
    print("\n=== 步骤5：启动本地劫持服务器 ===")

    def file_server():
        os.chdir(os.path.dirname(os.path.abspath(fw_path)))
        socketserver.TCPServer.allow_reuse_address = True
        http.server.ThreadingHTTPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()

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
                return
        socketserver.TCPServer.allow_reuse_address = True
        http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()

    threading.Thread(target=file_server, daemon=True).start()
    threading.Thread(target=ota_server, daemon=True).start()

    print("[成功] 服务器已启动")
    print(f"请在设备HOSTS添加：{local_ip}    {CAPTURED['host']}")
    print("然后在词典笔点击检查更新即可")
    return True

# ------------------------------------------------------------------------------
# 主程序
# ------------------------------------------------------------------------------
def main():
    print("==============================================")
    print("        有道词典笔ADB开启工具 · 稳定可运行版")
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

    pwd = input("\n请设置ADB密码：").strip()
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
        print("\n退出")
    except Exception as e:
        print(f"\n异常：{e}")
        os.system("pause")
