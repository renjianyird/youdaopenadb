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

# ==============================
# 完全按照你给的教程流程编写
# 无任何自创逻辑
# ==============================

CAPTURE = {
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

# ==============================
# 步骤1：抓包 checkVersion 响应
# ==============================
def packet_callback(pkt):
    if IP in pkt and TCP in pkt and Raw in pkt:
        try:
            data = pkt[Raw].load.decode("utf-8", "ignore")
            
            # 取HOST
            if "checkVersion" in data:
                res = re.findall(r"Host:\s*(.+)", data)
                if res:
                    CAPTURE["host"] = res[0].strip()

            # 取更新JSON
            if "status" in data and "deltaUrl" in data:
                js = re.search(r"(\{.*\})", data, re.DOTALL)
                if js:
                    obj = json.loads(js.group(1))
                    ver = obj["data"]["version"]
                    CAPTURE["deltaUrl"] = ver["deltaUrl"]
                    CAPTURE["segmentMd5"] = ver["segmentMd5"]
                    CAPTURE["endPos"] = ver["endPos"]
                    return True
        except:
            pass
    return False

def step1_capture():
    print("=== 步骤1：抓包检查更新 ===")
    print("请：词典笔连热点 → 设置 → 检查更新")
    try:
        sniff(stop_filter=packet_callback, store=0, timeout=120)
    except Exception as e:
        print("抓包失败，请管理员运行并安装Npcap")
        return False
    if not CAPTURE["deltaUrl"]:
        print("未获取到更新包")
        return False
    print("✅ 抓包成功")
    return True

# ==============================
# 步骤2：下载官方update.bin
# ==============================
def step2_download():
    print("=== 步骤2：下载更新包 ===")
    url = CAPTURE["deltaUrl"]
    r = requests.get(url, stream=True)
    with open("update.bin", "wb") as f:
        for c in r.iter_content(1024*1024):
            f.write(c)
    print("✅ 下载完成：update.bin")
    return "update.bin"

# ==============================
# 步骤3：提取原始MD5
# ==============================
def step3_extract_md5(path):
    print("=== 步骤3：提取原始MD5 ===")
    with open(path, "rb") as f:
        data = f.read()
    match = re.findall(rb"[0-9a-fA-F]{32}", data)
    old = match[0].decode().lower()
    print("原始MD5:", old)
    return old

# ==============================
# 步骤4：修改密码MD5
# ==============================
def step4_patch(path, old_md5, pwd):
    print("=== 步骤4：修改固件 ===")
    new_md5 = hashlib.md5((pwd + "\n").encode()).hexdigest()
    with open(path, "rb") as f:
        buf = f.read()
    buf = buf.replace(bytes.fromhex(old_md5), bytes.fromhex(new_md5))
    with open("patched.bin", "wb") as f:
        f.write(buf)
    sha256 = hashlib.sha256(buf).hexdigest()
    print("✅ 已生成：patched.bin")
    return "patched.bin", sha256

# ==============================
# 步骤5：本地劫持服务器
# 完全按教程字段返回
# ==============================
def step5_start_server(local_ip, fw_path, sha256):
    print("=== 步骤5：启动本地服务器 ===")

    def file_server():
        os.chdir(os.path.dirname(os.path.abspath(fw_path)))
        socketserver.TCPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()

    def ota_server():
        class OTAHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                url = f"http://{local_ip}:8080/{os.path.basename(fw_path)}"
                ret = {
                    "status": 1000,
                    "msg": "success",
                    "data": {
                        "version": {
                            "deltaUrl": url,
                            "fullUrl": url,
                            "segmentMd5": CAPTURE["segmentMd5"],
                            "endPos": CAPTURE["endPos"],
                            "sha256sum": sha256,
                            "force": 1
                        }
                    }
                }
                self.wfile.write(json.dumps(ret).encode())
            def log_message(self, *args):
                pass
        socketserver.TCPServer(("0.0.0.0", 80), OTAHandler).serve_forever()

    threading.Thread(target=file_server, daemon=True).start()
    threading.Thread(target=ota_server, daemon=True).start()

    print("✅ 服务已启动")
    print("设备HOSTS：")
    print(f"{local_ip}    {CAPTURE['host']}")

# ==============================
# 主流程（严格按教程顺序）
# 1.抓包 2.下载 3.提取MD5 4.修改 5.劫持
# ==============================
def main():
    print("==================================")
    print("      按你教程完整重写版")
    print("==================================")
    ip = get_local_ip()
    print("本机IP:", ip)

    if not step1_capture():
        input("按回车退出")
        return

    bin_file = step2_download()
    old_md5 = step3_extract_md5(bin_file)

    pwd = input("\n设置ADB密码：").strip()
    if not pwd:
        print("密码不能为空")
        return

    new_bin, sha = step4_patch(bin_file, old_md5, pwd)
    step5_start_server(ip, new_bin, sha)

    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print("错误:", e)
        input("退出...")
