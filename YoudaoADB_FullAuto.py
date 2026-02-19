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
# 【终极·不玩任何花样·抓包必中版】
# 不过滤、不判断、不强转、抓到就停
# ------------------------------------------------------------------------------
def packet_callback(pkt):
    try:
        if IP in pkt and TCP in pkt and Raw in pkt:
            raw = pkt[Raw].load
            data = raw.decode('utf-8', 'ignore')
            
            if "checkVersion" in data:
                match = re.search(r"Host:\s*([^\r\n]+)", data)
                if match:
                    CAPTURED["host"] = match.group(1)

            if "deltaUrl" in data and "status" in data:
                jmatch = re.search(r"\{.*\}", data, re.DOTALL)
                if jmatch:
                    j = json.loads(jmatch.group(0))
                    ver = j["data"]["version"]
                    CAPTURED["deltaUrl"] = ver.get("deltaUrl")
                    CAPTURED["segmentMd5"] = ver.get("segmentMd5", [])
                    CAPTURED["endPos"] = ver.get("endPos", [])
                    print("[INFO] 抓包成功！")
                    return True
    except:
        pass
    return False

def step1_capture():
    print("\n=== 步骤1：抓包（请点检查更新）===")
    try:
        sniff(iface=None, prn=None, stop_filter=packet_callback, store=0, timeout=120)
    except Exception as e:
        print(f"错误：{e}")
        return False

    if not CAPTURED["deltaUrl"]:
        print("抓包失败")
        return False
    print("成功获取更新包地址")
    return True

# ------------------------------------------------------------------------------
# 步骤2：下载
# ------------------------------------------------------------------------------
def step2_download():
    print("\n=== 步骤2：下载固件 ===")
    r = requests.get(CAPTURED["deltaUrl"], stream=True, timeout=200)
    with open("update.bin", "wb") as f:
        for chunk in r.iter_content(1024*1024):
            f.write(chunk)
    print("下载完成")
    return "update.bin"

# ------------------------------------------------------------------------------
# 步骤3：提取MD5
# ------------------------------------------------------------------------------
def step3_extract_md5(fn):
    print("\n=== 步骤3：提取MD5 ===")
    with open(fn, "rb") as f:
        d = f.read()
    matches = re.findall(rb"[0-9a-fA-F]{32}", d)
    old = matches[0].decode().lower()
    print("OLD MD5:", old)
    return old

# ------------------------------------------------------------------------------
# 步骤4：修改固件
# ------------------------------------------------------------------------------
def step4_patch(fn, old_md5, pwd):
    print("\n=== 步骤4：修改固件 ===")
    new_md5 = hashlib.md5((pwd + "\n").encode()).hexdigest()
    with open(fn, "rb") as f:
        buf = f.read()
    buf = buf.replace(bytes.fromhex(old_md5), bytes.fromhex(new_md5))
    with open("patched.bin", "wb") as f:
        f.write(buf)
    sha = hashlib.sha256(buf).hexdigest()
    print("修改完成")
    return "patched.bin", sha

# ------------------------------------------------------------------------------
# 步骤5：服务器（完全按教程字段）
# ------------------------------------------------------------------------------
def step5_server(ip, fw_path, sha):
    def file_srv():
        os.chdir(os.path.dirname(os.path.abspath(fw_path)))
        with socketserver.ThreadingTCPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler) as s:
            s.serve_forever()
    def ota_srv():
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type","application/json; charset=utf-8")
                self.end_headers()
                url = f"http://{ip}:8080/{os.path.basename(fw_path)}"
                res = {
                    "status": 1000,
                    "msg": "success",
                    "data": {
                        "version": {
                            "deltaUrl": url,
                            "fullUrl": url,
                            "segmentMd5": CAPTURED["segmentMd5"],
                            "endPos": CAPTURED["endPos"],
                            "sha256sum": sha,
                            "force": 1
                        }
                    }
                }
                self.wfile.write(json.dumps(res).encode())
            def log_message(self, *args): pass
        with socketserver.ThreadingTCPServer(("0.0.0.0",80), H) as s:
            s.serve_forever()
    threading.Thread(target=file_srv, daemon=True).start()
    threading.Thread(target=ota_srv, daemon=True).start()
    print("\n=== 服务器已启动 ===")
    print(f"{ip}    {CAPTURED['host']}")

# ------------------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------------------
def main():
    print("=== 最终稳定版 ===")
    lip = get_local_ip()
    print("本机IP:", lip)
    if not step1_capture(): return
    fw = step2_download()
    old = step3_extract_md5(fw)
    pwd = input("输入密码:")
    nfw, sha = step4_patch(fw, old, pwd)
    step5_server(lip, nfw, sha)
    while 1: time.sleep(1)

if __name__ == "__main__":
    main()
