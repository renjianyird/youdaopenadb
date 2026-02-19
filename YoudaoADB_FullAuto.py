import os
import sys
import json
import hashlib
import socket
import threading
import http.server
import socketserver
import requests
import time
import re
from scapy.all import sniff, IP, TCP, Raw, conf

# ====================== 版本信息 ======================
VERSION = "5.0"
AUTHOR = "喂鸡 (Wei Ji)"
COPYRIGHT = "Copyright (C) 2026 喂鸡 (Wei Ji). All rights reserved."

# ====================== 全局变量 ======================
CAPTURED_DATA = {
    "ota_url": "",
    "post_data": {},
    "timestamp": "",
    "sign": "",
    "mid": "",
    "productId": ""
}

ERROR_LOG = []

def log_error(error_code, message, details=""):
    error_entry = {
        "code": error_code,
        "message": message,
        "details": details,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    ERROR_LOG.append(error_entry)
    print(f"\n[错误 {error_code}] {message}")
    if details:
        print(f"详细信息: {details}")

def save_error_log():
    if not ERROR_LOG:
        return
    log_file = "YoudaoADB_ErrorLog.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("YoudaoADB Tools - Error Log\n")
        f.write("="*50 + "\n")
        for entry in ERROR_LOG:
            f.write(f"[{entry['time']}] {entry['code']}: {entry['message']}\n")
            if entry['details']:
                f.write(f"Details: {entry['details']}\n")
            f.write("\n")
    print(f"\n日志已保存: {os.path.abspath(log_file)}")

def print_title():
    os.system(f"title YoudaoADB Tools V{VERSION}")
    print("=" * 70)
    print(f"           YoudaoADB Tools  V{VERSION}")
    print("=" * 70)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 8))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"

def input_step(msg):
    print(f"\n -> {msg}")
    return input("> ").strip()

# ====================== 抓包模块 ======================
def packet_callback(packet):
    if IP in packet and TCP in packet and Raw in packet:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "checkVersion" in payload and "application/json" in payload:
                lines = payload.split('\r\n')
                host_line = next((l for l in lines if l.startswith('Host: ')), '')
                host = host_line.split(' ')[1]
                path_line = lines[0].split(' ')[1]
                CAPTURED_DATA["ota_url"] = f"{host}{path_line}"

                json_part = payload.split('\r\n\r\n')[1]
                post_data = json.loads(json_part)
                CAPTURED_DATA["post_data"] = post_data

                # 伪造为低版本号，让服务器下发固件
                if "currentVersion" in post_data:
                    CAPTURED_DATA["post_data"]["currentVersion"] = "4.88"
                if "deltaVersion" in post_data:
                    del CAPTURED_DATA["post_data"]["deltaVersion"]

                CAPTURED_DATA["timestamp"] = post_data.get("timestamp", "")
                CAPTURED_DATA["sign"] = post_data.get("sign", "")
                CAPTURED_DATA["mid"] = post_data.get("mid", "")
                CAPTURED_DATA["productId"] = post_data.get("productId", "")
                return True
        except Exception:
            return False
    return False

def auto_capture():
    print("\n[*] 正在启动抓包...")
    print("[提示] 请把词典笔连接电脑热点，然后在设备上点击“检查更新”")
    try:
        conf.iface = conf.iface
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=60)
        if not CAPTURED_DATA["ota_url"]:
            print("\n[!] 未抓到有效信息，请重试")
            return False
        print("\n[+] 抓包完成，已准备好获取固件")
        return True
    except Exception:
        print("\n[!] 抓包失败，请用管理员权限运行")
        return False

# ====================== 固件下载 ======================
def download_original_firmware():
    print("\n[*] 正在获取固件...")
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    try:
        r = requests.post(
            f"http://{CAPTURED_DATA['ota_url']}",
            json=CAPTURED_DATA["post_data"],
            headers=headers,
            timeout=15
        )
        r.raise_for_status()
        j = r.json()

        if j.get("status") == 2101:
            print("\n[!] 设备已是最新版本，正在尝试切换为低版本获取固件")
            return None, None

        ver = j["data"]["version"]
        url = ver.get("deltaUrl") or ver.get("fullUrl")
        seg = json.loads(ver["segmentMd5"])
        endpos = [x["endpos"] for x in seg]

        print("[+] 正在下载固件，请稍等...")
        with open("original.img", "wb") as f:
            with requests.get(url, stream=True, timeout=120) as resp:
                for chunk in resp.iter_content(1024*1024):
                    f.write(chunk)
        print("[+] 固件下载完成")
        return "original.img", endpos

    except Exception as e:
        print(f"\n[!] 获取固件失败: {e}")
        return None, None

# ====================== 固件修改 ======================
def md5_hex(data):
    return hashlib.md5(data).hexdigest()

def file_md5_hex(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()

def sha256_hex(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()

def calc_new_pass_md5(password):
    raw = (password + "\n").encode("utf-8")
    return md5_hex(raw)

def search_and_replace_md5_in_img(img_path, old_md5, new_md5):
    with open(img_path, "rb") as f:
        data = f.read()
    old_bytes = bytes.fromhex(old_md5)
    new_bytes = bytes.fromhex(new_md5)
    new_data = data.replace(old_bytes, new_bytes)
    with open("modified_firmware.img", "wb") as f:
        f.write(new_data)
    print("[+] 固件修改完成")
    return "modified_firmware.img"

def search_original_adb_md5(img_path):
    with open(img_path, "rb") as f:
        data = f.read()
    match = re.search(rb"[0-9a-fA-F]{32}", data)
    if match:
        s = match.group(0).hex() if isinstance(match.group(0), bytes) else match.group(0)
        print(f"[+] 已识别原始密码信息")
        return s
    return None

# ====================== 服务启动 ======================
def start_file_server(local_ip, img_path):
    os.chdir(os.path.dirname(os.path.abspath(img_path)))
    port = 14514
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

def start_ota_server(local_ip, modified_img, endpos_list):
    img_name = os.path.basename(modified_img)
    url = f"http://{local_ip}:14514/{img_name}"
    f_md5 = file_md5_hex(modified_img)
    f_sha = sha256_hex(modified_img)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.end_headers()
            seg = json.dumps([{
                "num": i,
                "startpos": 0 if i == 0 else endpos_list[i-1],
                "endpos": endpos_list[i],
                "md5": "0"*32
            } for i in range(len(endpos_list))])
            res = {
                "status": 1000,
                "msg": "success",
                "data": {
                    "releaseNotes": {"version":"99.99.99"},
                    "version": {
                        "deltaUrl": url,
                        "bakUrl": url,
                        "md5sum": f_md5,
                        "sha": f_sha,
                        "segmentMd5": seg,
                        "versionName": "99.99.99"
                    }
                }
            }
            self.wfile.write(json.dumps(res).encode())

    server = socketserver.TCPServer((local_ip, 80), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("[+] 升级服务已启动")

# ====================== 主流程 ======================
def main():
    print_title()
    local_ip = get_local_ip()
    print(f"本机IP: {local_ip}")

    if not auto_capture():
        save_error_log()
        os.system("pause")
        return

    new_pass = input_step("设置你要的ADB密码")
    if not new_pass:
        print("[!] 密码不能为空")
        os.system("pause")
        return

    original_img, endpos = download_original_firmware()
    if not original_img:
        save_error_log()
        os.system("pause")
        return

    old_md5 = search_original_adb_md5(original_img)
    new_md5 = calc_new_pass_md5(new_pass)
    modified_img = search_and_replace_md5_in_img(original_img, old_md5, new_md5)

    start_file_server(local_ip, modified_img)
    start_ota_server(local_ip, modified_img, endpos)

    print("\n" + "="*50)
    print("[下一步操作]")
    print(f"1. 在HOSTS添加：{local_ip} iotapi.abupdate.com")
    print("2. 打开CMD执行：ipconfig /flushdns")
    print("3. 词典笔点击检查更新并安装")
    print(f"4. ADB密码：{new_pass}")
    print("="*50)

    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        log_error("CRASH", "程序异常", str(e))
        save_error_log()
        os.system("pause")
