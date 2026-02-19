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

# ====================== 版本信息（会由 GitHub Action 自动更新）======================
VERSION = "2.0"
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

# ==============================================
# 有道词典笔 ADB 全自动破解工具 - 全能一体化版
# 功能：自动抓包 -> 下载固件 -> 替换密码 -> 自动服务
# 无任何外部依赖 - 单EXE - 小白一键完成
# ==============================================

def print_title():
    os.system("title 有道词典笔ADB全自动工具 V" + VERSION)
    print("=" * 70)
    print(f"    有道词典笔 ADB 全自动破解工具  V{VERSION}")
    print("    全流程一体化 - 自动抓包 - 无需手动输入")
    print("-" * 70)
    print(f"    作者：{AUTHOR}")
    print(f"    {COPYRIGHT}")
    print("-" * 70)
    print("    注意：本工具仅限学习研究，请勿用于商业用途")
    print("    注意：一切风险自行承担，版权所有，侵权必究")
    print("=" * 70)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "192.168.1.100"

def input_step(msg):
    print(f"\n -> {msg}")
    return input("> ").strip()

# ====================== 1. 自动抓包模块 ======================
def packet_callback(packet):
    if IP in packet and TCP in packet and Raw in packet:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "checkVersion" in payload and "application/json" in payload:
                print("[+] 捕获到 OTA 检查请求!")
                
                # 解析 OTA URL
                lines = payload.split('\r\n')
                host_line = next((l for l in lines if l.startswith('Host: ')), '')
                host = host_line.split(' ')[1]
                path_line = lines[0].split(' ')[1]
                CAPTURED_DATA["ota_url"] = f"{host}{path_line}"

                # 解析 POST 数据
                json_part = payload.split('\r\n\r\n')[1]
                post_data = json.loads(json_part)
                CAPTURED_DATA["post_data"] = post_data
                CAPTURED_DATA["timestamp"] = post_data.get("timestamp", "")
                CAPTURED_DATA["sign"] = post_data.get("sign", "")
                CAPTURED_DATA["mid"] = post_data.get("mid", "")
                CAPTURED_DATA["productId"] = post_data.get("productId", "")

                print(f"[+] 自动提取 OTA URL: {CAPTURED_DATA['ota_url']}")
                print(f"[+] 自动提取 timestamp: {CAPTURED_DATA['timestamp']}")
                print(f"[+] 自动提取 sign: {CAPTURED_DATA['sign']}")
                print(f"[+] 自动提取 mid: {CAPTURED_DATA['mid']}")
                print(f"[+] 自动提取 productId: {CAPTURED_DATA['productId']}")
                return True
        except Exception as e:
            print(f"[-] 解析数据包时出错: {e}")
    return False

def auto_capture():
    print("\n[*] 正在启动自动抓包...")
    print("[!] 请确保词典笔已连接到电脑热点，并在词典笔设置中点击 '检查更新'")
    conf.iface = conf.iface  # 使用默认网卡
    sniff(prn=lambda x: None, stop_filter=packet_callback, store=0)
    
    if not CAPTURED_DATA["ota_url"]:
        print("[-] 未捕获到有效 OTA 请求，请重试。")
        sys.exit(1)
    print("[+] 抓包完成，所有参数已自动填充!")

# ====================== 2. 下载与解包模块 ======================
def download_original_firmware():
    print("\n[*] 正在获取官方全量固件...")
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    r = requests.post(f"http://{CAPTURED_DATA['ota_url']}", 
                      json=CAPTURED_DATA["post_data"], 
                      headers=headers)
    j = r.json()
    try:
        url = j["data"]["version"]["deltaUrl"]
        seg = json.loads(j["data"]["version"]["segmentMd5"])
        endpos = [x["endpos"] for x in seg]
    except:
        print("[-] 解析固件地址失败")
        sys.exit(1)

    print(f"[+] 固件地址：{url}")
    with open("original.img", "wb") as f:
        with requests.get(url, stream=True) as resp:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
    print("[+] 官方固件下载完成")
    return "original.img", endpos

# ====================== 3. 修改与校验模块 ======================
def md5_hex(data):
    return hashlib.md5(data).hexdigest()

def sha256_hex(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()

def file_md5_hex(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()

def calc_new_pass_md5(password):
    raw = (password + "\n").encode("utf-8")
    return md5_hex(raw)

def search_and_replace_md5_in_img(img_path, old_md5_hex, new_md5_hex):
    old_bytes = bytes.fromhex(old_md5_hex)
    new_bytes = bytes.fromhex(new_md5_hex)

    with open(img_path, "rb") as f:
        data = f.read()

    if old_bytes not in data:
        print("[-] 未在固件中找到原MD5，可能型号不匹配")
        sys.exit(1)

    new_data = data.replace(old_bytes, new_bytes)
    new_img = "modified_firmware.img"

    with open(new_img, "wb") as f:
        f.write(new_data)

    print(f"[+] MD5替换完成！新固件：{new_img}")
    return new_img

def search_original_adb_md5(img_path):
    print("\n[*] 自动扫描固件中的adb密码MD5...")
    with open(img_path, "rb") as f:
        data = f.read()
    pattern = b"[0-9a-f]{32}  -"
    match = re.search(pattern, data, re.I)
    if match:
        s = match.group(0).decode().split()[0]
        print(f"[+] 找到原MD5：{s}")
        return s
    print("[-] 无法自动提取MD5")
    sys.exit(1)

# ====================== 4. 服务器模块 ======================
def start_file_server(local_ip, img_path):
    os.chdir(os.path.dirname(os.path.abspath(img_path)) or ".")
    port = 14514
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[+] 文件服务启动：http://{local_ip}:14514")

def start_ota_server(local_ip, modified_img, endpos_list):
    img_name = os.path.basename(modified_img)
    url = f"http://{local_ip}:14514/{img_name}"
    f_md5 = file_md5_hex(modified_img)
    f_sha = sha256_hex(modified_img)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/" + CAPTURED_DATA["ota_url"].split("/", 1)[1]:
                self.send_response(200)
                self.send_header("Content-Type", "application/json;charset=utf-8")
                self.end_headers()
                seg = json.dumps([{
                    "num": i,
                    "startpos": 0 if i == 0 else endpos_list[i-1],
                    "endpos": endpos_list[i],
                    "md5": "00000000000000000000000000000000"
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
                print("\n[+] 词典笔已连接！等待下载更新...")
            else:
                self.send_error(404)
    server = socketserver.TCPServer((local_ip, 80), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("[+] OTA劫持服务启动（端口80）")

# ====================== 主程序 ======================
def main():
    print_title()
    local_ip = get_local_ip()
    print(f"本机IP：{local_ip}")

    # 1. 自动抓包
    auto_capture()

    # 2. 设置新密码
    new_pass = input_step("设置你要的ADB新密码")

    # 3. 下载官方固件
    original_img, endpos = download_original_firmware()

    # 4. 自动提取原MD5
    old_md5 = search_original_adb_md5(original_img)

    # 5. 计算新密码MD5（带换行）
    new_md5 = calc_new_pass_md5(new_pass)
    print(f"新密码MD5：{new_md5}")

    # 6. 替换MD5生成新固件
    modified_img = search_and_replace_md5_in_img(original_img, old_md5, new_md5)

    # 7. 启动双服务器
    start_file_server(local_ip, modified_img)
    start_ota_server(local_ip, modified_img, endpos)

    # 8. 最终指引
    print("\n" + "="*70)
    print("[+] 全流程完成！现在只需：")
    print(f"1. 修改HOSTS：{local_ip} iotapi.abupdate.com")
    print("2. 刷新DNS：cmd 输入 ipconfig /flushdns")
    print("3. 词典笔连电脑热点 -> 检查更新 -> 安装")
    print(f"4. ADB密码：{new_pass}")
    print("="*70)
    print("\n按 Ctrl+C 退出")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        # 在Windows下以管理员权限运行才能抓包，这里进行提示
        if os.name == 'nt' and not sys.argv[0].endswith('exe'):
            print("[!] 抓包功能需要管理员权限，请以管理员身份运行此脚本。")
        main()
    except Exception as e:
        print(f"\n[-] 错误：{e}")
        os.system("pause")
