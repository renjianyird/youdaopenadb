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

# ====================== 版本信息（会由 GitHub Action 自动更新）======================
VERSION = "2.0"
AUTHOR = "喂鸡 (Wei Ji)"
COPYRIGHT = "Copyright © 2026 喂鸡 (Wei Ji). All rights reserved."

# ==============================================
# 有道词典笔 ADB 全自动破解工具 · 全能一体化版
# 功能：抓包 → 下载固件 → 替换密码 → 自动服务
# 无任何外部依赖 · 单EXE · 小白一键完成
# ==============================================

def print_title():
    os.system("title 有道词典笔ADB全自动工具 V" + VERSION)
    print("=" * 70)
    print(f"    🎉 有道词典笔 ADB 全自动破解工具  V{VERSION}")
    print("    🔥 全流程一体化 · 无需任何外部工具")
    print("-" * 70)
    print(f"    👤 作者：{AUTHOR}")
    print(f"    © {COPYRIGHT}")
    print("-" * 70)
    print("    ⚠️  本工具仅限学习研究，请勿用于商业用途")
    print("    ⚠️  一切风险自行承担，版权所有，侵权必究")
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
    print(f"\n👉 {msg}")
    return input("> ").strip()

def md5(data):
    return hashlib.md5(data).digest()

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
        print("❌ 未在固件中找到原MD5，可能型号不匹配")
        sys.exit(1)

    new_data = data.replace(old_bytes, new_bytes)
    new_img = "modified_firmware.img"

    with open(new_img, "wb") as f:
        f.write(new_data)

    print(f"✅ MD5替换完成！新固件：{new_img}")
    return new_img

def search_original_adb_md5(img_path):
    print("\n🔍 自动扫描固件中的adb密码MD5...")
    with open(img_path, "rb") as f:
        data = f.read()
    pattern = b"[0-9a-f]{32}  -"
    match = re.search(pattern, data, re.I)
    if match:
        s = match.group(0).decode().split()[0]
        print(f"✅ 找到原MD5：{s}")
        return s
    print("❌ 无法自动提取MD5")
    sys.exit(1)

def download_original_firmware(ota_url, post_data):
    print("\n📥 正在获取官方全量固件...")
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    r = requests.post("http://" + ota_url, json=post_data, headers=headers)
    j = r.json()
    try:
        url = j["data"]["version"]["deltaUrl"]
        seg = json.loads(j["data"]["version"]["segmentMd5"])
        endpos = [x["endpos"] for x in seg]
    except:
        print("❌ 解析固件地址失败")
        sys.exit(1)

    print(f"✅ 固件地址：{url}")
    with open("original.img", "wb") as f:
        with requests.get(url, stream=True) as resp:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
    print("✅ 官方固件下载完成")
    return "original.img", endpos

def start_file_server(local_ip, img_path):
    os.chdir(os.path.dirname(os.path.abspath(img_path)) or ".")
    port = 14514
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"✅ 文件服务启动：http://{local_ip}:14514")

def start_ota_server(local_ip, ota_path, modified_img, endpos_list):
    img_name = os.path.basename(modified_img)
    url = f"http://{local_ip}:14514/{img_name}"
    f_md5 = file_md5_hex(modified_img)
    f_sha = sha256_hex(modified_img)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == ota_path:
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
                print("\n✅ 词典笔已连接！等待下载更新...")
            else:
                self.send_error(404)
    server = socketserver.TCPServer((local_ip, 80), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("✅ OTA劫持服务启动（端口80）")

def main():
    print_title()
    local_ip = get_local_ip()
    print(f"🌐 本机IP：{local_ip}")

    new_pass = input_step("设置你要的ADB新密码")
    ota_url = input_step("输入抓包到的OTA域名+路径（如 iotapi.xxx.com/product/xxx/checkVersion）")
    ts = input_step("输入timestamp")
    sign = input_step("输入sign")
    mid = input_step("输入mid")
    pid = input_step("输入productId")

    post_data = {
        "timestamp": ts,
        "sign": sign,
        "mid": mid,
        "productId": pid,
        "version": "99.99.90",
        "networkType": "WIFI"
    }

    # 1. 下载官方固件
    original_img, endpos = download_original_firmware(ota_url, post_data)

    # 2. 自动提取原MD5
    old_md5 = search_original_adb_md5(original_img)

    # 3. 计算新密码MD5（带换行）
    new_md5 = calc_new_pass_md5(new_pass)
    print(f"🔐 新密码MD5：{new_md5}")

    # 4. 替换MD5生成新固件
    modified_img = search_and_replace_md5_in_img(original_img, old_md5, new_md5)

    # 5. 启动双服务器
    start_file_server(local_ip, modified_img)
    ota_path = "/" + ota_url.split("/", 1)[1]
    start_ota_server(local_ip, ota_path, modified_img, endpos)

    # 6. 最终指引
    print("\n" + "="*70)
    print("✅ 全流程完成！现在只需：")
    print(f"1. 修改HOSTS：{local_ip} iotapi.abupdate.com")
    print("2. 刷新DNS：cmd 输入 ipconfig /flushdns")
    print("3. 词典笔连电脑热点 → 检查更新 → 安装")
    print(f"4. ADB密码：{new_pass}")
    print("="*70)
    print("\n按 Ctrl+C 退出")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ 错误：{e}")
        os.system("pause")
