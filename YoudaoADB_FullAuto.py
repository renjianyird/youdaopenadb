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

ERROR_LOG = []

def log_error(error_code, message, details=""):
    """记录错误到日志"""
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
    """保存错误日志到文件"""
    if not ERROR_LOG:
        return
    log_file = "YoudaoADB_ErrorLog.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("有道词典笔ADB工具 - 错误日志\n")
        f.write("="*50 + "\n")
        for entry in ERROR_LOG:
            f.write(f"[{entry['time']}] 错误 {entry['code']}: {entry['message']}\n")
            if entry['details']:
                f.write(f"  详情: {entry['details']}\n")
            f.write("\n")
    print(f"\n错误日志已保存到: {os.path.abspath(log_file)}")

# ==============================================
# 有道词典笔 ADB 全自动破解工具 - 全能一体化版
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
    print("=" * 70)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        log_error("E001", "获取本机IP失败", str(e))
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
                
                lines = payload.split('\r\n')
                host_line = next((l for l in lines if l.startswith('Host: ')), '')
                if not host_line:
                    raise ValueError("未找到Host头")
                host = host_line.split(' ')[1]
                path_line = lines[0].split(' ')[1]
                CAPTURED_DATA["ota_url"] = f"{host}{path_line}"

                json_part = payload.split('\r\n\r\n')[1]
                post_data = json.loads(json_part)
                CAPTURED_DATA["post_data"] = post_data
                CAPTURED_DATA["timestamp"] = post_data.get("timestamp", "")
                CAPTURED_DATA["sign"] = post_data.get("sign", "")
                CAPTURED_DATA["mid"] = post_data.get("mid", "")
                CAPTURED_DATA["productId"] = post_data.get("productId", "")

                print(f"[+] 自动提取 OTA URL: {CAPTURED_DATA['ota_url']}")
                return True
        except Exception as e:
            log_error("E101", "解析OTA数据包失败", str(e))
    return False

def auto_capture():
    print("\n[*] 正在启动自动抓包...")
    print("[!] 请确保词典笔已连接到电脑热点，并在词典笔设置中点击 '检查更新'")
    try:
        conf.iface = conf.iface
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=60)
        
        if not CAPTURED_DATA["ota_url"]:
            log_error("E102", "60秒内未捕获到有效OTA请求", "请确保词典笔已连接热点并触发检查更新")
            return False
        print("[+] 抓包完成，所有参数已自动填充!")
        return True
    except Exception as e:
        log_error("E103", "抓包模块启动失败", f"请以管理员身份运行程序，并确保安装Npcap: {str(e)}")
        return False

# ====================== 2. 下载与解包模块 ======================
def download_original_firmware(max_retries=3):
    retries = 0
    while retries < max_retries:
        print(f"\n[*] 正在获取官方全量固件... (尝试 {retries + 1}/{max_retries})")
        headers = {"Content-Type": "application/json;charset=UTF-8"}
        try:
            r = requests.post(
                f"http://{CAPTURED_DATA['ota_url']}",
                json=CAPTURED_DATA["post_data"],
                headers=headers,
                timeout=30
            )
            r.raise_for_status()
            j = r.json()
            
            url = j["data"]["version"]["deltaUrl"]
            seg = json.loads(j["data"]["version"]["segmentMd5"])
            endpos = [x["endpos"] for x in seg]
            
            print(f"[+] 固件地址：{url}")
            with open("original.img", "wb") as f:
                with requests.get(url, stream=True, timeout=60) as resp:
                    resp.raise_for_status()
                    for chunk in resp.iter_content(1024*1024):
                        f.write(chunk)
            print("[+] 官方固件下载完成")
            return "original.img", endpos
            
        except requests.exceptions.RequestException as e:
            retries += 1
            log_error("E201", f"网络请求失败 (尝试 {retries}/{max_retries})", str(e))
        except (KeyError, json.JSONDecodeError) as e:
            retries += 1
            log_error("E202", f"解析固件地址失败 (尝试 {retries}/{max_retries})", f"服务器返回格式异常: {str(e)}")
        except Exception as e:
            retries += 1
            log_error("E203", f"下载固件时发生未知错误 (尝试 {retries}/{max_retries})", str(e))
        
        if retries < max_retries:
            print(f"[!] 将在 5 秒后重试...")
            time.sleep(5)
    
    log_error("E204", "连续多次获取固件地址失败", "请检查网络连接和OTA参数有效性")
    return None, None

# ====================== 3. 修改与校验模块 ======================
def md5_hex(data):
    return hashlib.md5(data).hexdigest()

def sha256_hex(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1024*1024), b""):
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        log_error("E301", f"计算文件SHA256失败: {path}", str(e))
        return None

def file_md5_hex(path):
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1024*1024), b""):
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        log_error("E302", f"计算文件MD5失败: {path}", str(e))
        return None

def calc_new_pass_md5(password):
    try:
        raw = (password + "\n").encode("utf-8")
        return md5_hex(raw)
    except Exception as e:
        log_error("E303", "计算新密码MD5失败", str(e))
        return None

def search_and_replace_md5_in_img(img_path, old_md5_hex, new_md5_hex):
    try:
        old_bytes = bytes.fromhex(old_md5_hex)
        new_bytes = bytes.fromhex(new_md5_hex)

        with open(img_path, "rb") as f:
            data = f.read()

        if old_bytes not in data:
            log_error("E304", "未在固件中找到原MD5", "可能型号不匹配或固件已损坏")
            return None

        new_data = data.replace(old_bytes, new_bytes)
        new_img = "modified_firmware.img"

        with open(new_img, "wb") as f:
            f.write(new_data)

        print(f"[+] MD5替换完成！新固件：{new_img}")
        return new_img
    except Exception as e:
        log_error("E305", "替换固件中的MD5失败", str(e))
        return None

def search_original_adb_md5(img_path):
    try:
        print("\n[*] 自动扫描固件中的adb密码MD5...")
        with open(img_path, "rb") as f:
            data = f.read()
        pattern = b"[0-9a-f]{32}  -"
        match = re.search(pattern, data, re.I)
        if match:
            s = match.group(0).decode().split()[0]
            print(f"[+] 找到原MD5：{s}")
            return s
        log_error("E306", "无法自动提取MD5", "固件格式可能不支持")
        return None
    except Exception as e:
        log_error("E307", "扫描固件中的MD5失败", str(e))
        return None

# ====================== 4. 服务器模块 ======================
def start_file_server(local_ip, img_path):
    try:
        os.chdir(os.path.dirname(os.path.abspath(img_path)) or ".")
        port = 14514
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[+] 文件服务启动：http://{local_ip}:14514")
        return True
    except Exception as e:
        log_error("E401", "启动文件服务器失败", f"端口 {14514} 可能被占用: {str(e)}")
        return False

def start_ota_server(local_ip, modified_img, endpos_list):
    try:
        img_name = os.path.basename(modified_img)
        url = f"http://{local_ip}:14514/{img_name}"
        f_md5 = file_md5_hex(modified_img)
        f_sha = sha256_hex(modified_img)

        if not f_md5 or not f_sha:
            raise ValueError("无法计算固件校验值")

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
        return True
    except Exception as e:
        log_error("E402", "启动OTA劫持服务器失败", f"端口 80 可能被占用或权限不足: {str(e)}")
        return False

# ====================== 主程序 ======================
def main():
    print_title()
    local_ip = get_local_ip()
    print(f"本机IP：{local_ip}")

    # 1. 自动抓包
    if not auto_capture():
        print("\n[!] 抓包失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

    # 2. 设置新密码
    new_pass = input_step("设置你要的ADB新密码")
    if not new_pass:
        log_error("E002", "未设置ADB新密码", "密码不能为空")
        save_error_log()
        os.system("pause")
        return

    # 3. 下载官方固件
    original_img, endpos = download_original_firmware()
    if not original_img or not endpos:
        print("\n[!] 下载固件失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

    # 4. 自动提取原MD5
    old_md5 = search_original_adb_md5(original_img)
    if not old_md5:
        print("\n[!] 提取原MD5失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

    # 5. 计算新密码MD5（带换行）
    new_md5 = calc_new_pass_md5(new_pass)
    if not new_md5:
        print("\n[!] 计算新密码MD5失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return
    print(f"新密码MD5：{new_md5}")

    # 6. 替换MD5生成新固件
    modified_img = search_and_replace_md5_in_img(original_img, old_md5, new_md5)
    if not modified_img:
        print("\n[!] 生成新固件失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

    # 7. 启动双服务器
    if not start_file_server(local_ip, modified_img):
        print("\n[!] 启动文件服务器失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

    if not start_ota_server(local_ip, modified_img, endpos):
        print("\n[!] 启动OTA服务器失败，程序无法继续。")
        save_error_log()
        os.system("pause")
        return

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
        if os.name == 'nt' and not sys.argv[0].endswith('exe'):
            print("[!] 抓包功能需要管理员权限，请以管理员身份运行此脚本。")
        main()
    except KeyboardInterrupt:
        print("\n[*] 用户主动退出程序。")
    except Exception as e:
        log_error("E999", "程序发生未捕获的致命错误", str(e))
        save_error_log()
        print("\n[!] 程序异常退出，请查看错误日志。")
        os.system("pause")
