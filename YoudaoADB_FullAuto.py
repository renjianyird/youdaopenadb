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
VERSION = "5.1"
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
                    old_ver = CAPTURED_DATA["post_data"]["currentVersion"]
                    CAPTURED_DATA["post_data"]["currentVersion"] = "4.88"
                    print(f"[+] 版本号已从 {old_ver} 改为 4.88，强制获取全量固件")
                if "deltaVersion" in post_data:
                    del CAPTURED_DATA["post_data"]["deltaVersion"]
                    print(f"[+] 已删除增量更新标识，强制获取全量包")

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
            log_error("E102", "60秒内未捕获到有效OTA请求", "请确保词典笔已连接热点并触发检查更新")
            return False
        print("\n[+] 抓包完成，已准备好获取固件")
        return True
    except Exception as e:
        log_error("E103", "抓包模块启动失败", f"请以管理员身份运行程序，并确保安装Npcap。异常: {str(e)}")
        return False

# ====================== 固件下载（修复闪退） ======================
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
        print(f"[DEBUG] 服务器返回原始内容: {r.text}")
        j = r.json()

        # 第一次 2101：自动重试，确保版本号伪造生效
        if j.get("status") == 2101:
            print("\n[!] 设备已是最新版本，正在尝试切换为低版本获取固件...")
            CAPTURED_DATA["post_data"]["currentVersion"] = "4.88"
            if "deltaVersion" in CAPTURED_DATA["post_data"]:
                del CAPTURED_DATA["post_data"]["deltaVersion"]
            
            # 重新发送请求
            r = requests.post(
                f"http://{CAPTURED_DATA['ota_url']}",
                json=CAPTURED_DATA["post_data"],
                headers=headers,
                timeout=15
            )
            r.raise_for_status()
            print(f"[DEBUG] 重试后服务器返回: {r.text}")
            j = r.json()

        # 第二次 2101：检查本地固件，避免闪退
        if j.get("status") == 2101:
            print("\n[!] 仍未获取到固件，正在检查本地文件...")
            if os.path.exists("original.img"):
                print("[+] 检测到本地已有 original.img，将直接使用本地固件继续流程。")
                return "original.img", [0]
            else:
                log_error("E205", "词典笔已是最新版本，且未检测到本地固件文件", "请手动下载固件并重试")
                return None, None

        # 正常获取固件
        if j is None or "data" not in j or j["data"] is None:
            raise ValueError(f"服务器响应异常，无data字段: {j}")
        if "version" not in j["data"] or j["data"]["version"] is None:
            raise ValueError(f"服务器响应异常，无version字段: {j['data']}")
        
        ver = j["data"]["version"]
        url = ver.get("deltaUrl") or ver.get("fullUrl")
        if not url:
            raise ValueError(f"未找到固件下载地址，version内容: {ver}")
        if "segmentMd5" not in ver:
            raise ValueError(f"缺少 segmentMd5 字段，version 内容: {ver}")
        
        seg = json.loads(ver["segmentMd5"])
        endpos = [x["endpos"] for x in seg]

        print("[+] 正在下载固件，请稍等...")
        with open("original.img", "wb") as f:
            with requests.get(url, stream=True, timeout=120) as resp:
                for chunk in resp.iter_content(1024*1024):
                    f.write(chunk)
        print("[+] 固件下载完成")
        return "original.img", endpos

    except requests.exceptions.Timeout:
        log_error("E201", "请求超时", "服务器响应超时，请检查网络或词典笔是否支持当前操作")
    except requests.exceptions.RequestException as e:
        log_error("E201", "网络请求失败", str(e))
    except (KeyError, json.JSONDecodeError, ValueError) as e:
        log_error("E202", "解析固件地址失败", str(e))
    except Exception as e:
        log_error("E203", "下载失败", str(e))

    # 失败后检查本地固件
    if os.path.exists("original.img"):
        print("[+] 检测到本地已有 original.img，将直接使用本地固件继续流程。")
        return "original.img", [0]
    return None, None

# ====================== 固件修改 ======================
def md5_hex(data):
    return hashlib.md5(data).hexdigest()

def file_md5_hex(path):
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1024*1024), b""):
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        log_error("E302", "计算文件MD5失败", str(e))
        return None

def sha256_hex(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1024*1024), b""):
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        log_error("E301", "计算SHA256失败", str(e))
        return None

def calc_new_pass_md5(password):
    try:
        raw = (password + "\n").encode("utf-8")
        return md5_hex(raw)
    except Exception as e:
        log_error("E303", "计算新密码MD5失败", str(e))
        return None

def search_and_replace_md5_in_img(img_path, old_md5, new_md5):
    try:
        with open(img_path, "rb") as f:
            data = f.read()
        old_bytes = bytes.fromhex(old_md5)
        new_bytes = bytes.fromhex(new_md5)
        if old_bytes not in data:
            log_error("E304", "未在固件中找到原MD5，型号不匹配", "请确认固件与设备型号一致")
            return None
        new_data = data.replace(old_bytes, new_bytes)
        with open("modified_firmware.img", "wb") as f:
            f.write(new_data)
        print("[+] 固件修改完成")
        return "modified_firmware.img"
    except Exception as e:
        log_error("E305", "替换MD5失败", str(e))
        return None

def search_original_adb_md5(img_path):
    try:
        with open(img_path, "rb") as f:
            data = f.read()
        match = re.search(rb"[0-9a-fA-F]{32}", data)
        if match:
            s = match.group(0).hex() if isinstance(match.group(0), bytes) else match.group(0)
            print(f"[+] 已识别原始密码信息")
            return s
        log_error("E306", "无法自动提取MD5", "固件中未找到符合格式的MD5字符串")
        return None
    except Exception as e:
        log_error("E307", "扫描MD5失败", str(e))
        return None

# ====================== 服务启动 ======================
def start_file_server(local_ip, img_path):
    try:
        os.chdir(os.path.dirname(os.path.abspath(img_path)))
        port = 14514
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[+] 文件服务已启动: http://{local_ip}:14514")
        return True
    except Exception as e:
        log_error("E401", "启动文件服务器失败", f"端口14514可能被占用: {str(e)}")
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
                print("\n[+] 词典笔已连接，等待更新...")

        server = socketserver.TCPServer((local_ip, 80), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print("[+] OTA劫持服务已启动（端口80）")
        return True
    except Exception as e:
        log_error("E402", "启动OTA服务器失败", f"端口80可能被占用或权限不足: {str(e)}")
        return False

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
        log_error("E002", "未设置ADB新密码", "密码不能为空")
        save_error_log()
        os.system("pause")
        return

    original_img, endpos = download_original_firmware()
    if not original_img:
        save_error_log()
        os.system("pause")
        return

    old_md5 = search_original_adb_md5(original_img)
    if not old_md5:
        save_error_log()
        os.system("pause")
        return

    new_md5 = calc_new_pass_md5(new_pass)
    if not new_md5:
        save_error_log()
        os.system("pause")
        return
    print(f"新密码MD5：{new_md5}")

    modified_img = search_and_replace_md5_in_img(original_img, old_md5, new_md5)
    if not modified_img:
        save_error_log()
        os.system("pause")
        return

    if not start_file_server(local_ip, modified_img):
        save_error_log()
        os.system("pause")
        return

    if not start_ota_server(local_ip, modified_img, endpos):
        save_error_log()
        os.system("pause")
        return

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
        log_error("E999", "程序致命错误", str(e))
        save_error_log()
        os.system("pause")
