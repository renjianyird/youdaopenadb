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
# 严格按照教程实现，带完整错误码和说明
# ==========================================================
VERSION = "FINAL_WITH_ERRORS"

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

# ====================== 错误码说明文档 ======================
ERROR_DOCS = {
    "E1": {
        "msg": "抓包失败",
        "desc": "未在60秒内抓到有效OTA请求，或抓包过程异常。请确保：\n1. 以管理员权限运行程序\n2. 已安装 Npcap 抓包驱动\n3. 词典笔已连接电脑热点并点击【检查更新】"
    },
    "E2": {
        "msg": "获取全量包失败",
        "desc": "请求全量包接口失败，可能原因：\n1. 网络不通\n2. 接口地址变更\n3. timestamp/sign 无效\n4. 服务器返回非预期格式"
    },
    "E3": {
        "msg": "下载更新包失败",
        "desc": "下载 deltaUrl 对应文件失败，请检查：\n1. 网络连接\n2. deltaUrl 是否有效\n3. 磁盘空间是否充足"
    },
    "E4": {
        "msg": "提取 rootfs / 查找 MD5 失败",
        "desc": "从更新包中提取 rootfs 或查找 adb_auth.sh 中的 MD5 失败，可能原因：\n1. 更新包格式不兼容\n2. 未找到 adb_auth.sh 脚本\n3. 脚本中未找到 MD5 密码"
    },
    "E5": {
        "msg": "固件修改失败",
        "desc": "替换 MD5 或生成新固件失败，可能原因：\n1. 原始 MD5 不匹配\n2. 固件文件损坏"
    },
    "E6": {
        "msg": "服务器启动失败",
        "desc": "本地劫持服务器启动失败，可能原因：\n1. 端口 80/8080 被占用\n2. 权限不足"
    },
    "E999": {
        "msg": "程序异常",
        "desc": "发生未预期的错误，请查看 error.log 并反馈"
    }
}

def log(code, detail=""):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "code": code,
        "msg": ERROR_DOCS[code]["msg"],
        "detail": detail
    }
    ERROR_LOG.append(entry)
    print(f"\n[错误 {code}] {ERROR_DOCS[code]['msg']}")
    if detail:
        print(f"详情: {detail}")

def save_error_log():
    with open("error.log", "w", encoding="utf-8") as f:
        f.write("错误日志\n========================\n")
        for e in ERROR_LOG:
            f.write(f"[{e['time']}] {e['code']} | {e['msg']} | {e['detail']}\n")
        f.write("\n错误码说明:\n")
        for code, doc in ERROR_DOCS.items():
            f.write(f"{code}: {doc['desc']}\n")
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
        log("E1", str(e))
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
        r.raise_for_status()
        j = r.json()
        print(f"[DEBUG] 服务器返回: {json.dumps(j, indent=2)}")

        # 修复：先检查是否有 data 字段，再访问
        if "data" not in j:
            log("E2", f"服务器返回格式异常，无 data 字段: {j}")
            return None
        if "version" not in j["data"]:
            log("E2", f"服务器返回格式异常，无 version 字段: {j}")
            return None

        ver = j["data"]["version"]
        delta_url = ver.get("deltaUrl") or ver.get("fullUrl")
        if not delta_url:
            log("E2", f"服务器返回中无 deltaUrl / fullUrl: {ver}")
            return None

        CAPTURED["segmentMd5"] = json.loads(ver.get("segmentMd5", "[]"))
        CAPTURED["endPos"] = ver.get("endPos", [])
        print(f"[+] deltaUrl: {delta_url}")
        print(f"[+] endPos: {CAPTURED['endPos']}")
        print(f"[+] segmentMd5: {CAPTURED['segmentMd5']}")
        return delta_url
    except requests.exceptions.RequestException as e:
        log("E2", f"网络请求异常: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        log("E2", f"JSON 解析失败: {str(e)}")
        return None
    except Exception as e:
        log("E2", str(e))
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
            resp.raise_for_status()
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)
        print("[+] 下载完成")
        return fn
    except Exception as e:
        log("E3", str(e))
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
            log("E4", "未找到 adb_auth.sh 脚本")
            return None
        matches = re.findall(rb"[0-9a-fA-F]{32}", data)
        if not matches:
            log("E4", "未找到 MD5 密码串")
            return None
        original_md5 = matches[0].decode()
        print(f"[+] 原始MD5: {original_md5}")
        return original_md5
    except Exception as e:
        log("E4", str(e))
        return None

# ------------------------------------------------------------------------------
# 步骤5：密码 + 换行 转MD5 → 替换 → 生成新固件
# ------------------------------------------------------------------------------
def step5_patch_firmware(orig_file, old_md5, new_pw):
    print("\n=== 步骤5：替换MD5（密码带换行） ===")
    try:
        # 关键：密码 + 换行 再算MD5
        data_for_md5 = (new_pw + "\n").encode("utf-8")
        new_md5 = hashlib.md5(data_for_md5).hexdigest()

        with open(orig_file, "rb") as f:
            buf = f.read()
        old_bytes = bytes.fromhex(old_md5)
        new_bytes = bytes.fromhex(new_md5)
        if old_bytes not in buf:
            log("E5", "原始 MD5 不匹配，无法替换")
            return None, None
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
    except Exception as e:
        log("E5", str(e))
        return None, None

# ------------------------------------------------------------------------------
# 步骤6：搭建劫持服务器
# ------------------------------------------------------------------------------
def step6_start_evil_server(local_ip, firmware_path, new_sha256):
    print("\n=== 步骤6：启动本地劫持服务器 ===")
    try:
        def file_server():
            os.chdir(os.path.dirname(os.path.abspath(firmware_path)))
            socketserver.TCPServer.allow_reuse_address = True
            http.server.ThreadingHTTPServer(("0.0.0.0", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()

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
        return True
    except Exception as e:
        log("E6", str(e))
        return False

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
    if not patched_file or not new_sha256:
        save_error_log()
        os.system("pause")
        return

    if not step6_start_evil_server(ip, patched_file, new_sha256):
        save_error_log()
        os.system("pause")
        return

    print("\n全部完成！按 Ctrl+C 退出")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        log("E999", str(e))
        save_error_log()
        os.system("pause")
