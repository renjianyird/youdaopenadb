import os
import sys
import json
import hashlib
import socket
import http.server
import socketserver

def 标题(title):
    os.system("title " + title)

def 分割线():
    print("=" * 60)

def 小白提示(text):
    print(f"\n📢 小白提示：{text}")

def 获取本机IP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def 输入提示(文字):
    print(f"\n👉 {text}", end="")
    return input().strip()

def 计算密码MD5(密码):
    密码带换行 = 密码 + "\n"
    md5值 = hashlib.md5(密码带换行.encode("utf-8")).hexdigest()
    print(f"✅ 新密码的MD5（带换行）：{md5值}")
    print("ℹ 这个值是用来替换固件里的密码校验码")
    return md5值

def 文件整体MD5(路径):
    h = hashlib.md5()
    with open(路径, "rb") as f:
        for 块 in iter(lambda: f.read(1024*1024), b""):
            h.update(块)
    return h.hexdigest()

def 文件SHA256(路径):
    h = hashlib.sha256()
    with open(路径, "rb") as f:
        for 块 in iter(lambda: f.read(1024*1024), b""):
            h.update(块)
    return h.hexdigest()

def 计算分片MD5(路径, 结束位置列表):
    结果 = []
    with open(路径, "rb") as f:
        起始 = 0
        for 序号, 结束 in enumerate(结束位置列表):
            f.seek(起始)
            数据 = f.read(结束 - 起始)
            md5 = hashlib.md5(数据).hexdigest()
            结果.append({"num":序号, "startpos":起始, "md5":md5, "endpos":结束})
            起始 = 结束
    return 结果

def 生成OTA配置(img路径, 本机IP, 分片结束位置):
    文件名 = os.path.basename(img路径)
    下载地址 = f"http://{本机IP}:14514/{文件名}"
    
    整体MD5 = 文件整体MD5(img路径)
    整体SHA = 文件SHA256(img路径)
    分片信息 = 计算分片MD5(img路径, 分片结束位置)
    文件大小 = os.path.getsize(img路径)

    数据 = {
        "status":1000,"msg":"success",
        "data":{
            "releaseNotes":{
                "publishDate":"2024-01-01",
                "version":"99.99.99",
                "content":"[{\"country\":\"zh_CN\",\"content\":\"优化系统\"}]"
            },
            "safe":{"encKey":None,"isEncrypt":0},
            "version":{
                "segmentMd5":json.dumps(分片信息, ensure_ascii=False),
                "bakUrl":下载地址,
                "deltaUrl":下载地址,
                "deltaID":"custom",
                "fileSize":文件大小,
                "md5sum":整体MD5,
                "versionName":"99.99.99",
                "sha":整体SHA
            },
            "policy":{
                "download":[
                    {"key_name":"wifi","key_message":"仅WiFi下载","key_value":"optional"},
                    {"key_name":"storageSize","key_message":"空间不足","key_value":str(文件大小)},
                    {"key_name":"forceDownload","key_message":"","key_value":"false"}
                ],
                "install":[
                    {"key_name":"battery","key_message":"电量不足","key_value":"30"},
                    {"key_name":"rebootUpgrade","key_message":"","key_value":"false"},
                    {"key_name":"force","key_message":"","key_value":"{}"}
                ],
                "check":[{"key_name":"cycle","key_message":"","key_value":"1500"}]
            }
        }
    }
    with open("ota.json","w",encoding="utf-8") as f:
        json.dump(数据,f,indent=2,ensure_ascii=False)
    print("✅ 已生成 ota.json（更新验证文件）")
    return 数据

def 生成Node服务器(本机IP, OTA路径, OTA数据):
    脚本 = f'''const http=require('http');const url=require('url');
const ota={json.dumps(OTA数据)};
const s=http.createServer((q,r)=>{{
const u=url.parse(q.url,true);
if(u.pathname==='{OTA路径}'){{
r.writeHead(200,{{'Content-Type':'application/json;charset=utf-8'}});
r.end(JSON.stringify(ota));console.log("✅ 词典笔已连接更新服务器");return;
}}
r.writeHead(404);r.end("404");
}});
s.listen(80,'{本机IP}',()=>{{console.log("✅ OTA服务器已启动");}});'''
    with open("YDPen.js","w",encoding="utf-8") as f:
        f.write(脚本)
    print("✅ 已生成 YDPen.js（劫持更新用）")

def 启动文件服务(img路径, 本机IP):
    try:
        os.chdir(os.path.dirname(img路径) or ".")
    except:
        pass
    端口 = 14514
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", 端口), http.server.SimpleHTTPRequestHandler) as 服务:
        分割线()
        print(f"📶 文件服务运行：http://{本机IP}:14514")
        print(f"✅ 固件已准备好，等待词典笔下载")
        小白提示("另开一个窗口，运行：node YDPen.js")
        小白提示(f"一定要改HOSTS：{本机IP} iotapi.abupdate.com")
        小白提示("词典笔连电脑热点 → 检查更新 → 安装")
        try:
            服务.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 服务已停止")

def 主程序():
    标题("有道词典笔ADB一键工具 · 小白专用版")
    分割线()
    print("          有道词典笔 ADB 密码破解工具")
    print("            全程中文引导 · 不用懂代码")
    分割线()

    小白提示("本工具仅用于学习折腾，风险自负！")
    小白提示("使用前必须先：抓包 → 解包 → 替换密码MD5 → 保存固件")

    本机IP = 获取本机IP()
    print(f"🌐 自动获取本机IP：{本机IP}")

    新密码 = 输入提示("请设置你要的ADB新密码：")
    小白提示("密码自己记住，后面ADB登录要用！")

    固件路径 = 输入提示("请把修改后的.img固件拖到此窗口：").replace('"','')
    小白提示("就是你用WinHex修改过的那个固件文件")

    OTA接口 = 输入提示("请输入抓包到的OTA检查地址：")
    小白提示("类似：/product/xxxx/ota/checkVersion")

    分片输入 = 输入提示("请输入endpos（用英文逗号分隔）：")
    小白提示("例：104857600,209715200,314572800")

    分片结束位置 = []
    for s in 分片输入.split(","):
        s = s.strip()
        if s.isdigit():
            分片结束位置.append(int(s))

    分割线()
    print("🚀 开始自动处理...")

    print("\n【1/4】计算新密码MD5（带换行，网易专用）")
    计算密码MD5(新密码)

    print("\n【2/4】生成OTA更新验证文件")
    ota数据 = 生成OTA配置(固件路径, 本机IP, 分片结束位置)

    print("\n【3/4】生成更新劫持服务器")
    生成Node服务器(本机IP, OTA接口, ota数据)

    print("\n【4/4】启动固件下载服务")
    启动文件服务(固件路径, 本机IP)

if __name__ == "__main__":
    try:
        主程序()
    except Exception as e:
        分割线()
        print(f"❌ 出错：{e}")
        print("💡 检查：路径是否正确、固件是否存在、分片是否填对")
        os.system("pause")
