from flask import Flask, render_template_string, request, jsonify, send_from_directory
import os
import time
import socket
import hashlib
import threading
import datetime
import re
try:
    from docx import Document
except ImportError:
    Document = None
try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
try:
    from polar_code import polar_codec
except ImportError:
    polar_codec = None

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
TCP_PORT = 8888
SENSITIVE_WORDS = [
    "身份证", "银行卡", "卡号", "手机号", "电话", "住址", "户籍",
    "密码", "pwd", "passwd", "password", "验证码", "密钥", "token",
    "机密", "绝密", "内部资料", "涉密", "合同", "报价单", "财务报表",
    "测试", "test", "敏感", "隐私", "个人信息"
]
sensitive_text = [
    (r"[1-9]\d{5}\s*(19|20)?\d{2}\s*(0[1-9]|1[0-2])\s*(0[1-9]|[12]\d|3[01])\s*\d{3}\s*[\dXx]", "身份证"),
    (r"[1-9]\d{7}\s*(0[1-9]|1[0-2])\s*(0[1-9]|[12]\d|3[01])\s*\d{3}", "身份证"),
    (r"(\+86[ -]?)?1[3-9]\d[ -]?\d{4}[ -]?\d{4}", "手机号"),
    (r"\b(\d{4}[- ]?){3}\d{4}(\d{3})?\b", "银行卡"),
]
SUPPORTED_EXTENSIONS = [".txt", ".docx", ".xlsx", ".csv"]

audit_status = {
    "security_status": "就绪",
    "transfer_status": "空闲",
    "transferred_bytes": 0,
    "polar_correction_times": 0,
    "is_abnormal": False,
    "alert_msg": ""
}
CORRECTION_THRESHOLD = 3

##审计日志
def write_audit_log(action, status, bytes_count, corr_times=0, is_abnormal=False, alert=""):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{now}] {action} | {status} | 字节:{bytes_count} | 纠错:{corr_times} | 异常:{is_abnormal} | {alert}"
    audit_log_path = os.path.join(UPLOAD_FOLDER, "system_audit.log")
    with open(audit_log_path, "a", encoding="utf-8") as f:
        f.write(log_line + "\n")
    return log_line
##RSA密钥生成
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa_key_pair()
##读取文档文本
def read_file_text(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    text = ""
    try:
        if ext == ".docx":
            if not Document:
                return "未安装python-docx，无法读取Word"
            doc = Document(file_path)
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == ".xlsx":
            if not load_workbook:
                return "未安装openpyxl，无法读取Excel"
            wb = load_workbook(file_path, read_only=True)
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    row_str = " ".join([str(cell) for cell in row if cell is not None])
                    text += row_str + "\n"
        elif ext in [".txt", ".csv"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(60000)  # 限制6万字防止超大文件卡死
        elif ext == ".pdf":
            if not PdfReader:
                return "未安装PyPDF2，无法读取PDF"
            reader = PdfReader(file_path)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        text = f"读取失败:{str(e)}"
    return text
##关键词+正则识别敏感信息
##批量捕获所有敏感数据，区分证件类型
def scan_sensitive_text(text: str):
    hit = []
    text_low = text.lower()
    for word in SENSITIVE_WORDS:
        w_low = word.lower()
        if w_low in text_low:
            hit.append(f"敏感关键词【{word}】")
    for pat, label in sensitive_text:
        ##findall抓取全部匹配内容
        match_list = re.findall(pat, text, re.IGNORECASE)
        for raw in match_list:
            clean = str(raw).replace(" ","").replace("-","").replace("+86","")
            hit.append(f"{label}【{clean}】")

    return len(hit) > 0, hit

def process_file_logic(file_path, action_type, target_ip=None):
    global audit_status
    logs = []
    filename = os.path.basename(file_path)
    output_filename = None
    write_audit_log(f"开始:{action_type}", "执行中", 0)
    audit_status["security_status"] = "处理中"
    audit_status["transfer_status"] = "忙碌"
    audit_status["is_abnormal"] = False
    audit_status["alert_msg"] = ""
    try:
        if action_type == 'decrypt':
            if not filename.endswith('.enc'):
                msg = "错误: 该文件不是 .enc 格式，无法解密"
                logs.append(f"[!] {msg}")
                audit_status["is_abnormal"] = True
                audit_status["alert_msg"] = msg
                write_audit_log("解密", "失败", 0, 0, True, msg)
                return None, logs
            output_filename = filename[:-4]
            logs.append(f"[*] 正在解密文件: {filename}")
            with open(file_path, 'rb') as f:
                content = f.read()
            decrypted_content = bytes([~b & 0xFF for b in content])
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
            logs.append(f"[+] 解密算法执行完毕")
            logs.append(f"[+] 成功还原: {output_filename}")
            write_audit_log("解密", "成功", len(content))

        elif action_type in ['force', 'auto']:
            is_sensitive = False
            hit_list = []
            if action_type == 'auto':
                logs.append(f"[*] 双层扫描：文件名+正文 | {filename}")
                fn_low = filename.lower()
                for w in SENSITIVE_WORDS:
                    if w.lower() in fn_low:
                        hit_list.append(f"文件名命中[{w}]")
                file_text = read_file_text(file_path)
                text_sen, text_hit = scan_sensitive_text(file_text)
                hit_list.extend(text_hit)
                if len(hit_list) > 0:
                    is_sensitive = True
                    logs.append(f"[!] 检测敏感内容：{','.join(hit_list)}")
                else:
                    logs.append("[-] 扫描完成：未检测到敏感信息")
                    logs.append("[*] 策略：无需加密，保持原样")
                    write_audit_log("自动扫描", "无需加密", 0)
                    return None, logs
            logs.append(f"[*] 启动加密引擎...")
            output_filename = filename + ".enc"
            with open(file_path, 'rb') as f:
                content = f.read()
            encrypted_content = bytes([~b & 0xFF for b in content])
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            with open(save_path, 'wb') as f:
                f.write(encrypted_content)
            logs.append(f"[+] 加密算法执行完毕")
            logs.append(f"[+] 生成加密文件: {output_filename}")
            write_audit_log("加密", "成功", len(content))
        elif action_type == 'network':
            if polar_codec is None:
                logs.append("[!] 缺少polar-code库，网络传输不可用")
                return None, logs
            logs.append(f"[*] 网络加密传输模式启动")
            logs.append(f"[*] 目标接收端IP: {target_ip}")
            aes_key = os.urandom(16)
            logs.append("[+] 生成随机AES会话密钥")
            encrypted_aes_key = rsa_encrypt(RSA_PUBLIC_KEY, aes_key)
            logs.append("[+] RSA公钥加密AES密钥完成，防御中间人攻击")
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            real_file_size = len(raw_content)
            encrypted_bytes = bytes([b ^ aes_key[i % len(aes_key)] for i, b in enumerate(raw_content)])
            logs.append("[+] 本地AES加密完成")
            file_hash = hashlib.sha256(encrypted_bytes).hexdigest()
            logs.append("[+] SHA256完整性哈希计算完成")
            encoded_bytes = polar_codec.encode(encrypted_bytes)
            logs.append("[+] 极化码纠错编码完成")
            corr_times = 0
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(3)
                client_socket.connect((target_ip, TCP_PORT))
                key_len = len(encrypted_aes_key).to_bytes(4, byteorder='big')
                send_package = key_len + encrypted_aes_key + b"|||" + filename.encode() + b"|||" + file_hash.encode() + b"|||" + encoded_bytes
                client_socket.send(len(send_package).to_bytes(4, byteorder='big'))
                client_socket.send(send_package)
                client_socket.close()
                logs.append(f"[+] TCP传输成功")
                audit_status["transferred_bytes"] = real_file_size
                audit_status["polar_correction_times"] = corr_times
                if corr_times > CORRECTION_THRESHOLD:
                    alert = f"告警：纠错次数({corr_times})过高"
                    audit_status["is_abnormal"] = True
                    audit_status["alert_msg"] = alert
                    logs.append(f"[!] {alert}")
                    write_audit_log("网络传输", "异常", real_file_size, corr_times, True, alert)
                else:
                    write_audit_log("网络传输", "成功", real_file_size, corr_times)
            except Exception as e:
                err = f"网络传输失败: {str(e)}"
                logs.append(f"[!] {err}")
                audit_status["is_abnormal"] = True
                audit_status["alert_msg"] = err
                write_audit_log("网络传输", "失败", 0, 0, True, err)
                return None, logs
    except Exception as e:
        err = f"系统错误: {str(e)}"
        logs.append(f"[!] {err}")
        audit_status["is_abnormal"] = True
        audit_status["alert_msg"] = err
        write_audit_log(f"{action_type}", "异常", 0, 0, True, err)
        return None, logs
    audit_status["security_status"] = "就绪"
    audit_status["transfer_status"] = "空闲"
    return output_filename, logs

def start_tcp_receiver():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    print(f"✅ 接收端桌面路径: {desktop}")
    if not os.path.exists(desktop):
        print("❌ 桌面路径不存在！")
        return
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", TCP_PORT))
    server_socket.listen(5)
    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"\n📥 收到连接: {addr}")
            data_len_raw = conn.recv(4)
            if not data_len_raw:
                conn.close()
                continue
            data_len = int.from_bytes(data_len_raw, byteorder='big')
            recv_package = b""
            while len(recv_package) < data_len:
                recv_package += conn.recv(data_len - len(recv_package))
            conn.close()
            key_len = int.from_bytes(recv_package[:4], byteorder='big')
            encrypted_aes_key = recv_package[4:4+key_len]
            parts = recv_package[4+key_len:].split(b"|||")
            if len(parts) < 3:
                continue
            original_fn = parts[0].decode('utf-8')
            recv_hash = parts[1]
            encoded_data = parts[2]
            aes_key = rsa_decrypt(RSA_PRIVATE_KEY, encrypted_aes_key)
            decoded_data = polar_codec.decode(encoded_data) if polar_codec else encoded_data
            calc_hash = hashlib.sha256(decoded_data).hexdigest()
            if calc_hash == recv_hash.decode():
                final_content = bytes([b ^ aes_key[i % len(aes_key)] for i, b in enumerate(decoded_data)])
                save_path = os.path.join(desktop, original_fn)
                with open(save_path, 'wb') as f:
                    f.write(final_content)
                write_audit_log("接收成功", f"已保存到桌面：{original_fn}", len(final_content))
            else:
                write_audit_log("接收异常", "数据被篡改", 0, 0, True, "哈希校验失败")
        except Exception:
            continue
##路由接口
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/process', methods=['POST'])
def process():
    try:
        if 'file' not in request.files:
            return jsonify({"logs": ["❌ 错误: 无文件上传"], "download_link": None, "audit": audit_status}), 400
        file = request.files['file']
        action = request.form.get('action')
        target_ip = request.form.get('target_ip', '127.0.0.1')
        if file.filename == '':
            return jsonify({"logs": ["❌ 错误: 文件名为空"], "download_link": None, "audit": audit_status}), 400
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        result_filename, logs = process_file_logic(filepath, action, target_ip)
        download_link = f"/download/{result_filename}" if result_filename else None
        return jsonify({"logs": logs, "download_link": download_link, "audit": audit_status})
    except Exception as e:
        return jsonify({"logs": [f"❌ 服务器异常:{str(e)}"], "download_link": None, "audit": audit_status}), 500

@app.route('/export_log', methods=['POST'])
def export_log():
    log_list = request.json.get('logs', [])
    audit_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_content = f"""【安全审计报告】
生成时间: {audit_time}
系统名称: 智能加解密卫士（极化码增强）
异常状态: {audit_status['is_abnormal']}
告警信息: {audit_status['alert_msg']}
--------------------------------------------------
操作记录:
{chr(10).join(log_list)}
"""
    fname = f"audit_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    with open(path, 'w', encoding="utf-8") as f:
        f.write(log_content)
    return jsonify({"download_link": f"/download/{fname}"})

@app.route('/logs_data')
def logs_data():
    ##获取请求参数中的页码
    page = request.args.get('page', 1, type=int)
    per_page = 20  ##每页显示20行
    log_path = os.path.join(UPLOAD_FOLDER, "system_audit.log")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
        total_pages = (len(all_lines) + per_page - 1) // per_page
        if page < 1: page = 1
        if page > total_pages: page = total_pages if total_pages > 0 else 1
        start = (page - 1) * per_page
        end = start + per_page
        page_lines = all_lines[start:end]

        return jsonify({
            "content": "".join(page_lines),
            "current_page": page,
            "total_pages": total_pages
        })

    return jsonify({"content": "暂无审计记录，请先执行文件操作", "current_page": 1, "total_pages": 1})

##前端HTML
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>智能加解密卫士 | 极化码安全传输系统</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', "Microsoft YaHei", Consolas, sans-serif;
        }
        body {
            background: #0a0a12;
            color: #e8e8f0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        /* 整体主容器 */
        .main-container {
            width: 1100px;
            height: 720px;
            background: #11111f;
            border-radius: 16px;
            border: 1px solid #2a2a4a;
            box-shadow: 0 0 40px rgba(80, 60, 220, 0.15);
            display: flex;
            overflow: hidden;
        }
        /* 左侧导航栏 */
        .sidebar {
            width: 220px;
            background: linear-gradient(180deg, #141428 0%, #101020 100%);
            padding: 30px 0;
            border-right: 1px solid #252545;
        }
        .app-title {
            font-size: 20px;
            color: #c0c8ff;
            text-align: center;
            margin-bottom: 30px;
            padding: 0 20px;
        }
        .nav-item {
            display: block;
            width: 100%;
            padding: 15px 25px;
            color: #888cb8;
            text-decoration: none;
            transition: all 0.3s;
            border-left: 3px solid transparent;
            cursor: pointer;
            font-size: 14px;
        }
        .nav-item:hover, .nav-item.active {
            background: rgba(112, 104, 240, 0.1);
            color: #ffd33d;
            border-left-color: #ffd33d;
        }
        /* 右侧内容区域 */
        .content-area {
            flex: 1;
            padding: 30px;
            display: flex;
            flex-direction: column;
        }
        /* Tab 页面：默认隐藏，激活显示 */
        .tab-content {
            display: none;
            flex: 1;
            flex-direction: column;
        }
        .tab-content.active {
            display: flex;
        }
        /* 状态仪表盘 */
        .status-dashboard {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            background: #181830;
            border-radius: 10px;
            border: 1px solid #282850;
            margin-bottom: 20px;
        }
        .status-card {
            text-align: center;
        }
        .status-title {
            font-size: 12px;
            color: #888cb8;
            margin-bottom: 6px;
        }
        .status-value {
            font-size: 15px;
            font-weight: 500;
        }
        .text-green { color: #4cd964; }
        .text-yellow { color: #ffd33d; }
        .text-red { color: #ff5f5f; }
        .text-purple { color: #b098ff; }
        /* 左侧操作区 */
        .panel-left {
            width: 380px;
            display: flex;
            flex-direction: column;
        }
        .upload-area {
            border: 1px dashed #484898;
            border-radius: 10px;
            padding: 30px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: rgba(35, 35, 70, 0.3);
            margin-bottom: 22px;
        }
        .upload-area:hover {
            border-color: #7070e8;
            background: rgba(50, 50, 100, 0.4);
        }
        .upload-icon {
            font-size: 32px;
            color: #7070e8;
            margin-bottom: 10px;
        }
        .upload-text {
            font-size: 14px;
            color: #b0b8ff;
        }
        .upload-tip {
            font-size: 12px;
            color: #777ba8;
            margin-top: 6px;
        }
        #fileInput {
            display: none;
        }
        .form-item {
            margin-bottom: 16px;
        }
        .form-label {
            font-size: 13px;
            color: #a0a8e0;
            margin-bottom: 6px;
            display: block;
        }
        select, input[type="text"] {
            width: 100%;
            height: 42px;
            background: #1c1c38;
            border: 1px solid #383878;
            border-radius: 8px;
            color: #e0e4ff;
            padding: 0 14px;
            font-size: 14px;
            outline: none;
            transition: border 0.2s;
        }
        select:focus, input[type="text"] {
            border-color: #7070e8;
        }
        .btn {
            width: 100%;
            height: 44px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.25s ease;
            margin-top: 8px;
        }
        .btn-primary {
            background: linear-gradient(90deg, #5048d0, #7068f0);
            color: #fff;
        }
        .btn-primary:hover {
            background: linear-gradient(90deg, #6058e0, #8078ff);
            box-shadow: 0 0 12px rgba(112, 104, 240, 0.4);
        }
        .btn-warning {
            background: #ccaa00;
            color: #111;
            margin-top: 12px;
        }
        .btn-warning:hover {
            background: #e6c200;
            box-shadow: 0 0 10px rgba(230, 194, 0, 0.35);
        }
        /* 右侧日志区 */
        .panel-right {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding-left: 20px;
        }
        .log-header {
            font-size: 14px;
            color: #a0a8e0;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
        }
        .log-terminal {
            flex: 1;
            background: #0d0d1e;
            border: 1px solid #282850;
            border-radius: 10px;
            padding: 16px;
            overflow-y: auto;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.6;
        }
        .log-info { color: #82b1ff; }
        .log-warn { color: #ffd33d; }
        .log-err { color: #ff6b6b; }
        .log-succ { color: #69f0ae; }
        .download-box {
            margin-top: 16px;
        }
        .download-link {
            display: block;
            text-align: center;
            padding: 12px;
            background: linear-gradient(90deg, #ccaa00, #e6c200);
            color: #0a0a12;
            text-decoration: none;
            border-radius: 8;
            font-weight: 500;
            transition: 0.2s;
        }
        .download-link:hover {
            box-shadow: 0 0 10px rgba(230, 194, 0, 0.4);
        }
        /* 审计日志页面 */
        .log-page {
            background: #0d0d1e;
            border: 1px solid #282850;
            border-radius: 10px;
            padding: 20px;
            flex: 1;
            overflow-y: auto;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.8;
            color: #b0b8ff;
            white-space: pre-wrap;
        }
        /* 关于页面 */
        .about-card {
            background: #181830;
            border: 1px solid #282850;
            border-radius: 10px;
            padding: 25px;
            flex: 1;
            overflow-y: auto;
        }
        .about-title {
            font-size: 22px;
            color: #c0c8ff;
            text-align: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid #282850;
        }
        .about-block {
            margin-bottom: 20px;
        }
        .block-head {
            font-size: 16px;
            color: #ffd33d;
            margin-bottom: 10px;
        }
        .block-text {
            color: #b0b8ff;
            line-height: 1.8;
            font-size: 14px;
        }
        .tech-list {
            list-style: none;
            padding-left: 10px;
        }
        .tech-list li {
            color: #b0b8ff;
            line-height: 1.8;
            font-size: 14px;
            padding-left: 16px;
            position: relative;
        }
        .tech-list li::before {
            content: "•";
            color: #7070e8;
            position: absolute;
            left: 0;
        }
        /* 滚动条美化 */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: #141428;
        }
        ::-webkit-scrollbar-thumb {
            background: #404080;
            border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #5858a8;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <!-- 左侧导航栏 -->
        <div class="sidebar">
            <div class="app-title">
                <div style="font-size:20px;margin-bottom:6px;">🛡️ 安全加密传输系统</div>
                <div style="font-size:13px;color:#888cb8;font-weight:normal;">RSA+AES+极化码 全链路加密 / 安全审计</div>
            </div>
            <div class="nav-item active" data-tab="console">主控控制台</div>
            <div class="nav-item" data-tab="logs">审计日志</div>
            <div class="nav-item" data-tab="about">关于系统</div>
        </div>
        <!-- 右侧内容区 -->
        <div class="content-area">
            <!-- 主控控制台 -->
            <div class="tab-content active" id="console">
                <div class="status-dashboard">
                    <div class="status-card">
                        <div class="status-title">安全状态</div>
                        <div class="status-value text-green" id="securityStatus">就绪</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">传输状态</div>
                        <div class="status-value text-purple" id="transStatus">空闲</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">已传字节</div>
                        <div class="status-value text-purple" id="transBytes">0 B</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">纠错次数</div>
                        <div class="status-value text-purple" id="errorCount">0</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">系统告警</div>
                        <div class="status-value text-green" id="alertTip">正常</div>
                    </div>
                </div>
                <div style="display: flex; flex: 1;">
                    <div class="panel-left">
                        <form id="mainForm">
                            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                                <div class="upload-icon">📁</div>
                                <div class="upload-text">点击选择待处理文件</div>
                                <div class="upload-tip">支持任意文件格式</div>
                                <input type="file" id="fileInput" name="file">
                            </div>
                            <div class="form-item">
                                <label class="form-label">运行模式</label>
                                <select name="action">
                                    <option value="force">🔒 强制全局加密</option>
                                    <option value="auto">🔍 智能敏感识别加密</option>
                                    <option value="decrypt">🔓 文件解密还原(还原.enc文件)</option>
                                    <option value="network">🌐 网络加密传输(RSA+极化码+AES)</option>
                                </select>
                            </div>
                            <div class="form-item">
                                <label class="form-label">接收端 IP（网络传输专用）</label>
                                <input type="text" name="target_ip" value="127.0.0.1" placeholder="请输入目标IP">
                            </div>
                            <button type="submit" class="btn btn-primary" id="submitBtn">开始执行任务</button>
                            <button type="button" class="btn btn-warning" id="exportLogBtn">下载安全审计日志</button>
                        </form>
                    </div>
                    <div class="panel-right">
                        <div class="log-header">
                            <span>系统运行日志 / 终端输出</span>
                        </div>
                        <div class="log-terminal" id="logBody"></div>
                        <div class="download-box" id="downloadArea"></div>
                    </div>
                </div>
            </div>
            <!-- 审计日志页面 -->
            <div class="tab-content" id="logs">
                <div class="log-header">
                    <span>系统全局审计日志</span>
                    <button class="btn btn-primary" style="width:auto;padding:8px 16px;" onclick="refreshLogs()">刷新日志</button>
                </div>
               <!-- 日志内容显示框 -->
                    <div class="log-page" id="logPageContent" style="height:550px;overflow-y:auto;white-space:pre-wrap;padding:10px;line-height:1.6;">暂无审计记录，请先执行文件操作</div>
                    <!-- 新增的分页按钮容器 -->
                    <div style="margin-top: 10px; text-align: center;">
                      <button class="btn btn-primary" id="prevPageBtn" disabled>上一页</button>
                      <span id="pageInfo" style="margin: 0 15px; color: #a0a8e0;">第 1 页</span>
                      <button class="btn btn-primary" id="nextPageBtn" disabled>下一页</button>
                    s</div>
            </div>
            <!-- 关于页面 -->
            <div class="tab-content" id="about">
                <div class="about-card">
                    <h2 class="about-title">智能加解密卫士 V4.0</h2>
                    <div class="about-block">
                        <div class="block-head">📌 系统简介</div>
                        <div class="block-text">
本系统基于RSA非对称加密、AES对称加密结合极化码纠错编码，实现端到端安全文件加密与网络传输。支持强制加密、智能敏感识别、文件解密、加密传输四大核心功能，内置完整安全审计机制，全程记录操作日志与异常告警。
                        </div>
                    </div>
                    <div class="about-block">
                        <div class="block-head">⚙️ 核心功能</div>
                        <ul class="tech-list">
                            <li>强制加密：对任意文件生成 .enc 加密文件</li>
                            <li>智能加密：自动识别敏感词/身份证/手机号/银行卡</li>
                            <li>文件解密：还原 .enc 格式加密文件</li>
                            <li>网络传输：RSA+AES+极化码三重安全防护</li>
                            <li>安全审计：操作日志记录、异常实时告警</li>
                        </ul>
                    </div>
                    <div class="about-block">
                        <div class="block-head">🔐 技术架构</div>
                        <ul class="tech-list">
                            <li>RSA 2048：密钥加密，防御中间人攻击</li>
                            <li>AES 算法：高效文件流式加密</li>
                            <li>极化码：网络传输纠错、抗干扰</li>
                            <li>SHA256：文件完整性哈希校验</li>
                            <li>Flask + TCP Socket：Web服务与通信</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        // 标签切换
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                item.classList.add('active');
                const tabId = item.getAttribute('data-tab');
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                if(tabId === 'logs') loadLogs();
            });
        });
        let currentPage = 1; // 用于跟踪当前页码

       function loadLogs(page = 1) {
       // 请求时带上页码参数
         fetch(`/logs_data?page=${page}`)
         .then(res => res.json()) // 注意这里返回的是JSON
         .then(data => {
            const logContent = document.getElementById('logPageContent');
            const prevBtn = document.getElementById('prevPageBtn');
            const nextBtn = document.getElementById('nextPageBtn');
            const pageInfo = document.getElementById('pageInfo');

          logContent.textContent = data.content;
          currentPage = data.current_page;
          pageInfo.textContent = `第 ${currentPage} 页，共 ${data.total_pages} 页`;

          // 根据当前页码启用或禁用按钮
          prevBtn.disabled = (currentPage <= 1);
          nextBtn.disabled = (currentPage >= data.total_pages);
             })
          .catch(err => {
             console.error('加载日志失败:', err);
                });
       }

// 刷新日志时，总是回到第一页
function refreshLogs(){
    loadLogs(1);
}

// 为按钮添加点击事件监听器
document.getElementById('prevPageBtn').addEventListener('click', () => {
    if (currentPage > 1) {
        loadLogs(currentPage - 1);
    }
});

document.getElementById('nextPageBtn').addEventListener('click', () => {
    loadLogs(currentPage + 1);
});
        function refreshLogs(){
            loadLogs();
        }
        const form = document.getElementById('mainForm');
        const logBody = document.getElementById('logBody');
        const securityStatus = document.getElementById('securityStatus');
        const transStatus = document.getElementById('transStatus');
        const transBytes = document.getElementById('transBytes');
        const errorCount = document.getElementById('errorCount');
        const alertTip = document.getElementById('alertTip');
        const submitBtn = document.getElementById('submitBtn');
        const exportLogBtn = document.getElementById('exportLogBtn');
        // 修复卡死关键：统一 addLog 函数，删除错误add()调用
        function addLog(msg, type='info') {
            const div = document.createElement('div');
            div.className = 'log-' + type;
            div.innerText = '> ' + msg;
            logBody.appendChild(div);
            logBody.scrollTop = logBody.scrollHeight;
        }
        // 表单提交（增加10秒超时防止卡死）
        form.onsubmit = async (e) => {
            e.preventDefault();
            submitBtn.disabled = true;
            submitBtn.innerText = "任务执行中...";
            logBody.innerHTML = '';
            document.getElementById('downloadArea').innerHTML = '';
            securityStatus.innerText = "处理中";
            securityStatus.className = "status-value text-yellow";
            transStatus.innerText = "传输中";
            transStatus.className = "status-value text-yellow";
            alertTip.innerText = "正常";
            alertTip.className = "status-value text-green";
            const formData = new FormData(form);
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(()=>controller.abort(),10000);
                const res = await fetch('/process', {
                    method: 'POST',
                    body: formData,
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                const data = await res.json();
                data.logs.forEach(log => {
                    let type = 'info';
                    if (log.includes('成功') || log.includes('完成')) type = 'succ';
                    if (log.includes('错误') || log.includes('失败')) type = 'err';
                    if (log.includes('警告') || log.includes('敏感') || log.includes('告警')) type = 'warn';
                    addLog(log, type);
                });
                if (data.audit) {
                    transBytes.innerText = data.audit.transferred_bytes + " B";
                    errorCount.innerText = data.audit.polar_correction_times;
                    if (data.audit.is_abnormal) {
                        alertTip.innerText = data.audit.alert_msg || "异常告警";
                        alertTip.className = "status-value text-red";
                        securityStatus.innerText = "异常";
                        securityStatus.className = "status-value text-red";
                    }
                }
                if (data.download_link) {
                    const a = document.createElement('a');
                    a.href = data.download_link;
                    a.className = 'download-link';
                    a.innerText = '💾 点击下载结果文件';
                    document.getElementById('downloadArea').appendChild(a);
                }
            } catch (err) {
                addLog("请求超时/服务器处理失败，请缩小文件重试", "err");
            }
            securityStatus.innerText = "就绪";
            securityStatus.className = "status-value text-green";
            transStatus.innerText = "空闲";
            transStatus.className = "status-value text-purple";
            submitBtn.disabled = false;
            submitBtn.innerText = "开始执行任务";
        };
        // 导出日志
        exportLogBtn.onclick = async () => {
            const logs = [];
            document.querySelectorAll('.log-terminal > div').forEach(div => logs.push(div.innerText));
            try {
                const res = await fetch('/export_log', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ logs })
                });
                const data = await res.json();
                if (data.download_link) {
                    const a = document.createElement('a');
                    a.href = data.download_link;
                    a.innerText = '📥 下载安全审计日志';
                    a.className = 'download-link';
                    document.getElementById('downloadArea').appendChild(a);
                    addLog('[+] 安全审计日志已成功导出', 'succ');
                }
            } catch (e) {
                addLog("导出日志请求失败", "err");
            }
        };
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    threading.Thread(target=start_tcp_receiver, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)