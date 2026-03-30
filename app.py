from flask import Flask, render_template_string, request, jsonify
import os
import threading
import time

app = Flask(__name__)

# --- 模拟你的核心处理逻辑 ---
# 这里假设你的 utils.py 或 crypto.py 里的函数
def scan_and_encrypt(folder_path):
    """模拟扫描和加密过程"""
    result_logs = []
    result_logs.append(f"[*] 开始扫描目录: {folder_path}")
    time.sleep(1)  # 模拟耗时
    result_logs.append("[+] 发现文件: 财务报告.docx")
    result_logs.append("[!] 检测到敏感词: '机密'")
    result_logs.append("[*] 正在加密文件...")
    time.sleep(1)
    result_logs.append("[+] 加密成功: 财务报告.docx.enc")
    return result_logs

# --- Web 页面代码 ---
# 将 HTML 和 CSS 写在 Python 字符串中，方便你直接运行测试
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>🛡️ 敏感文件监控与加密系统</title>
    <style>
        /* --- 全局样式 --- */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: "Microsoft YaHei", "Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB", "Heiti SC", "Noto Sans CJK SC", "WenQuanYi Micro Hei", sans-serif;
            background-color: #f5f6fa;
            color: #2c3e50;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        /* --- 主容器 --- */
        .container {
            width: 900px;
            height: 700px;
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* --- 顶部标题栏 --- */
        .header {
            background-color: #4a90e2;
            color: white;
            padding: 20px 30px;
            font-size: 24px;
            font-weight: bold;
            letter-spacing: 1px;
        }

        /* --- 内容区域 --- */
        .content {
            display: flex;
            flex: 1;
            padding: 30px;
        }

        /* --- 左侧操作区 --- */
        .left-panel {
            width: 380px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding-right: 30px;
            border-right: 1px solid #e0e0e0;
        }

        .guide-box {
            background-color: #f8f9fa;
            border-left: 4px solid #4a90e2;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }

        .guide-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: #4a90e2;
        }

        .guide-item {
            font-size: 14px;
            line-height: 2;
            color: #555;
        }

        .guide-item span {
            color: #4a90e2;
            margin-right: 5px;
        }

        .btn-group {
            display: flex;
            justify-content: space-between;
        }

        .btn {
            padding: 12px 30px;
            font-size: 16px;
            font-weight: bold;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
            flex: 1;
            margin: 0 5px;
        }

        .btn-start {
            background-color: #4a90e2;
            color: white;
        }

        .btn-exit {
            background-color: #e74c3c;
            color: white;
        }

        .btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }

        /* --- 右侧日志区 --- */
        .right-panel {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding-left: 30px;
        }

        .log-title {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }

        .log-container {
            flex: 1;
            background-color: #1e272e;
            color: #f5f6fa;
            border-radius: 8px;
            padding: 15px;
            font-family: "Consolas", "Monaco", "Courier New", monospace;
            font-size: 13px;
            line-height: 1.6;
            overflow-y: auto;
            white-space: pre-wrap;
        }

        /* --- 状态栏 --- */
        .status-bar {
            background-color: #2c3e50;
            color: #bdc3c7;
            padding: 10px 30px;
            font-size: 12px;
            display: flex;
            justify-content: space-between;
        }

        /* --- 模拟终端样式 --- */
        .log-info { color: #81ecec; } /* 青色 */
        .log-warn { color: #f1c40f; } /* 黄色 */
        .log-error { color: #e74c3c; } /* 红色 */
        .log-success { color: #58d68d; } /* 绿色 */

    </style>
</head>
<body>

    <div class="container">
        <!-- 顶部标题 -->
        <div class="header">
            敏感文件自动检测与加密工具
        </div>

        <!-- 内容主体 -->
        <div class="content">
            <!-- 左侧：操作指引和按钮 -->
            <div class="left-panel">
                <div class="guide-box">
                    <div class="guide-title">操作指引</div>
                    <div class="guide-item"><span>1.</span> 点击下方按钮选择需要检测的文件或文件夹。</div>
                    <div class="guide-item"><span>2.</span> 系统将自动扫描内容中的敏感词 (如身份证、密码等)。</div>
                    <div class="guide-item"><span>3.</span> 检测到隐私信息后，系统将自动进行加密处理。</div>
                </div>

                <div class="btn-group">
                    <button class="btn btn-start" onclick="startProcess()">开始扫描与加密</button>
                    <button class="btn btn-exit" onclick="exitSystem()">退出系统</button>
                </div>
            </div>

            <!-- 右侧：实时日志 -->
            <div class="right-panel">
                <div class="log-title">实时监控日志:</div>
                <div id="log-container" class="log-container">
                    <div class="log-info">[*] 系统已启动，等待用户指令...</div>
                    <div class="log-info">[*] 当前环境: Web 版本</div>
                </div>
            </div>
        </div>

        <!-- 底部状态栏 -->
        <div class="status-bar">
            <span>状态: 就绪</span>
            <span>版本: v1.0</span>
        </div>
    </div>

    <script>
        // 模拟文件选择对话框
        function startProcess() {
            // 这里不能直接调用本地文件选择器，通常 Web 需要上传文件
            // 为了演示效果，我们模拟一个文件路径
            const fakePath = "C:/Users/YourName/Desktop/TestFolder";

            // 更新状态
            updateStatus("正在处理...");
            logMessage("开始任务：敏感文件监控与加密", "info");
            logMessage(`目标路径: ${fakePath}`, "info");

            // 发送请求给后端
            fetch('/process', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ path: fakePath }),
            })
            .then(response => response.json())
            .then(data => {
                data.logs.forEach(log => {
                    logMessage(log, "info");
                });
                logMessage("✅ 任务执行完毕", "success");
                updateStatus("任务完成");
            })
            .catch(error => {
                logMessage("❌ 网络错误: " + error, "error");
                updateStatus("错误");
            });
        }

        function logMessage(msg, type) {
            const logContainer = document.getElementById('log-container');
            const newMsg = document.createElement('div');
            newMsg.className = `log-${type}`;
            newMsg.innerText = msg;
            logContainer.appendChild(newMsg);
            logContainer.scrollTop = logContainer.scrollHeight; // 自动滚动到底部
        }

        function updateStatus(status) {
            document.querySelector('.status-bar span:first-child').innerText = "状态: " + status;
        }

        function exitSystem() {
            if (confirm("确定要退出吗？")) {
                window.close();
            }
        }
    </script>

</body>
</html>
"""

# --- Flask 路由 ---

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/process', methods=['POST'])
def process():
    data = request.get_json()
    target_path = data.get('path', '未知路径')

    # 在子线程中运行耗时的扫描任务，防止阻塞 Web 服务器
    def run_task():
        logs = scan_and_encrypt(target_path)
        # 这里为了演示，直接返回日志
        return jsonify({"logs": logs})

    # 使用线程模拟异步处理
    threading.Thread(target=lambda: run_task()).start()

    # 为了演示流畅，这里直接返回一个成功的日志流
    # 实际应用中，你需要用 WebSocket 或轮询来实时推送日志
    # 这里为了简化，直接返回一个包含所有步骤的日志
    return jsonify({
        "logs": [
            f"[*] 启动任务: 敏感文件监控与加密",
            f"[*] 开始扫描目录: {target_path}",
            "[+] 共发现 3 个待检测文件",
            "[!] 检测到敏感词: '身份证号' 在 10月报表.xlsx 中",
            "[*] 正在加密文件: 10月报表.xlsx",
            "[+] 文件已加密: 10月报表.xlsx.enc",
            "[*] 检测完成，共处理 3 个文件。"
        ]
    })

if __name__ == '__main__':
    print("🚀 Web 系统已启动！")
    print("请在浏览器访问: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)