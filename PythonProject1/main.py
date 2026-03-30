import os
import logging
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from pathlib import Path
from utils import setup_logger, scan_files, contains_sensitive_word
from crypto import FileCrypto
from config import Config, SENSITIVE_WORDS

# --- GUI 界面类 ---
class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ 敏感文件监控与加密系统 v1.0")
        self.root.geometry("800x600")
        # 设置背景色，让界面看起来更统一
        self.root.configure(bg="#f0f0f0")

        # --- 顶部标题区域 ---
        title_frame = tk.Frame(root, bg="#4a90e2", pady=15)
        title_frame.pack(fill="x")
        title_label = tk.Label(title_frame, text="敏感文件自动检测与加密工具",
                               font=("微软雅黑", 16, "bold"), fg="white", bg="#4a90e2")
        title_label.pack()

        # --- 主体内容区域 ---
        main_frame = tk.Frame(root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        # 左侧：操作说明
        left_frame = tk.Frame(main_frame, bg="#f0f0f0", width=300)
        left_frame.pack(side="left", fill="y", padx=(0, 20))

        # 加大字体，作为引导
        guide_label = tk.Label(left_frame,
                               text="操作指引",
                               font=("微软雅黑", 12, "bold"),
                               bg="#f0f0f0",
                               justify="left",
                               wraplength=280)
        guide_label.pack(anchor="w", pady=(0, 10))

        steps = """1. 点击下方按钮选择需要检测的文件或文件夹。
2. 系统将自动扫描内容中的敏感词（如身份证、密码等）。
3. 检测到隐私信息后，系统将自动进行加密处理。"""
        steps_label = tk.Label(left_frame, text=steps, bg="#f0f0f0", fg="#555", justify="left", wraplength=280)
        steps_label.pack(anchor="w")

        # 右侧：日志显示
        right_frame = tk.Frame(main_frame, bg="#f0f0f0")
        right_frame.pack(side="right", fill="both", expand=True)

        log_title = tk.Label(right_frame, text="实时监控日志:", font=("微软雅黑", 10, "bold"), bg="#f0f0f0")
        log_title.pack(anchor="w")

        # 日志框（使用 ScrolledText）
        self.log_text = scrolledtext.ScrolledText(right_frame, state="disabled", height=25, bg="white", relief="sunken")
        self.log_text.pack(fill="both", expand=True, pady=5)

        # --- 底部按钮区域 ---
        btn_frame = tk.Frame(root, bg="#f0f0f0", pady=15)
        btn_frame.pack(fill="x", side="bottom")

        # 使用 ttk.Style 来美化按钮样式
        style = ttk.Style()
        style.configure('TButton', font=('微软雅黑', 10), padding=5)

        self.scan_btn = ttk.Button(btn_frame, text="🚀 开始扫描与加密", command=self.start_process, width=25, style='TButton')
        self.scan_btn.pack(side="left", expand=True, padx=40)

        self.exit_btn = ttk.Button(btn_frame, text="❌ 退出系统", command=root.quit, width=25, style='TButton')
        self.exit_btn.pack(side="right", expand=True, padx=40)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 初始化加密器
        self.key = b'1234567890abcdef'
        self.crypto = FileCrypto(self.key)

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)

    def start_process(self):
        self.log(">>> 启动任务：敏感文件监控与加密")
        self.status_var.set("正在运行...")
        self.scan_btn.config(state=tk.DISABLED)

        # --- 复制你原来的 main 逻辑 ---
        try:
            self.log(f"开始扫描目录: {Config.ROOT_DIR}")
            files = scan_files(Config.ROOT_DIR)
            self.log(f"共发现 {len(files)} 个待检测文件")

            detected_files = []

            for file in files:
                self.log(f"正在检测: {file}")
                content = self.read_file_content(file)

                sensitive_word = contains_sensitive_word(content)
                if sensitive_word:
                    self.log(f"⚠️ 发现敏感词: [{sensitive_word}] 在文件 {file} 中")
                    detected_files.append(file)

                    self.log(f"正在加密文件: {file}")
                    new_path = self.crypto.encrypt_file(file)
                    if new_path:
                        self.log(f"✅ 文件已加密并保存为: {new_path}")

            if detected_files:
                self.log(f"\n--- 扫描结束 ---")
                self.log(f"共检测到 {len(detected_files)} 个包含敏感词的文件，已全部加密。")
                messagebox.showinfo("任务完成", f"共加密 {len(detected_files)} 个文件！")
            else:
                self.log("未发现敏感文件，系统正常。")
                messagebox.showinfo("任务完成", "未发现敏感文件，一切正常。")

        except Exception as e:
            self.log(f"❌ 系统错误: {str(e)}")
            messagebox.showerror("错误", f"程序出错: {str(e)}")

        finally:
            self.status_var.set("任务完成")
            self.scan_btn.config(state=tk.NORMAL)

    def read_file_content(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext == ".docx":
                doc = Document(file_path)
                text = []
                for para in doc.paragraphs:
                    text.append(para.text)
                return "\n".join(text)

            elif ext in [".txt", ".csv"]:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()

            else:
                return ""

        except Exception as e:
            self.log(f"⚠️ 无法读取文件内容 {file_path}: {e}")
            return ""

if __name__ == "__main__":
    setup_logger()
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()