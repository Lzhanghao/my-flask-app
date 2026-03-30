# utils.py - 工具类集合

import os
import logging
from config import Config
from docx import Document
from config import SENSITIVE_WORDS, SENSITIVE_PATTERNS

# --- 日志模块 ---
def setup_logger():
    """初始化日志系统"""
    logging.basicConfig(
        filename=Config.LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        encoding='utf-8'  # 防止写入中文时出错
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    logging.info("日志系统已启动")


# utils.py

import os
from docx import Document # 必须导入这个

import os
from docx import Document

def read_docx_content(file_path):
    """
    强制读取 DOCX 文件（解决文件被占用问题）
    """
    try:
        # --- 关键修复：使用 open() 的二进制模式读取 ---
        # 这样可以绕过 Windows 对文件的独占锁定
        with open(file_path, 'rb') as f:
            doc = Document(f)

        # 提取文本
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)

        return '\n'.join(full_text)

    except Exception as e:
        print(f"读取失败: {e}")
        return ""

    except Exception as e:
        print(f"读取文件出错: {e}")
        return ""

    except Exception as e:
        # 如果读取失败，返回错误信息
        return f"读取错误: {str(e)}"

# --- 文件扫描模块 ---
def scan_files(directory):
    """递归扫描指定目录下的所有文件"""
    found_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 检查文件扩展名是否在支持列表中
            if any(file.lower().endswith(ext) for ext in Config.SUPPORTED_EXTENSIONS):
                full_path = os.path.join(root, file)
                found_files.append(full_path)
    return found_files


# --- 敏感词检测模块 ---
def contains_sensitive_word(content):
    """检测文本内容是否包含敏感词"""
    for word in Config.SENSITIVE_WORDS:
        if word in content:
            return word  # 返回第一个匹配的敏感词
    return None