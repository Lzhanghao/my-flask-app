import os

# --- 敏感词配置 ---
# 支持多个敏感词，用逗号分隔
SENSITIVE_WORDS = [
    "机密", "绝密", "密码", "身份证", "测试", "test", "敏感","合同"]

# 敏感模式：用于匹配身份证号、手机号等格式的正则表达式
SENSITIVE_PATTERNS = [
    r"\d{18}",  # 身份证号
    r"1[3-9]\d{9}",] # 手机号
# 你可以在这里添加更多正则表达式

class Config:
    # --- 基础路径配置 ---
    # 扫描的根目录（可修改）
    ROOT_DIR =r"C:\Users\1\PycharmProjects\PythonProject1\data"
    # 日志文件路径
    LOG_FILE =r"C:\Users\1\PycharmProjects\PythonProject1\log"
    SENSITIVE_WORDS = [
        "机密", "绝密", "密码", "身份证", "测试", "test", "敏感", "合同"]



    # --- 加密配置 ---
    # 密钥（必须是16字节，即16个ASCII字符）
    # 注意：在生产环境中，应从环境变量或硬件安全模块读取，而非硬编码
    MASTER_KEY = b"SecurityKey12345"  # 16 bytes

    # --- 其他配置 ---
    # 支持的文件类型（扩展名）
    SUPPORTED_EXTENSIONS = [".docx", ".pdf", ".txt", ".xlsx"]