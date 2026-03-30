# client.py - 员工电脑运行
from gmssl import sm4
import os
import json

# 注意：为了演示方便，客户端加密也用这个密钥。
# 实际企业环境中，客户端密钥可能由服务器动态下发，或者使用固定密钥。
KEY = "16位密钥12345678".encode("utf-8")


def scan_and_encrypt(file_path):
    """方案⑤：扫描文件内容，发现敏感词则加密"""

    # 1. 读取文件内容 (假设是文本文件，如果是二进制文件如docx，需要专门的库读文本)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        print("非文本文件，跳过内容检测（实际应用需用docx等库）")
        return False

    # 2. 检测敏感词 (模拟方案⑤)
    sensitive_words = ["机密", "密码", "绝密", "身份证"]
    for word in sensitive_words:
        if word in content:
            print(f"发现敏感词: {word}")
            encrypt_file(file_path)
            return True  # 表示触发了拦截
    return False


def encrypt_file(file_path):
    """执行加密操作"""
    # --- 1. 生成随机IV ---
    iv = os.urandom(16)

    # --- 2. 读取原始文件数据 ---
    with open(file_path, 'rb') as f:
        plain_data = f.read()

    # --- 3. 执行SM4加密 ---
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(KEY, sm4.SM4_ENCRYPT)
    cipher_data = crypt_sm4.crypt_cbc(iv, plain_data)

    # --- 4. 将 IV + 密文 写回文件 ---
    with open(file_path, 'wb') as f:
        f.write(iv + cipher_data)  # 前16字节是IV，后面是密文

    print(f"[系统] 文件 {file_path} 已被加密保护！")


def request_decrypt(file_path):
    """员工申请解密（模拟点击按钮）"""
    request_data = {
        "user": "employee_007",
        "target_file": file_path,
        "reason": "误拦截，需要正常外发",
        "status": "待处理"
    }
    # 模拟网络传输：写入一个json文件给管理员看
    with open("dlp_admin_console.json", "w", encoding="utf-8") as f:
        json.dump(request_data, f, indent=4)

    print("[系统] 解密申请已发送给管理员，请等待批复...")


# --- 演示主流程 ---
if __name__ == "__main__":
    target_file = "data/test.docx"  # 假设这是要监控的文件

    # 模拟创建一个测试文件（内容包含敏感词）
    with open(target_file, "w", encoding="utf-8") as f:
        f.write("这是一份机密文件，包含敏感信息。")

    print("=== 开始扫描文件 ===")
    triggered = scan_and_encrypt(target_file)

    if triggered:
        print("=== 文件已被锁定 ===")
        # 模拟员工发现误拦截，申请解密
        user_input = input("文件被加密，是否申请解密？(y/n): ")
        if user_input.lower() == 'y':
            request_decrypt(target_file)