# admin.py - 管理员后台运行
from gmssl import sm4
import json
import os

# --- 核心密钥 ---
# 只有管理员拥有这个密钥
# 必须和 client.py 里的 KEY 一致，否则解密失败
MASTER_KEY = '16位密钥12345678'


def decrypt_file(encrypted_file_path, output_path):
    """管理员执行解密"""
    with open(encrypted_file_path, 'rb') as f:
        # --- 1. 自动读取前16字节 -> 这就是 IV ---
        iv = f.read(16)
        print(f"[调试] 读取到IV: {iv.hex()}")  # 打印IV看看（自动获取的）

        # --- 2. 读取剩余数据 -> 这就是密文 ---
        cipher_data = f.read()

    # --- 3. 创建SM4解密对象 ---
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(MASTER_KEY, sm4.SM4_DECRYPT)  # 使用管理员密钥

    # --- 4. 执行解密 ---
    try:
        plain_data = crypt_sm4.crypt_cbc(iv, cipher_data)
        with open(output_path, 'wb') as f:
            f.write(plain_data)
        print(f"[管理员] 解密成功！文件已恢复为: {output_path}")
    except Exception as e:
        print("[错误] 解密失败，密钥或IV不正确:", e)


def admin_console():
    """管理员控制台主程序"""
    print("=== 管理员后台启动 (等待申请...) ===")

    while True:
        try:
            # 检查是否有申请文件
            if os.path.exists("dlp_admin_console.json"):
                with open("dlp_admin_console.json", "r", encoding="utf-8") as f:
                    req = json.load(f)

                print("\n--- 收到新申请 ---")
                print(f"用户: {req['user']}")
                print(f"文件: {req['target_file']}")
                print(f"理由: {req['reason']}")

                action = input("\n是否批准解密？(y/n): ")
                if action.lower() == 'y':
                    # 执行解密
                    # 生成恢复后的文件名
                    restored_name = req['target_file'].replace(".docx", "_恢复版.docx")
                    decrypt_file(req['target_file'], restored_name)

                    # 清理申请文件
                    os.remove("dlp_admin_console.json")
                    print("申请已处理，申请记录已清除。\n")
                else:
                    print("已拒绝申请。\n")
                    os.remove("dlp_admin_console.json")

        except KeyboardInterrupt:
            print("\n管理员后台关闭。")
            break
        except Exception as e:
            # print("等待中...", e)
            pass


if __name__ == "__main__":
    admin_console()