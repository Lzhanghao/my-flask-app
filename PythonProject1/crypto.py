
from config import Config
from gmssl import sm4
import base64


class FileCrypto:
    def __init__(self, key):
        self.key = key
        self.cipher = sm4.CryptSM4()  # 创建 CryptSM4 对象
        self.cipher.set_key(self.key, sm4.SM4_ENCRYPT)  # 设置密钥和加密模式

    def encrypt(self, data):
        # 加密时需要确保数据长度是 16 的倍数（SM4 的块大小是 16 字节）
        # 这里假设 data 已经是字节类型，且长度符合要求
        return self.cipher.crypt_ecb(data)  # 使用 ECB 模式加密

    def decrypt(self, data):
        return self.cipher.crypt_ecb(data)  # 使用 ECB 模式解密

    def encrypt_file(self, file_path):
        """加密文件"""
        try:
            with open(file_path, 'rb') as f:
                original_data = f.read()

            encrypted_data = self.encrypt(original_data)

            # 重命名文件并写入加密数据（或覆盖原文件）
            # 这里我们加个后缀表示已加密
            encrypted_path = file_path + ".enc"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # 删除原文件（可选，安全场景下建议删除）
            # os.remove(file_path)

            return encrypted_path

        except Exception as e:
            print(f"加密文件 {file_path} 时出错: {e}")
            return None

    def decrypt_file(self, encrypted_path):
        """解密文件"""
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.decrypt(encrypted_data)

            # 去掉后缀
            decrypted_path = encrypted_path.replace(".enc", "")
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)

            return decrypted_path

        except Exception as e:
            print(f"解密文件 {encrypted_path} 时出错: {e}")
            return None