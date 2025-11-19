import base64
import tempfile
import unittest
import os
import sys
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from Key import KeyManager
from Database import UserSheet, ContentSheet
from Util import generate_timestamp, generate_short_password


class TestAuthFlow(unittest.TestCase):
    def test_register_and_login_flow(self):
        with tempfile.TemporaryDirectory() as td:
            # 创建测试环境
            key_manager = KeyManager(td)
            user_sheet = UserSheet(td)
            content_sheet = ContentSheet(td)

            # 获取公钥（default）
            keys = key_manager.get_public_keys()
            self.assertTrue(any(k["id"] == "default" for k in keys))
            pub_pem = next(k["public_key"] for k in keys if k["id"] == "default").encode("utf-8")

            # 模拟客户端加密请求
            public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
            
            # 构造注册载荷
            payload = {
                "account": "alice",
                "cmd": "reg",
                "shortpwd": generate_short_password(),
                "content": ["secret-password", "Alice"],
                "timestamp": generate_timestamp()
            }
            
            payload_json = json.dumps(payload).encode('utf-8')
            ciphertext = public_key.encrypt(
                payload_json,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # 模拟服务器解密
            decrypted = key_manager.decrypt("default", ciphertext)
            decrypted_payload = json.loads(decrypted.decode('utf-8'))
            
            self.assertEqual("alice", decrypted_payload["account"])
            self.assertEqual("reg", decrypted_payload["cmd"])
            self.assertEqual(["secret-password", "Alice"], decrypted_payload["content"])

    def test_content_storage_flow(self):
        with tempfile.TemporaryDirectory() as td:
            key_manager = KeyManager(td)
            content_sheet = ContentSheet(td)
            
            # 测试内容存储
            account = "alice"
            content_key = "my_secret"
            encrypted_content = "encrypted_data_here"
            encrypted_symmetric_key = "encrypted_key_here"
            key_id = "default"
            
            success = content_sheet.store_content(
                account, content_key, encrypted_content, 
                encrypted_symmetric_key, key_id
            )
            self.assertTrue(success)
            
            # 测试内容获取
            retrieved = content_sheet.get_content(account, content_key)
            self.assertIsNotNone(retrieved)
            self.assertEqual(encrypted_content, retrieved["encrypted_content"])
            self.assertEqual(key_id, retrieved["key_id"])
            
            # 测试内容删除
            deleted = content_sheet.delete_content(account, content_key)
            self.assertTrue(deleted)
            
            # 验证删除后无法获取
            retrieved_after_delete = content_sheet.get_content(account, content_key)
            self.assertIsNone(retrieved_after_delete)


if __name__ == "__main__":
    unittest.main()


