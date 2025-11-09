import base64
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

import db as db_mod
import cryption as cryp
from cryption import KeyManager


class TestAuthFlow(unittest.TestCase):
	def test_register_and_login_flow(self):
		with tempfile.TemporaryDirectory() as td:
			# 隔离 data 存储
			db_mod.DATA_DIR = td
			db_mod.DATA_FILE = os.path.join(td, "data.json")  # type: ignore[name-defined]
			db_mod.init_db()

			# 隔离密钥目录并替换模块内的 key_manager
			test_key_manager = KeyManager(td)
			cryp.key_manager = test_key_manager

			# 获取公钥（default）
			keys = cryp.get_public_keys()
			self.assertTrue(any(k["id"] == "default" for k in keys))
			pub_pem = next(k["public_key"] for k in keys if k["id"] == "default").encode("utf-8")

			# 客户端加密
			public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
			password = b"secret-password"
			ciphertext = public_key.encrypt(
				password,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None,
				),
			)

			username = "alice"
			key_id = "default"
			# 注册
			ok = cryp.server_register(username, key_id, ciphertext)
			self.assertTrue(ok)

			# 登录
			ok2, roles = cryp.server_login(username, key_id, ciphertext)
			self.assertTrue(ok2)
			self.assertIsInstance(roles, list)


if __name__ == "__main__":
	unittest.main()


