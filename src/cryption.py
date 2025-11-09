from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import hashlib
import os
from typing import Dict, List, Tuple

from db import store_user_credential, get_credentials, get_user_roles


# ------------------- 密钥管理：多私钥 -------------------
class KeyManager:
	def __init__(self, key_dir: str = "data", key_suffix: str = ".key.pem") -> None:
		self.key_dir = key_dir
		self.key_suffix = key_suffix
		self._id_to_private = {}  # type: Dict[str, object]
		self._id_to_public_pem = {}  # type: Dict[str, str]
		self._ensure_dir()
		self._load_all_keys()

	def _ensure_dir(self) -> None:
		if not os.path.isdir(self.key_dir):
			os.makedirs(self.key_dir, exist_ok=True)

	def _load_all_keys(self) -> None:
		self._id_to_private.clear()
		self._id_to_public_pem.clear()
		for fname in sorted(os.listdir(self.key_dir)):
			if not fname.lower().endswith(self.key_suffix):
				continue
			key_id = fname[: -len(self.key_suffix)]
			path = os.path.join(self.key_dir, fname)
			with open(path, "rb") as f:
				private_key = serialization.load_pem_private_key(
					f.read(),
					password=None,
					backend=default_backend()
				)
			public_pem = private_key.public_key().public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			).decode("utf-8")
			self._id_to_private[key_id] = private_key
			self._id_to_public_pem[key_id] = public_pem
		# 若目录为空则自动生成默认密钥
		if not self._id_to_private:
			self.generate_key("default")

	def get_public_keys(self) -> List[Dict[str, str]]:
		# 返回 [{id, public_key}]
		return [{"id": key_id, "public_key": pem} for key_id, pem in self._id_to_public_pem.items()]

	def decrypt(self, key_id: str, encrypted_data: bytes) -> bytes:
		private_key = self._id_to_private.get(key_id)
		if private_key is None:
			raise KeyError(f"未找到对应 key_id: {key_id}")
		return private_key.decrypt(
			encrypted_data,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)

	def generate_key(self, key_id: str, key_size: int = 2048) -> str:
		"""生成并持久化一个新的 RSA 私钥，返回公钥 PEM 字符串"""
		if key_id in self._id_to_private:
			raise ValueError(f"key_id 已存在: {key_id}")
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=key_size,
			backend=default_backend()
		)
		private_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)
		path = os.path.join(self.key_dir, f"{key_id}{self.key_suffix}")
		with open(path, "wb") as f:
			f.write(private_pem)
		public_pem = private_key.public_key().public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		).decode("utf-8")
		self._id_to_private[key_id] = private_key
		self._id_to_public_pem[key_id] = public_pem
		return public_pem

	def get_public_key_pem(self, key_id: str) -> str:
		pem = self._id_to_public_pem.get(key_id)
		if pem is None:
			raise KeyError(f"未找到对应 key_id: {key_id}")
		return pem


key_manager = KeyManager("data")


def get_public_keys() -> List[Dict[str, str]]:
	return key_manager.get_public_keys()


# ------------------- 密码哈希 -------------------
def hash_password(password: bytes, salt: bytes) -> bytes:
	return hashlib.pbkdf2_hmac(
		"sha256",
		password,
		salt,
		100000
	)


def verify_password(stored_hash: bytes, salt: bytes, input_password: bytes) -> bool:
	input_hash = hash_password(input_password, salt)
	stored_hash = bytes(stored_hash)
	return input_hash == stored_hash


# ------------------- 服务端逻辑 -------------------
def server_register(username: str, key_id: str, encrypted_data: bytes) -> bool:
	try:
		password = key_manager.decrypt(key_id, encrypted_data)
		salt = os.urandom(16)
		hashed_password = hash_password(password, salt)
		return store_user_credential(username, salt, hashed_password, key_id)
	except Exception as e:
		print(f"注册失败: {str(e)}")
		return False


def server_login(username: str, key_id: str, encrypted_data: bytes) -> Tuple[bool, List[str]]:
	try:
		password = key_manager.decrypt(key_id, encrypted_data)
		creds = get_credentials(username, key_id)
		for salt, stored_hash in creds:
			if verify_password(stored_hash, salt, password):
				roles = get_user_roles(username)
				return True, roles
		return False, []
	except Exception as e:
		print(f"登录失败: {str(e)}")
		return False, []


