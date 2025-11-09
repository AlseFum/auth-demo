import os
import json
import base64
from typing import Dict, Any, List, Tuple

DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "data.json")


def _ensure_dirs() -> None:
	if not os.path.isdir(DATA_DIR):
		os.makedirs(DATA_DIR, exist_ok=True)


def _empty_data() -> Dict[str, Any]:
	return {
		"users": [],  # {id, username}
		"credentials": [],  # {id, user_id, salt(b64), password_hash(b64), key_id}
		"roles": [],  # {id, name}
		"user_roles": [],  # {user_id, role_id}
		"next_ids": {"user": 1, "credential": 1, "role": 1},
	}


def _load_data() -> Dict[str, Any]:
	_ensure_dirs()
	if not os.path.exists(DATA_FILE):
		return _empty_data()
	with open(DATA_FILE, "r", encoding="utf-8") as f:
		return json.load(f)


def _save_data(data: Dict[str, Any]) -> None:
	_ensure_dirs()
	tmp_path = DATA_FILE + ".tmp"
	with open(tmp_path, "w", encoding="utf-8") as f:
		json.dump(data, f, ensure_ascii=False, indent=2)
	os.replace(tmp_path, DATA_FILE)


def init_db() -> None:
	"""初始化本地 JSON 存储"""
	data = _load_data()
	# 若文件不存在，会返回空结构；保存一次以生成文件
	_save_data(data)


def _get_or_create_user_id(username: str) -> int:
	data = _load_data()
	for u in data["users"]:
		if u["username"] == username:
			return u["id"]
	# create
	new_id = data["next_ids"]["user"]
	data["next_ids"]["user"] = new_id + 1
	data["users"].append({"id": new_id, "username": username})
	_save_data(data)
	return new_id


def _b64e(b: bytes) -> str:
	return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
	return base64.b64decode(s.encode("ascii"))


def store_user_credential(username: str, salt: bytes, password_hash: bytes, key_id: str) -> bool:
	"""为用户新增（或保持唯一）一个凭证"""
	try:
		user_id = _get_or_create_user_id(username)
		data = _load_data()
		# 唯一性：同一 user_id + hash + key_id 只存一次
		salt_b64 = _b64e(salt)
		hash_b64 = _b64e(password_hash)
		for c in data["credentials"]:
			if c["user_id"] == user_id and c["password_hash"] == hash_b64 and c["key_id"] == key_id:
				return True
		new_id = data["next_ids"]["credential"]
		data["next_ids"]["credential"] = new_id + 1
		data["credentials"].append(
			{
				"id": new_id,
				"user_id": user_id,
				"salt": salt_b64,
				"password_hash": hash_b64,
				"key_id": key_id,
			}
		)
		_save_data(data)
		return True
	except Exception as e:
		print(f"存储凭证失败: {str(e)}")
		return False


def get_credentials(username: str, key_id: str) -> List[Tuple[bytes, bytes]]:
	"""获取指定用户在某 key_id 下的全部凭证 [(salt, hash), ...]"""
	try:
		data = _load_data()
		user_id = None
		for u in data["users"]:
			if u["username"] == username:
				user_id = u["id"]
				break
		if user_id is None:
			return []
		out = []
		for c in data["credentials"]:
			if c["user_id"] == user_id and c["key_id"] == key_id:
				out.append((_b64d(c["salt"]), _b64d(c["password_hash"])))
		return out
	except Exception as e:
		print(f"获取凭证失败: {str(e)}")
		return []


def get_user_roles(username: str) -> List[str]:
	"""获取用户的全部角色名 [role, ...]"""
	try:
		data = _load_data()
		user_id = None
		for u in data["users"]:
			if u["username"] == username:
				user_id = u["id"]
				break
		if user_id is None:
			return []
		role_id_to_name = {r["id"]: r["name"] for r in data["roles"]}
		roles = []
		for ur in data["user_roles"]:
			if ur["user_id"] == user_id and ur["role_id"] in role_id_to_name:
				roles.append(role_id_to_name[ur["role_id"]])
		return sorted(set(roles))
	except Exception as e:
		print(f"获取用户角色失败: {str(e)}")
		return []


if __name__ == "__main__":
	init_db()

