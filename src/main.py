from fastapi import FastAPI
from pydantic import BaseModel
import base64
from datetime import datetime

from db import init_db
from cryption import key_manager, server_register, server_login, get_public_keys


app = FastAPI()


@app.on_event("startup")
def _startup() -> None:
	# 初始化数据库表
	init_db()


@app.get("/")
@app.get("/nihao")
async def read_root():
	return {"message": "Hello, world!"}


@app.get("/api/login/publickeys")
async def api_public_keys():
	# 返回可用公钥列表：[{id, public_key}]
	return {"keys": get_public_keys()}


class LoginRegisterItem(BaseModel):
	name: str
	key_id: str
	key: str  # base64 编码的密文


@app.post("/api/login/register")
async def register(item: LoginRegisterItem):
	plaintext = base64.b64decode(item.key)
	ok = server_register(item.name, item.key_id, plaintext)
	return {"ok": ok}


@app.post("/api/login/login")
async def login(item: LoginRegisterItem):
	plaintext = base64.b64decode(item.key)
	ok, roles = server_login(item.name, item.key_id, plaintext)
	return {"ok": ok, "roles": roles}

class KeyGenItem(BaseModel):
	key_id: str | None = None


@app.post("/api/login/keys/generate")
async def generate_key(item: KeyGenItem):
	new_id = item.key_id or f"key-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
	public_pem = key_manager.generate_key(new_id)
	return {"id": new_id, "public_key": public_pem}


