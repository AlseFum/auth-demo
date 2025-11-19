from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import base64
import json
from datetime import datetime

from Key import key_manager, get_public_keys
from Database import init_db, user_sheet, content_sheet
from Util import (
    verify_timestamp, generate_short_password, encrypt_with_password,
    decrypt_with_password, hash_password, verify_password, generate_salt,
    encrypt_content, decrypt_content, generate_content_key
)

app = FastAPI(title="Auth Demo API", version="1.0.0")

# 请求模型
class PublicKeyRequest(BaseModel):
    cmd: str

class EncryptedRequest(BaseModel):
    encrypted: str  # base64编码的RSA加密数据
    pubkey_id: str

class APIResponse(BaseModel):
    status: str
    value: str = ""

# API端点 (严格按照 auth demo.md)

@app.post("/api/request_public_key")
async def request_public_key(request: PublicKeyRequest) -> Dict[str, str]:
    """请求公钥端点
    请求: {"cmd": "request_public_key"}
    响应: {"pubkey_id": "...", "value": "..."}
    """
    if request.cmd != "request_public_key":
        raise HTTPException(status_code=400, detail="Invalid command")
    
    keys = get_public_keys()
    if not keys:
        raise HTTPException(status_code=500, detail="No keys available")
    
    # 返回使用次数最少的密钥
    selected_key = min(keys, key=lambda k: k.get("usage_count", 0))
    return {
        "pubkey_id": selected_key["id"],
        "value": selected_key["public_key"]
    }

@app.post("/api/encrypted_request")
async def encrypted_request(request: EncryptedRequest) -> APIResponse:
    """处理所有加密请求的统一端点
    请求格式: {
        "encrypted": "base64_encoded_rsa_encrypted_data",
        "pubkey_id": "key_id"
    }
    
    解密后的载荷格式: {
        "account": "用户账户",
        "cmd": "reg|get|set",
        "shortpwd": "短期密码",
        "content": "命令相关内容",
        "timestamp": "时间戳"
    }
    
    响应格式: {
        "status": "success|error",
        "value": "用shortpwd对称加密的响应数据"
    }
    """
    try:
        # 记录密钥使用
        key_manager.record_key_usage(request.pubkey_id)
        
        # RSA解密载荷
        encrypted_data = base64.b64decode(request.encrypted)
        decrypted_json = key_manager.decrypt(request.pubkey_id, encrypted_data)
        payload = json.loads(decrypted_json.decode('utf-8'))
        
        # 验证时间戳
        if not verify_timestamp(payload["timestamp"]):
            return APIResponse(status="error", value="Timestamp expired")
        
        # 分发处理
        account = payload["account"]
        cmd = payload["cmd"]
        shortpwd = payload["shortpwd"]
        content = payload["content"]
        
        if cmd == "reg":
            result = await handle_register(account, content)
        elif cmd == "get":
            result = await handle_get(account, content)
        elif cmd == "set":
            result = await handle_set(account, content)
        else:
            result = {"status": "error", "data": "Unknown command"}
        
        # 用shortpwd加密响应
        response_data = json.dumps(result)
        encrypted_response = encrypt_with_password(response_data, shortpwd)
        
        return APIResponse(
            status="success",
            value=encrypted_response
        )
        
    except Exception as e:
        return APIResponse(status="error", value=str(e))

# 内部处理函数
async def handle_register(account: str, content: List[str]) -> Dict[str, Any]:
    """处理注册命令
    content格式: [password, nickname]
    """
    if len(content) < 1:
        return {"status": "error", "data": "Missing password"}
    
    password = content[0].encode('utf-8')
    nickname = content[1] if len(content) > 1 else ""
    
    # 16位盐 + 慢哈希
    salt = generate_salt(16)
    hashed_password = hash_password(password, salt)
    
    # 存储用户凭据
    success = user_sheet.store_user_credential(account, salt, hashed_password, "default")
    
    return {
        "status": "success" if success else "error",
        "data": {"registered": success, "nickname": nickname}
    }

async def handle_get(account: str, content: List[str]) -> Dict[str, Any]:
    """处理获取命令  
    content格式: [password, content_key, preprocessor?]
    """
    if len(content) < 2:
        return {"status": "error", "data": "Missing password or content_key"}
    
    password = content[0].encode('utf-8')
    content_key = content[1]
    preprocessor = content[2] if len(content) > 2 else None
    
    # 验证密码
    credentials = user_sheet.get_credentials(account, "default")
    password_valid = False
    for salt, stored_hash in credentials:
        if verify_password(stored_hash, salt, password):
            password_valid = True
            break
    
    if not password_valid:
        return {"status": "error", "data": "Invalid password"}
    
    # 获取内容
    content_info = content_sheet.get_content(account, content_key)
    if not content_info:
        return {"status": "error", "data": "Content not found"}
    
    # 双重解密
    try:
        # 解密对称密钥
        encrypted_symmetric_key = base64.b64decode(content_info["encrypted_symmetric_key"])
        symmetric_key = key_manager.decrypt(content_info["key_id"], encrypted_symmetric_key)
        
        # 解密内容
        encrypted_content = base64.b64decode(content_info["encrypted_content"])
        decrypted_content = decrypt_content(encrypted_content, symmetric_key)
        
        return {
            "status": "success",
            "data": {
                "content": decrypted_content.decode('utf-8'),
                "preprocessor": preprocessor
            }
        }
    except Exception as e:
        return {"status": "error", "data": f"Decryption failed: {str(e)}"}

async def handle_set(account: str, content: List[str]) -> Dict[str, Any]:
    """处理设置命令
    content格式: [accountpwd, content_key, content_data]
    content_data为""表示删除
    """
    if len(content) < 3:
        return {"status": "error", "data": "Missing required parameters"}
    
    account_password = content[0].encode('utf-8')
    content_key = content[1]
    content_data = content[2]
    
    # 验证账户密码
    credentials = user_sheet.get_credentials(account, "default")
    password_valid = False
    for salt, stored_hash in credentials:
        if verify_password(stored_hash, salt, account_password):
            password_valid = True
            break
    
    if not password_valid:
        return {"status": "error", "data": "Invalid account password"}
    
    # 删除操作
    if content_data == "":
        success = content_sheet.delete_content(account, content_key)
        return {
            "status": "success" if success else "error",
            "data": {"deleted": success}
        }
    
    # 存储操作 - 双重加密
    try:
        # 生成对称密钥
        symmetric_key = generate_content_key()
        
        # 用对称密钥加密内容
        encrypted_content = encrypt_content(content_data.encode('utf-8'), symmetric_key)
        
        # 用服务器RSA密钥加密对称密钥
        server_key_id = "default"  # 使用默认服务器密钥
        encrypted_symmetric_key = key_manager.encrypt_with_public_key(server_key_id, symmetric_key)
        
        # 存储
        success = content_sheet.store_content(
            account, 
            content_key,
            base64.b64encode(encrypted_content).decode('utf-8'),
            base64.b64encode(encrypted_symmetric_key).decode('utf-8'),
            server_key_id
        )
        
        return {
            "status": "success" if success else "error",
            "data": {"stored": success}
        }
    except Exception as e:
        return {"status": "error", "data": f"Storage failed: {str(e)}"}

# 管理端点
@app.post("/admin/keys/generate")
async def generate_key(key_id: str = None) -> Dict[str, str]:
    """生成新密钥"""
    if not key_id:
        key_id = f"key-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    try:
        public_pem = key_manager.generate_key(key_id)
        return {"id": key_id, "public_key": public_pem}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin/keys/hot")
async def get_hot_keys() -> List[str]:
    """获取高热度密钥"""
    return key_manager.get_hot_keys()

@app.post("/admin/keys/rotate")
async def rotate_key(old_key_id: str, new_key_id: str) -> Dict[str, Any]:
    """密钥轮换"""
    try:
        success = key_manager.rotate_key(old_key_id, new_key_id)
        return {"rotated": success, "old_key": old_key_id, "new_key": new_key_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 启动事件
@app.on_event("startup")
async def startup_event() -> None:
    """应用启动初始化"""
    init_db()

# 根端点
@app.get("/")
async def root() -> Dict[str, str]:
    """根端点"""
    return {"message": "Auth Demo API", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
