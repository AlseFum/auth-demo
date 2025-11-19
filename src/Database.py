from typing import Dict, Any, Optional, List, Tuple
import json
import os
from abc import ABC, abstractmethod

class Sheet(ABC):
    """抽象Sheet类，所有数据表的基类"""
    
    def __init__(self, sheet_name: str, data_dir: str = "data") -> None:
        """初始化Sheet"""
        self.sheet_name = sheet_name
        self.data_dir = data_dir
        self.file_path = os.path.join(data_dir, f"{sheet_name}.sheet.json")
        self.data: Dict[str, Any] = {}
        self.load()
        
    def load(self) -> None:
        """从文件加载数据"""
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.data = {}
        else:
            self.data = {}
            
    def save(self) -> None:
        """保存数据到文件"""
        os.makedirs(self.data_dir, exist_ok=True)
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except IOError as e:
            print(f"保存数据失败: {e}")
            
    def get(self, key: str) -> Optional[Any]:
        """获取数据"""
        return self.data.get(key)
        
    def set(self, key: str, value: Any) -> None:
        """设置数据"""
        self.data[key] = value
        self.save()
        
    def delete(self, key: str) -> bool:
        """删除数据"""
        if key in self.data:
            del self.data[key]
            self.save()
            return True
        return False
        
    def keys(self) -> List[str]:
        """获取所有键"""
        return list(self.data.keys())
        
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return self.data.copy()
        
    def from_dict(self, data: Dict[str, Any]) -> None:
        """从字典加载数据"""
        self.data = data.copy()
        self.save()

# 具体的Sheet实现
class UserSheet(Sheet):
    """用户凭据Sheet"""
    
    def __init__(self, data_dir: str = "data") -> None:
        super().__init__("users", data_dir)
        
    def store_user_credential(self, username: str, salt: bytes, hashed_password: bytes, key_id: str) -> bool:
        """存储用户凭据"""
        try:
            user_data = self.get(username) or {"credentials": [], "roles": []}
            user_data["credentials"].append({
                "salt": salt.hex(),
                "hashed_password": hashed_password.hex(),
                "key_id": key_id
            })
            self.set(username, user_data)
            return True
        except Exception as e:
            print(f"存储用户凭据失败: {e}")
            return False
        
    def get_credentials(self, username: str, key_id: str) -> List[Tuple[bytes, bytes]]:
        """获取用户凭据"""
        user_data = self.get(username)
        if not user_data:
            return []
        
        credentials = []
        try:
            for cred in user_data.get("credentials", []):
                if cred["key_id"] == key_id:
                    salt = bytes.fromhex(cred["salt"])
                    hashed_password = bytes.fromhex(cred["hashed_password"])
                    credentials.append((salt, hashed_password))
        except (ValueError, KeyError) as e:
            print(f"解析凭据失败: {e}")
            
        return credentials
        
    def get_user_roles(self, username: str) -> List[str]:
        """获取用户角色"""
        user_data = self.get(username)
        return user_data.get("roles", []) if user_data else []
        
    def set_user_roles(self, username: str, roles: List[str]) -> bool:
        """设置用户角色"""
        try:
            user_data = self.get(username) or {"credentials": [], "roles": []}
            user_data["roles"] = roles
            self.set(username, user_data)
            return True
        except Exception as e:
            print(f"设置用户角色失败: {e}")
            return False

class ContentSheet(Sheet):
    """内容存储Sheet - 实现双重加密"""
    
    def __init__(self, data_dir: str = "data") -> None:
        super().__init__("contents", data_dir)
        
    def store_content(self, account: str, content_key: str, encrypted_content: str, 
                     encrypted_symmetric_key: str, key_id: str) -> bool:
        """存储双重加密的内容"""
        try:
            account_data = self.get(account) or {}
            account_data[content_key] = {
                "encrypted_content": encrypted_content,
                "encrypted_symmetric_key": encrypted_symmetric_key,
                "key_id": key_id
            }
            self.set(account, account_data)
            return True
        except Exception as e:
            print(f"存储内容失败: {e}")
            return False
        
    def get_content(self, account: str, content_key: str) -> Optional[Dict[str, str]]:
        """获取加密内容"""
        account_data = self.get(account)
        if not account_data:
            return None
        return account_data.get(content_key)
        
    def delete_content(self, account: str, content_key: str) -> bool:
        """删除内容"""
        try:
            account_data = self.get(account)
            if not account_data or content_key not in account_data:
                return False
            del account_data[content_key]
            self.set(account, account_data)
            return True
        except Exception as e:
            print(f"删除内容失败: {e}")
            return False
        
    def list_user_contents(self, account: str) -> List[str]:
        """列出用户的所有内容键"""
        account_data = self.get(account)
        return list(account_data.keys()) if account_data else []
        
    def get_contents_by_key_id(self, key_id: str) -> List[Tuple[str, str]]:
        """获取使用指定密钥的所有内容"""
        results = []
        try:
            for account in self.keys():
                account_data = self.get(account)
                if account_data:
                    for content_key, content_info in account_data.items():
                        if isinstance(content_info, dict) and content_info.get("key_id") == key_id:
                            results.append((account, content_key))
        except Exception as e:
            print(f"查询内容失败: {e}")
        return results
    
    def migrate_content_key(self, old_key_id: str, new_key_id: str, 
                           content_key_mapping: Dict[str, str]) -> int:
        """迁移内容的加密密钥
        Args:
            old_key_id: 旧密钥ID
            new_key_id: 新密钥ID  
            content_key_mapping: {old_encrypted_key: new_encrypted_key}
        Returns: 迁移的内容数量
        """
        migrated_count = 0
        try:
            for account in self.keys():
                account_data = self.get(account)
                if not account_data:
                    continue
                
                updated = False
                for content_key, content_info in account_data.items():
                    if (isinstance(content_info, dict) and 
                        content_info.get("key_id") == old_key_id):
                        
                        old_encrypted_key = content_info["encrypted_symmetric_key"]
                        if old_encrypted_key in content_key_mapping:
                            content_info["encrypted_symmetric_key"] = content_key_mapping[old_encrypted_key]
                            content_info["key_id"] = new_key_id
                            updated = True
                            migrated_count += 1
                
                if updated:
                    self.set(account, account_data)
                    
        except Exception as e:
            print(f"迁移内容密钥失败: {e}")
            
        return migrated_count

# 全局Sheet实例
user_sheet: Optional[UserSheet] = None
content_sheet: Optional[ContentSheet] = None

def init_db(data_dir: str = "data") -> None:
    """初始化数据库"""
    global user_sheet, content_sheet
    user_sheet = UserSheet(data_dir)
    content_sheet = ContentSheet(data_dir)

# 便捷函数
def store_user_credential(username: str, salt: bytes, hashed_password: bytes, key_id: str) -> bool:
    """存储用户凭据"""
    if user_sheet is None:
        init_db()
    return user_sheet.store_user_credential(username, salt, hashed_password, key_id)

def get_credentials(username: str, key_id: str) -> List[Tuple[bytes, bytes]]:
    """获取用户凭据"""
    if user_sheet is None:
        init_db()
    return user_sheet.get_credentials(username, key_id)

def get_user_roles(username: str) -> List[str]:
    """获取用户角色"""
    if user_sheet is None:
        init_db()
    return user_sheet.get_user_roles(username)
