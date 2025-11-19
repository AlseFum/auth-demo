from typing import Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import time

class KeyManager:
    """RSA密钥管理器，支持密钥轮换和热度统计"""
    
    def __init__(self, key_dir: str = "data", key_suffix: str = ".key.pem") -> None:
        """初始化密钥管理器"""
        self.key_dir = key_dir
        self.key_suffix = key_suffix
        self.id_to_private: Dict[str, rsa.RSAPrivateKey] = {}
        self.id_to_public_pem: Dict[str, str] = {}
        self.key_usage_stats: Dict[str, int] = {}  # 密钥使用统计
        self.key_creation_time: Dict[str, float] = {}  # 密钥创建时间
        self.ensure_dir()
        self.load_all_keys()
        
    def ensure_dir(self) -> None:
        """确保密钥目录存在"""
        if not os.path.isdir(self.key_dir):
            os.makedirs(self.key_dir, exist_ok=True)
        
    def load_all_keys(self) -> None:
        """加载所有密钥文件"""
        self.id_to_private.clear()
        self.id_to_public_pem.clear()
        
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
            
            self.id_to_private[key_id] = private_key
            self.id_to_public_pem[key_id] = public_pem
            
            # 初始化统计信息
            if key_id not in self.key_usage_stats:
                self.key_usage_stats[key_id] = 0
            if key_id not in self.key_creation_time:
                self.key_creation_time[key_id] = os.path.getmtime(path)
        
        # 若目录为空则自动生成默认密钥
        if not self.id_to_private:
            self.generate_key("default")
        
    def get_public_keys(self) -> List[Dict[str, str]]:
        """获取所有公钥列表
        Returns: [{"id": str, "public_key": str, "usage_count": int}]
        """
        return [
            {
                "id": key_id, 
                "public_key": pem,
                "usage_count": self.key_usage_stats.get(key_id, 0)
            } 
            for key_id, pem in self.id_to_public_pem.items()
        ]
        
    def get_public_key_pem(self, key_id: str) -> str:
        """获取指定密钥的公钥PEM格式"""
        pem = self.id_to_public_pem.get(key_id)
        if pem is None:
            raise KeyError(f"未找到对应 key_id: {key_id}")
        return pem
        
    def decrypt(self, key_id: str, encrypted_data: bytes) -> bytes:
        """使用指定私钥解密数据"""
        private_key = self.id_to_private.get(key_id)
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
    
    def encrypt_with_public_key(self, key_id: str, data: bytes) -> bytes:
        """使用指定公钥加密数据"""
        private_key = self.id_to_private.get(key_id)
        if private_key is None:
            raise KeyError(f"未找到对应 key_id: {key_id}")
        
        public_key = private_key.public_key()
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    def generate_key(self, key_id: str, key_size: int = 2048) -> str:
        """生成新的RSA密钥对并持久化"""
        if key_id in self.id_to_private:
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
        
        self.id_to_private[key_id] = private_key
        self.id_to_public_pem[key_id] = public_pem
        self.key_usage_stats[key_id] = 0
        self.key_creation_time[key_id] = time.time()
        
        return public_pem
        
    def record_key_usage(self, key_id: str) -> None:
        """记录密钥使用次数"""
        if key_id in self.key_usage_stats:
            self.key_usage_stats[key_id] += 1
        
    def get_hot_keys(self, threshold: int = 1000) -> List[str]:
        """获取高热度密钥列表（需要轮换的密钥）"""
        return [
            key_id for key_id, usage_count in self.key_usage_stats.items()
            if usage_count >= threshold
        ]
        
    def rotate_key(self, old_key_id: str, new_key_id: str) -> bool:
        """密钥轮换：生成新密钥，迁移数据，删除旧密钥"""
        try:
            # 生成新密钥
            self.generate_key(new_key_id)
            
            # TODO: 这里需要与Database模块配合迁移内容
            # 暂时返回True，具体迁移逻辑在Database模块中实现
            
            return True
        except Exception as e:
            print(f"密钥轮换失败: {str(e)}")
            return False
        
    def delete_key(self, key_id: str) -> bool:
        """删除指定密钥（仅在确认无数据使用时）"""
        if key_id not in self.id_to_private:
            return False
        
        try:
            # 删除文件
            path = os.path.join(self.key_dir, f"{key_id}{self.key_suffix}")
            if os.path.exists(path):
                os.remove(path)
            
            # 清理内存
            del self.id_to_private[key_id]
            del self.id_to_public_pem[key_id]
            if key_id in self.key_usage_stats:
                del self.key_usage_stats[key_id]
            if key_id in self.key_creation_time:
                del self.key_creation_time[key_id]
            
            return True
        except Exception as e:
            print(f"删除密钥失败: {str(e)}")
            return False

# 全局密钥管理器实例
key_manager = KeyManager("data")

# 导出函数
def get_public_keys() -> List[Dict[str, str]]:
    """获取公钥列表的便捷函数"""
    return key_manager.get_public_keys()
