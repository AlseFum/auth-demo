import argparse
import cmd
import json
import base64
import requests
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from Util import generate_short_password, generate_timestamp, decrypt_with_password

class AuthClient:
    """认证客户端"""
    
    def __init__(self, server_url: str = "http://localhost:8000") -> None:
        """初始化客户端"""
        self.server_url = server_url
        self.public_keys: Dict[str, str] = {}  # {key_id: public_key_pem}
        self.current_key_id: Optional[str] = None
        self.session = requests.Session()
        
    def fetch_public_keys(self) -> bool:
        """从服务器获取公钥"""
        try:
            response = self.session.post(
                f"{self.server_url}/api/request_public_key",
                json={"cmd": "request_public_key"}
            )
            if response.status_code == 200:
                data = response.json()
                self.public_keys[data["pubkey_id"]] = data["value"]
                self.current_key_id = data["pubkey_id"]
                return True
        except Exception as e:
            print(f"获取公钥失败: {e}")
        return False
        
    def encrypt_payload(self, account: str, cmd: str, content: List[str], 
                       shortpwd: Optional[str] = None) -> tuple[str, str]:
        """加密请求载荷"""
        if not self.current_key_id or self.current_key_id not in self.public_keys:
            raise ValueError("没有可用的公钥")
        
        if shortpwd is None:
            shortpwd = generate_short_password()
        
        payload = {
            "account": account,
            "cmd": cmd,
            "shortpwd": shortpwd,
            "content": content,
            "timestamp": generate_timestamp()
        }
        
        # RSA加密
        public_key_pem = self.public_keys[self.current_key_id].encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        payload_json = json.dumps(payload).encode('utf-8')
        encrypted_data = public_key.encrypt(
            payload_json,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted_data).decode('utf-8'), shortpwd
        
    def send_request(self, encrypted_payload: str) -> Dict[str, Any]:
        """发送加密请求到服务器"""
        request_data = {
            "encrypted": encrypted_payload,
            "pubkey_id": self.current_key_id
        }
        
        response = self.session.post(
            f"{self.server_url}/api/encrypted_request",
            json=request_data
        )
        return response.json()
        
    def decrypt_response(self, response: Dict[str, Any], shortpwd: str) -> Dict[str, Any]:
        """解密服务器响应"""
        if response["status"] != "success":
            return response
        
        try:
            decrypted_data = decrypt_with_password(response["value"], shortpwd)
            return json.loads(decrypted_data)
        except Exception as e:
            return {"status": "error", "data": f"解密失败: {e}"}
        
    # 业务方法
    def register(self, account: str, password: str, nickname: str = "") -> bool:
        """用户注册"""
        try:
            encrypted_payload, shortpwd = self.encrypt_payload(
                account, "reg", [password, nickname]
            )
            response = self.send_request(encrypted_payload)
            result = self.decrypt_response(response, shortpwd)
            return result.get("status") == "success"
        except Exception as e:
            print(f"注册失败: {e}")
            return False
        
    def get_content(self, account: str, password: str, content_key: str) -> Optional[str]:
        """获取内容"""
        try:
            encrypted_payload, shortpwd = self.encrypt_payload(
                account, "get", [password, content_key]
            )
            response = self.send_request(encrypted_payload)
            result = self.decrypt_response(response, shortpwd)
            if result.get("status") == "success":
                return result["data"]["content"]
        except Exception as e:
            print(f"获取内容失败: {e}")
        return None
        
    def set_content(self, account: str, account_password: str, 
                   content_key: str, content_data: str) -> bool:
        """设置内容"""
        try:
            encrypted_payload, shortpwd = self.encrypt_payload(
                account, "set", [account_password, content_key, content_data]
            )
            response = self.send_request(encrypted_payload)
            result = self.decrypt_response(response, shortpwd)
            return result.get("status") == "success"
        except Exception as e:
            print(f"设置内容失败: {e}")
            return False
        
    def delete_content(self, account: str, account_password: str, content_key: str) -> bool:
        """删除内容"""
        return self.set_content(account, account_password, content_key, "")

class AuthCLI(cmd.Cmd):
    """交互式命令行界面"""
    
    intro = "欢迎使用认证系统客户端。输入 help 查看可用命令。"
    prompt = "(auth) "
    
    def __init__(self, server_url: str = "http://localhost:8000") -> None:
        super().__init__()
        self.client = AuthClient(server_url)
        
    def do_connect(self, arg: str) -> None:
        """连接到服务器并获取公钥
        用法: connect [server_url]
        """
        if arg.strip():
            self.client.server_url = arg.strip()
        
        if self.client.fetch_public_keys():
            print(f"连接成功，获取到密钥: {self.client.current_key_id}")
        else:
            print("连接失败")
        
    def do_register(self, arg: str) -> None:
        """注册新用户
        用法: register <account> <password> [nickname]
        """
        parts = arg.split()
        if len(parts) < 2:
            print("用法: register <account> <password> [nickname]")
            return
        
        account = parts[0]
        password = parts[1]
        nickname = parts[2] if len(parts) > 2 else ""
        
        if self.client.register(account, password, nickname):
            print("注册成功")
        else:
            print("注册失败")
        
    def do_get(self, arg: str) -> None:
        """获取内容
        用法: get <account> <password> <content_key>
        """
        parts = arg.split()
        if len(parts) < 3:
            print("用法: get <account> <password> <content_key>")
            return
        
        account, password, content_key = parts[0], parts[1], parts[2]
        content = self.client.get_content(account, password, content_key)
        if content is not None:
            print(f"内容: {content}")
        else:
            print("获取失败")
        
    def do_set(self, arg: str) -> None:
        """设置内容
        用法: set <account> <account_password> <content_key> <content_data>
        """
        parts = arg.split(None, 3)
        if len(parts) < 4:
            print("用法: set <account> <account_password> <content_key> <content_data>")
            return
        
        account, account_password, content_key, content_data = parts
        if self.client.set_content(account, account_password, content_key, content_data):
            print("设置成功")
        else:
            print("设置失败")
        
    def do_delete(self, arg: str) -> None:
        """删除内容
        用法: delete <account> <account_password> <content_key>
        """
        parts = arg.split()
        if len(parts) < 3:
            print("用法: delete <account> <account_password> <content_key>")
            return
        
        account, account_password, content_key = parts
        if self.client.delete_content(account, account_password, content_key):
            print("删除成功")
        else:
            print("删除失败")
    
    def do_status(self, arg: str) -> None:
        """显示连接状态"""
        if self.client.current_key_id:
            print(f"已连接到: {self.client.server_url}")
            print(f"当前密钥: {self.client.current_key_id}")
        else:
            print("未连接")
        
    def do_quit(self, arg: str) -> bool:
        """退出程序"""
        print("再见!")
        return True
        
    def do_EOF(self, arg: str) -> bool:
        """处理Ctrl+D"""
        return self.do_quit(arg)

# 命令行入口
def main() -> None:
    """主函数"""
    parser = argparse.ArgumentParser(description="认证系统客户端")
    parser.add_argument("--server", default="http://localhost:8000", 
                       help="服务器URL")
    parser.add_argument("--repl", action="store_true", 
                       help="启动交互式REPL")
    
    # 非交互式命令
    parser.add_argument("--register", nargs='+', metavar="ARGS",
                       help="注册用户: --register <account> <password> [nickname]")
    parser.add_argument("--get", nargs=3, metavar=("ACCOUNT", "PASSWORD", "KEY"),
                       help="获取内容")
    parser.add_argument("--set", nargs=4, metavar=("ACCOUNT", "ACCOUNT_PWD", "KEY", "DATA"),
                       help="设置内容")
    parser.add_argument("--delete", nargs=3, metavar=("ACCOUNT", "ACCOUNT_PWD", "KEY"),
                       help="删除内容")
    
    args = parser.parse_args()
    
    if args.repl:
        # 启动交互式模式
        cli = AuthCLI(args.server)
        cli.client.fetch_public_keys()  # 自动连接
        cli.cmdloop()
    else:
        # 执行单个命令
        client = AuthClient(args.server)
        if not client.fetch_public_keys():
            print("无法连接到服务器")
            return
        
        if args.register:
            if len(args.register) < 2:
                print("用法: --register <account> <password> [nickname]")
                return
            account = args.register[0]
            password = args.register[1]
            nickname = args.register[2] if len(args.register) > 2 else ""
            success = client.register(account, password, nickname)
            print("注册成功" if success else "注册失败")
            
        elif args.get:
            account, password, content_key = args.get
            content = client.get_content(account, password, content_key)
            print(content if content else "获取失败")
            
        elif args.set:
            account, account_pwd, content_key, content_data = args.set
            success = client.set_content(account, account_pwd, content_key, content_data)
            print("设置成功" if success else "设置失败")
            
        elif args.delete:
            account, account_pwd, content_key = args.delete
            success = client.delete_content(account, account_pwd, content_key)
            print("删除成功" if success else "删除失败")
        else:
            print("请指定操作或使用 --repl 启动交互模式")

if __name__ == "__main__":
    main()
