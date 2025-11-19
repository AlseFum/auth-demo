import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from Cli import AuthClient


class TestAuthClient(unittest.TestCase):
    def setUp(self):
        self.client = AuthClient("http://test-server:8000")
    
    @patch('requests.Session.post')
    def test_fetch_public_keys_success(self, mock_post):
        # 模拟成功的公钥请求响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pubkey_id": "test_key_123",
            "value": "-----BEGIN PUBLIC KEY-----\ntest_key_content\n-----END PUBLIC KEY-----"
        }
        mock_post.return_value = mock_response
        
        success = self.client.fetch_public_keys()
        
        self.assertTrue(success)
        self.assertEqual("test_key_123", self.client.current_key_id)
        self.assertIn("test_key_123", self.client.public_keys)
        
        # 验证请求参数
        mock_post.assert_called_once_with(
            "http://test-server:8000/api/request_public_key",
            json={"cmd": "request_public_key"}
        )
    
    @patch('requests.Session.post')
    def test_fetch_public_keys_failure(self, mock_post):
        # 模拟失败的请求
        mock_post.side_effect = Exception("Network error")
        
        success = self.client.fetch_public_keys()
        
        self.assertFalse(success)
        self.assertIsNone(self.client.current_key_id)
        self.assertEqual({}, self.client.public_keys)
    
    def test_encrypt_payload_no_key(self):
        # 测试没有公钥时的加密
        with self.assertRaises(ValueError):
            self.client.encrypt_payload("alice", "reg", ["password"])
    
    @patch('requests.Session.post')
    def test_send_request(self, mock_post):
        # 设置客户端状态
        self.client.current_key_id = "test_key"
        
        mock_response = Mock()
        mock_response.json.return_value = {"status": "success", "value": "encrypted_response"}
        mock_post.return_value = mock_response
        
        result = self.client.send_request("encrypted_payload")
        
        self.assertEqual({"status": "success", "value": "encrypted_response"}, result)
        mock_post.assert_called_once_with(
            "http://test-server:8000/api/encrypted_request",
            json={"encrypted": "encrypted_payload", "pubkey_id": "test_key"}
        )
    
    def test_decrypt_response_error_status(self):
        # 测试错误状态的响应
        response = {"status": "error", "value": "Error message"}
        result = self.client.decrypt_response(response, "shortpwd")
        
        self.assertEqual(response, result)
    
    @patch('Cli.decrypt_with_password')
    def test_decrypt_response_success(self, mock_decrypt):
        # 测试成功解密响应
        mock_decrypt.return_value = '{"status": "success", "data": "decrypted_data"}'
        
        response = {"status": "success", "value": "encrypted_response"}
        result = self.client.decrypt_response(response, "shortpwd")
        
        expected = {"status": "success", "data": "decrypted_data"}
        self.assertEqual(expected, result)
        mock_decrypt.assert_called_once_with("encrypted_response", "shortpwd")
    
    @patch('Cli.decrypt_with_password')
    def test_decrypt_response_decrypt_failure(self, mock_decrypt):
        # 测试解密失败
        mock_decrypt.side_effect = Exception("Decryption failed")
        
        response = {"status": "success", "value": "encrypted_response"}
        result = self.client.decrypt_response(response, "shortpwd")
        
        self.assertEqual("error", result["status"])
        self.assertIn("解密失败", result["data"])


class TestCLIIntegration(unittest.TestCase):
    """集成测试，测试CLI的完整流程"""
    
    @patch('requests.Session.post')
    def test_register_flow(self, mock_post):
        client = AuthClient("http://test-server:8000")
        
        # 模拟获取公钥
        def mock_post_side_effect(url, json=None):
            if "request_public_key" in url:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "pubkey_id": "test_key",
                    "value": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef...
-----END PUBLIC KEY-----"""
                }
                return mock_response
            elif "encrypted_request" in url:
                mock_response = Mock()
                mock_response.json.return_value = {
                    "status": "success", 
                    "value": "encrypted_success_response"
                }
                return mock_response
        
        mock_post.side_effect = mock_post_side_effect
        
        # 由于需要真实的RSA加密，这里只测试到获取公钥
        success = client.fetch_public_keys()
        self.assertTrue(success)
        self.assertEqual("test_key", client.current_key_id)


if __name__ == "__main__":
    unittest.main()
