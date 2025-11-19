import os
import tempfile
import unittest
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from Database import Sheet, UserSheet, ContentSheet


class TestSheet(unittest.TestCase):
    def test_basic_sheet_operations(self):
        with tempfile.TemporaryDirectory() as td:
            # 创建一个基本的Sheet实现
            class TestSheet(Sheet):
                pass
            
            sheet = TestSheet("test", td)
            
            # 测试设置和获取
            sheet.set("key1", "value1")
            self.assertEqual("value1", sheet.get("key1"))
            
            # 测试不存在的键
            self.assertIsNone(sheet.get("nonexistent"))
            
            # 测试删除
            self.assertTrue(sheet.delete("key1"))
            self.assertIsNone(sheet.get("key1"))
            self.assertFalse(sheet.delete("key1"))  # 再次删除应该返回False
            
            # 测试序列化
            test_data = {"a": 1, "b": [1, 2, 3]}
            sheet.from_dict(test_data)
            self.assertEqual(test_data, sheet.to_dict())

    def test_user_sheet(self):
        with tempfile.TemporaryDirectory() as td:
            user_sheet = UserSheet(td)
            
            # 测试存储用户凭据
            username = "alice"
            salt = b"test_salt_16byte"
            hashed_password = b"hashed_password_32_bytes_here_ok"
            key_id = "default"
            
            success = user_sheet.store_user_credential(username, salt, hashed_password, key_id)
            self.assertTrue(success)
            
            # 测试获取凭据
            credentials = user_sheet.get_credentials(username, key_id)
            self.assertEqual(1, len(credentials))
            retrieved_salt, retrieved_hash = credentials[0]
            self.assertEqual(salt, retrieved_salt)
            self.assertEqual(hashed_password, retrieved_hash)
            
            # 测试角色管理
            roles = ["user", "admin"]
            user_sheet.set_user_roles(username, roles)
            retrieved_roles = user_sheet.get_user_roles(username)
            self.assertEqual(roles, retrieved_roles)

    def test_content_sheet(self):
        with tempfile.TemporaryDirectory() as td:
            content_sheet = ContentSheet(td)
            
            # 测试内容存储
            account = "alice"
            content_key = "secret_note"
            encrypted_content = "base64_encrypted_content"
            encrypted_symmetric_key = "base64_encrypted_key"
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
            self.assertEqual(encrypted_symmetric_key, retrieved["encrypted_symmetric_key"])
            self.assertEqual(key_id, retrieved["key_id"])
            
            # 测试列出用户内容
            content_keys = content_sheet.list_user_contents(account)
            self.assertIn(content_key, content_keys)
            
            # 测试按密钥ID查询内容
            contents_by_key = content_sheet.get_contents_by_key_id(key_id)
            self.assertIn((account, content_key), contents_by_key)
            
            # 测试内容删除
            deleted = content_sheet.delete_content(account, content_key)
            self.assertTrue(deleted)
            
            # 验证删除后无法获取
            retrieved_after_delete = content_sheet.get_content(account, content_key)
            self.assertIsNone(retrieved_after_delete)

    def test_content_key_migration(self):
        with tempfile.TemporaryDirectory() as td:
            content_sheet = ContentSheet(td)
            
            # 存储一些使用旧密钥的内容
            old_key_id = "old_key"
            new_key_id = "new_key"
            
            content_sheet.store_content("alice", "note1", "content1", "old_encrypted_key1", old_key_id)
            content_sheet.store_content("bob", "note2", "content2", "old_encrypted_key2", old_key_id)
            content_sheet.store_content("alice", "note3", "content3", "other_key", "other_key_id")
            
            # 准备密钥映射
            key_mapping = {
                "old_encrypted_key1": "new_encrypted_key1",
                "old_encrypted_key2": "new_encrypted_key2"
            }
            
            # 执行迁移
            migrated_count = content_sheet.migrate_content_key(old_key_id, new_key_id, key_mapping)
            self.assertEqual(2, migrated_count)
            
            # 验证迁移结果
            alice_note1 = content_sheet.get_content("alice", "note1")
            self.assertEqual(new_key_id, alice_note1["key_id"])
            self.assertEqual("new_encrypted_key1", alice_note1["encrypted_symmetric_key"])
            
            bob_note2 = content_sheet.get_content("bob", "note2")
            self.assertEqual(new_key_id, bob_note2["key_id"])
            self.assertEqual("new_encrypted_key2", bob_note2["encrypted_symmetric_key"])
            
            # 验证其他内容未受影响
            alice_note3 = content_sheet.get_content("alice", "note3")
            self.assertEqual("other_key_id", alice_note3["key_id"])


if __name__ == "__main__":
    unittest.main()
