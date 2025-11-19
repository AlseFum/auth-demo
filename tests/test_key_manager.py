import os
import tempfile
import unittest
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from Key import KeyManager


class TestKeyManager(unittest.TestCase):
    def test_key_manager_generates_default_when_empty(self):
        with tempfile.TemporaryDirectory() as td:
            manager = KeyManager(td)
            keys = manager.get_public_keys()
            self.assertEqual(1, len(keys))
            self.assertEqual("default", keys[0]["id"])
            self.assertTrue(os.path.exists(os.path.join(td, "default.key.pem")))

    def test_key_manager_generate_new_key(self):
        with tempfile.TemporaryDirectory() as td:
            manager = KeyManager(td)
            pub = manager.generate_key("k1")
            self.assertIn("BEGIN PUBLIC KEY", pub)
            ids = {k["id"] for k in manager.get_public_keys()}
            self.assertIn("default", ids)
            self.assertIn("k1", ids)
            self.assertTrue(os.path.exists(os.path.join(td, "k1.key.pem")))
    
    def test_key_usage_tracking(self):
        with tempfile.TemporaryDirectory() as td:
            manager = KeyManager(td)
            manager.record_key_usage("default")
            manager.record_key_usage("default")
            keys = manager.get_public_keys()
            default_key = next(k for k in keys if k["id"] == "default")
            self.assertEqual(2, default_key["usage_count"])
    
    def test_encrypt_decrypt(self):
        with tempfile.TemporaryDirectory() as td:
            manager = KeyManager(td)
            test_data = b"Hello, World!"
            encrypted = manager.encrypt_with_public_key("default", test_data)
            decrypted = manager.decrypt("default", encrypted)
            self.assertEqual(test_data, decrypted)


if __name__ == "__main__":
    unittest.main()


