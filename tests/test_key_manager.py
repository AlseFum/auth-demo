import os
import tempfile
import unittest

from cryption import KeyManager


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


if __name__ == "__main__":
	unittest.main()


