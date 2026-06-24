import os
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.collector.security import encrypt_value, decrypt_value, mask_secret, mask_text


class MaskSecretTests(SimpleTestCase):
    def test_mask_non_empty(self):
        result = mask_secret("abc123")
        self.assertNotEqual(result, "abc123")
        self.assertIn("****", result)

    def test_mask_short_value(self):
        result = mask_secret("ab")
        self.assertEqual(result, "****")

    def test_mask_empty(self):
        self.assertEqual(mask_secret(""), "")

    def test_mask_none(self):
        self.assertEqual(mask_secret(None), "")

    def test_mask_does_not_expose_full_value(self):
        result = mask_secret("supersecretpassword")
        self.assertNotIn("supersecret", result)


class MaskTextTests(SimpleTestCase):
    def test_mask_text_removes_secret(self):
        result = mask_text("Login with admin:secret123", ["secret123"])
        self.assertNotIn("secret123", result)

    def test_mask_text_multiple_secrets(self):
        result = mask_text("user: pass1, admin: pass2", ["pass1", "pass2"])
        self.assertNotIn("pass1", result)
        self.assertNotIn("pass2", result)

    def test_mask_text_empty_text(self):
        self.assertEqual(mask_text("", ["secret"]), "")

    def test_mask_text_no_secrets(self):
        self.assertEqual(mask_text("hello world", []), "hello world")


class EncryptDecryptTests(SimpleTestCase):
    @patch.dict(os.environ, {"COLLECTOR_SECRET_KEY": "cHVibGljX3Rlc3Rfa2V5XzAxMjM0NTY3ODkwMTIzNAo="})
    def test_encrypt_decrypt_roundtrip(self):
        original = "mysupersecretpassword"
        encrypted = encrypt_value(original)
        self.assertNotEqual(encrypted, original)
        decrypted = decrypt_value(encrypted)
        self.assertEqual(decrypted, original)

    @patch.dict(os.environ, {"COLLECTOR_SECRET_KEY": ""}, clear=True)
    def test_without_key_returns_plaintext(self):
        original = "test"
        encrypted = encrypt_value(original)
        self.assertEqual(encrypted, original)

    def test_encrypt_empty(self):
        self.assertEqual(encrypt_value(""), "")

    def test_decrypt_empty(self):
        self.assertEqual(decrypt_value(""), "")
