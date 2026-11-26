import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from securehub import blockchain, db
from securehub.crypto_utils import create_user_crypto, decrypt_file, decrypt_super_text, encrypt_file, encrypt_super_text
from securehub.steganography import embed_payload, extract_payload
from PIL import Image
import io


class SecureHubCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "test.db"
        db.init_db()
        self.alice = create_user_crypto("password-alice-123", "alice")
        self.bob = create_user_crypto("password-bob-12345", "bob")
        db.insert_user({"username": "alice", **self.alice, "role": "admin", "created_at": "2026-01-01T00:00:00+07:00"})
        db.insert_user({"username": "bob", **self.bob, "role": "user", "created_at": "2026-01-01T00:00:00+07:00"})
        # Private keys are intentionally encrypted at rest; tests create temporary in-memory pairs.
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.bob_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.alice_pub = self.alice_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.bob_pub = self.bob_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_super_encryption_roundtrip(self):
        text = "Pesan rahasia SecureHub 123!"
        env = encrypt_super_text(text, self.alice_pub, self.bob_pub)
        self.assertNotEqual(env["ciphertext"], text.encode())
        self.assertEqual(decrypt_super_text(env, self.bob_key, "recipient"), text)
        self.assertEqual(decrypt_super_text(env, self.alice_key, "sender"), text)

    def test_file_roundtrip(self):
        raw = b"\x00\x01file rahasia\xff" * 30
        env = encrypt_file(raw, self.alice_pub, self.bob_pub)
        self.assertEqual(decrypt_file(env, self.bob_key, "recipient"), raw)

    def test_steganography_roundtrip(self):
        image = Image.new("RGB", (500, 500), (80, 140, 200))
        stream = io.BytesIO()
        image.save(stream, format="PNG")
        secret = b"pesan tersembunyi"
        changed = embed_payload(stream.getvalue(), secret)
        self.assertEqual(extract_payload(changed), secret)

    def test_blockchain_roundtrip(self):
        blockchain.add_ledger_record({"action": "CREATE_ASSET", "asset_id": "abc", "owner": "alice"}, "2026-01-01T00:00:00+07:00")
        valid, _ = blockchain.verify_chain()
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
