from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 310_000


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    return hmac.compare_digest(password_hash(password, salt), expected_hash)


def derive_password_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)


def create_user_crypto(password: str, username: str) -> dict[str, bytes]:
    password_salt = os.urandom(16)
    key_salt = os.urandom(16)
    p_hash = password_hash(password, password_salt)
    wrapping_key = derive_password_key(password, key_salt)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_nonce = os.urandom(12)
    private_enc = AESGCM(wrapping_key).encrypt(private_nonce, private_pem, username.encode("utf-8"))

    return {
        "password_salt": password_salt,
        "password_hash": p_hash,
        "key_salt": key_salt,
        "public_key": public_pem,
        "private_key_nonce": private_nonce,
        "private_key_enc": private_enc,
    }


def unlock_private_key(user: dict[str, Any], password: str):
    key = derive_password_key(password, user["key_salt"])
    pem = AESGCM(key).decrypt(
        user["private_key_nonce"], user["private_key_enc"], user["username"].encode("utf-8")
    )
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def _rsa_wrap(public_pem: bytes, payload: bytes) -> bytes:
    public_key = load_public_key(public_pem)
    return public_key.encrypt(
        payload,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def _rsa_unwrap(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def vigenere_encrypt(text: str, key: str) -> str:
    """Vigenere on ASCII letters; spaces, numbers, punctuation and non-ASCII chars stay intact."""
    key = "".join(c for c in key.upper() if "A" <= c <= "Z")
    if not key:
        raise ValueError("Kunci Vigenere tidak boleh kosong.")
    out: list[str] = []
    ki = 0
    for ch in text:
        if "A" <= ch <= "Z":
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            ki += 1
        elif "a" <= ch <= "z":
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    key = "".join(c for c in key.upper() if "A" <= c <= "Z")
    if not key:
        raise ValueError("Kunci Vigenere tidak boleh kosong.")
    out: list[str] = []
    ki = 0
    for ch in text:
        if "A" <= ch <= "Z":
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
            ki += 1
        elif "a" <= ch <= "z":
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt_super_text(plain_text: str, sender_public: bytes, recipient_public: bytes) -> dict[str, bytes]:
    """Classic Vigenere layer followed by modern AES-GCM; AES key + Vigenere key are RSA-wrapped."""
    vig_key = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(32))
    aes_key = os.urandom(32)
    classical_cipher = vigenere_encrypt(plain_text, vig_key).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, classical_cipher, b"SecureHub:text:v1")
    key_package = json.dumps(
        {"aes": base64.b64encode(aes_key).decode(), "vig": vig_key}, separators=(",", ":")
    ).encode("utf-8")
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "wrapped_sender": _rsa_wrap(sender_public, key_package),
        "wrapped_recipient": _rsa_wrap(recipient_public, key_package),
    }


def decrypt_super_text(envelope: dict[str, bytes], private_key, role: str) -> str:
    wrapped_name = "wrapped_sender" if role == "sender" else "wrapped_recipient"
    package = json.loads(_rsa_unwrap(private_key, envelope[wrapped_name]).decode("utf-8"))
    aes_key = base64.b64decode(package["aes"])
    vig_key = package["vig"]
    classical_cipher = AESGCM(aes_key).decrypt(envelope["nonce"], envelope["ciphertext"], b"SecureHub:text:v1")
    return vigenere_decrypt(classical_cipher.decode("utf-8"), vig_key)


def encrypt_file(data: bytes, sender_public: bytes, recipient_public: bytes) -> dict[str, bytes]:
    """Files use AES-GCM directly, deliberately different from the text super-encryption pipeline."""
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, b"SecureHub:file:v1")
    package = json.dumps({"aes": base64.b64encode(aes_key).decode()}, separators=(",", ":")).encode()
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "wrapped_sender": _rsa_wrap(sender_public, package),
        "wrapped_recipient": _rsa_wrap(recipient_public, package),
    }


def decrypt_file(envelope: dict[str, bytes], private_key, role: str) -> bytes:
    wrapped_name = "wrapped_sender" if role == "sender" else "wrapped_recipient"
    package = json.loads(_rsa_unwrap(private_key, envelope[wrapped_name]).decode("utf-8"))
    aes_key = base64.b64decode(package["aes"])
    return AESGCM(aes_key).decrypt(envelope["nonce"], envelope["ciphertext"], b"SecureHub:file:v1")


def encrypt_note(text: str, owner_public: bytes) -> dict[str, bytes]:
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, text.encode("utf-8"), b"SecureHub:note:v1")
    package = json.dumps({"aes": base64.b64encode(aes_key).decode()}, separators=(",", ":")).encode()
    return {"nonce": nonce, "ciphertext": ciphertext, "wrapped_key": _rsa_wrap(owner_public, package)}


def decrypt_note(envelope: dict[str, bytes], private_key) -> str:
    package = json.loads(_rsa_unwrap(private_key, envelope["wrapped_key"]).decode("utf-8"))
    return AESGCM(base64.b64decode(package["aes"])).decrypt(
        envelope["nonce"], envelope["ciphertext"], b"SecureHub:note:v1"
    ).decode("utf-8")


def encrypt_biometric_model(model_bytes: bytes, password: str, key_salt: bytes, username: str) -> tuple[bytes, bytes]:
    key = derive_password_key(password, key_salt)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, model_bytes, (username + ":face-model").encode())
    return nonce, encrypted


def decrypt_biometric_model(nonce: bytes, encrypted: bytes, password: str, key_salt: bytes, username: str) -> bytes:
    key = derive_password_key(password, key_salt)
    return AESGCM(key).decrypt(nonce, encrypted, (username + ":face-model").encode())
