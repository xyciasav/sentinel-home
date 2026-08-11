import base64
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

from sentinel.config import get_settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_PASSWORD_HASH = password_hasher.hash("sentinel-timing-defense-not-a-real-password")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerificationError):
        return False


def create_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _data_cipher() -> Fernet:
    configured = get_settings().data_encryption_key
    if configured is None:
        raise RuntimeError("DATA_ENCRYPTION_KEY is required for integration credentials")
    derived = hashlib.sha256(configured.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(value: str) -> str:
    return _data_cipher().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return _data_cipher().decrypt(value.encode()).decode()
