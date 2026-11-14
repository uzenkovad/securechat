from __future__ import annotations

import base64
import binascii
import os
from typing import Protocol

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import CryptoError
from .models import AesKey

_VALID_KEY_SIZES = (16, 24, 32)
_IV_SIZE = 16


class IAesService(Protocol):
    def generate_secret_key(self) -> AesKey: ...

    def encrypt(self, aes_key: AesKey, plain_text: str) -> str: ...

    def decrypt(self, aes_key: AesKey, cipher_text: str) -> str: ...


class AesService:
    """Симетричне шифрування AES-256 у режимі CBC з доповненням PKCS#7.

    Ключ і вектор ініціалізації (IV) зберігаються в AesKey як base64.
    Шифротекст повертається як base64.
    """

    def __init__(self, key_size_bytes: int = 32) -> None:
        if key_size_bytes not in _VALID_KEY_SIZES:
            raise ValueError("Розмір ключа AES має бути 16, 24 або 32 байти.")
        self._key_size = key_size_bytes

    def generate_secret_key(self) -> AesKey:
        return AesKey(
            key=base64.b64encode(os.urandom(self._key_size)).decode("ascii"),
            iv=base64.b64encode(os.urandom(_IV_SIZE)).decode("ascii"),
        )

    @staticmethod
    def _decode(aes_key: AesKey) -> tuple[bytes, bytes]:
        try:
            key = base64.b64decode(aes_key.key, validate=True)
            iv = base64.b64decode(aes_key.iv, validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise CryptoError("Ключ або вектор ініціалізації AES не є коректним base64.") from exc
        if len(key) not in _VALID_KEY_SIZES:
            raise CryptoError("Неправильна довжина ключа AES (потрібно 16, 24 або 32 байти).")
        if len(iv) != _IV_SIZE:
            raise CryptoError("Неправильна довжина вектора ініціалізації (потрібно 16 байтів).")
        return key, iv

    def encrypt(self, aes_key: AesKey, plain_text: str) -> str:
        key, iv = self._decode(aes_key)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plain_text.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        cipher = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(cipher).decode("ascii")

    def decrypt(self, aes_key: AesKey, cipher_text: str) -> str:
        key, iv = self._decode(aes_key)
        try:
            raw = base64.b64decode(cipher_text, validate=True)
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(raw) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plain = unpadder.update(padded) + unpadder.finalize()
            return plain.decode("utf-8")
        except (binascii.Error, ValueError, TypeError) as exc:
            raise CryptoError("Не вдалося розшифрувати дані AES (неправильний ключ або дані).") from exc
