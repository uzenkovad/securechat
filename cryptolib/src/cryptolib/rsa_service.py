from __future__ import annotations

import base64
import binascii
from typing import Protocol

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import CryptoError
from .models import RsaKeys


class IRsaService(Protocol):
    def generate_crypto_keys(self) -> RsaKeys: ...

    def encrypt(self, public_key: str, plain_text: str) -> str: ...

    def decrypt(self, private_key: str, cipher_text: str) -> str: ...


class RsaService:
    """Асиметричне шифрування RSA-OAEP (SHA-256).

    Ключі та шифротекст передаються як base64-рядки. Сам алгоритм не
    реалізовано вручну — використовується бібліотека `cryptography`.
    """

    def __init__(self, key_size: int = 2048) -> None:
        self._key_size = key_size

    @staticmethod
    def _oaep() -> padding.OAEP:
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def generate_crypto_keys(self) -> RsaKeys:
        try:
            private = rsa.generate_private_key(public_exponent=65537, key_size=self._key_size)
        except ValueError as exc:
            raise CryptoError(f"Не вдалося згенерувати RSA-ключі: {exc}") from exc

        private_der = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_der = private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return RsaKeys(
            public_key=base64.b64encode(public_der).decode("ascii"),
            private_key=base64.b64encode(private_der).decode("ascii"),
        )

    def encrypt(self, public_key: str, plain_text: str) -> str:
        """Шифрує рядок публічним ключем. Повертає base64.

        Обмеження RSA-OAEP: для ключа 2048 біт і SHA-256 можна зашифрувати
        не більше 190 байтів. Довші дані шифруються AES, а RSA захищає лише
        ключ AES — саме так працює протокол цієї лабораторної.
        """
        try:
            key = serialization.load_der_public_key(base64.b64decode(public_key, validate=True))
            if not isinstance(key, rsa.RSAPublicKey):
                raise CryptoError("Переданий ключ не є публічним ключем RSA.")
            cipher = key.encrypt(plain_text.encode("utf-8"), self._oaep())
        except CryptoError:
            raise
        except (ValueError, binascii.Error, UnsupportedAlgorithm, TypeError) as exc:
            raise CryptoError(f"Не вдалося зашифрувати дані RSA: {exc}") from exc
        return base64.b64encode(cipher).decode("ascii")

    def decrypt(self, private_key: str, cipher_text: str) -> str:
        """Розшифровує base64-шифротекст приватним ключем."""
        try:
            key = serialization.load_der_private_key(
                base64.b64decode(private_key, validate=True), password=None
            )
            if not isinstance(key, rsa.RSAPrivateKey):
                raise CryptoError("Переданий ключ не є приватним ключем RSA.")
            plain = key.decrypt(base64.b64decode(cipher_text, validate=True), self._oaep())
            return plain.decode("utf-8")
        except CryptoError:
            raise
        except (ValueError, binascii.Error, UnsupportedAlgorithm, TypeError) as exc:
            raise CryptoError("Не вдалося розшифрувати дані RSA (неправильний ключ або дані).") from exc
