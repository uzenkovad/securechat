from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RsaKeys:
    """Пара RSA-ключів. Обидва ключі — base64-рядки.

    public_key  — DER, формат SubjectPublicKeyInfo
    private_key — DER, формат PKCS#8
    """

    public_key: str
    private_key: str


@dataclass(frozen=True)
class AesKey:
    """Секретний ключ AES і вектор ініціалізації (обидва — base64-рядки)."""

    key: str
    iv: str
