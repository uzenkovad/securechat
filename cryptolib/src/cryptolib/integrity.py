"""Перевірка цілісності: повідомлення передається разом зі своїм хешем SHA-256."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from .errors import ProtocolError


def compute_hash(text: str) -> str:
    """SHA-256 від тексту (UTF-8) у вигляді hex-рядка."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HashedMessage:
    """Модель {"data": ..., "hash": ...}. Її JSON шифрується AES і надсилається."""

    data: str
    hash: str

    @classmethod
    def create(cls, data: str) -> "HashedMessage":
        return cls(data=data, hash=compute_hash(data))

    def is_valid(self) -> bool:
        # compare_digest порівнює за сталий час, щоб не підказувати, скільки символів збіглося
        return hmac.compare_digest(self.hash.lower(), compute_hash(self.data))

    def to_json(self) -> str:
        return json.dumps({"data": self.data, "hash": self.hash}, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "HashedMessage":
        try:
            parsed = json.loads(text)
            data = parsed["data"]
            hash_ = parsed["hash"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ProtocolError("Повідомлення має неправильну структуру: потрібні поля data та hash.") from exc
        if not isinstance(data, str) or not isinstance(hash_, str):
            raise ProtocolError("Поля data та hash мають бути рядками.")
        return cls(data=data, hash=hash_)
