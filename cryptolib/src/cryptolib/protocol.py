"""Спільний опис протоколу безпечного каналу.

Клієнт і сервер імпортують звідси назви заголовків та структуру даних
рукостискання, щоб ці константи не дублювалися в обох проєктах.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .errors import ProtocolError
from .models import AesKey

# Заголовок: номер пари RSA-ключів, до якої належить публічний ключ.
RSA_ID_HEADER = "x-rsa-id"
# Заголовок: номер сесії, до якої належить секретний ключ AES.
SESSION_ID_HEADER = "x-session-id"
# Код відповіді, коли термін дії сесії закінчився (клієнт у цьому разі створює нову сесію).
SESSION_EXPIRED_STATUS = 440


@dataclass(frozen=True)
class HandshakePayload:
    """Те, що клієнт шифрує публічним ключем RSA і відправляє серверу:
    номер сесії та симетричний ключ (ключ + вектор ініціалізації)."""

    session_id: str
    aes_key: AesKey

    def to_json(self) -> str:
        return json.dumps(
            {"session_id": self.session_id, "key": self.aes_key.key, "iv": self.aes_key.iv},
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, text: str) -> "HandshakePayload":
        try:
            data = json.loads(text)
            session_id = data["session_id"]
            key = data["key"]
            iv = data["iv"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ProtocolError("Дані рукостискання мають неправильну структуру.") from exc
        if not all(isinstance(v, str) and v for v in (session_id, key, iv)):
            raise ProtocolError("Поля session_id, key та iv мають бути непорожніми рядками.")
        return cls(session_id=session_id, aes_key=AesKey(key=key, iv=iv))
