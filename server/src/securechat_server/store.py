"""Сховища даних у пам'ять (за умовою лабораторної база даних не обов'язкова)."""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass
from datetime import datetime

from cryptolib import AesKey, RsaKeys


class KeyStore:
    """Пари RSA-ключів. Ідентифікатор — ціле число, що зростає з 1."""

    def __init__(self) -> None:
        self._keys: dict[int, RsaKeys] = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def add(self, keys: RsaKeys) -> int:
        with self._lock:
            key_id = self._next_id
            self._next_id += 1
            self._keys[key_id] = keys
            return key_id

    def get(self, key_id: int) -> RsaKeys | None:
        with self._lock:
            return self._keys.get(key_id)

    def get_random(self) -> tuple[int, RsaKeys] | None:
        """Повертає випадкову пару (ідентифікатор, ключі) або None, якщо сховище порожнє."""
        with self._lock:
            if not self._keys:
                return None
            key_id = random.choice(list(self._keys))
            return key_id, self._keys[key_id]

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)


@dataclass
class Session:
    """Клієнтська сесія: секретний ключ AES і час, після якого сесія не дійсна."""

    session_id: str
    aes_key: AesKey
    created_at: datetime
    expires_at: datetime
    invalidated: bool = False

    def is_valid(self, now: datetime) -> bool:
        return not self.invalidated and now <= self.expires_at


class SessionStore:
    """Сесії за їх номером. Недійсні сесії не видаляються: про них повертає GET /api/sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def add(self, session: Session) -> bool:
        """Зберігає сесію. Повертає False, якщо така сесія вже існує
        (її не можна перезаписати, інакше чужу сесію можна було б підмінити)."""
        with self._lock:
            if session.session_id in self._sessions:
                return False
            self._sessions[session.session_id] = session
            return True

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def mark_expired(self, now: datetime) -> list[Session]:
        """Позначає як недійсні всі сесії, термін дії яких минув, і повертає всі сесії."""
        with self._lock:
            for session in self._sessions.values():
                if not session.is_valid(now):
                    session.invalidated = True
            return list(self._sessions.values())

    def invalidate(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].invalidated = True

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
