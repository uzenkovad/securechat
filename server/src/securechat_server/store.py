"""Сховища даних у пам'ять (за умовою лабораторної база даних не обов'язкова)."""

from __future__ import annotations

import random
import threading

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


class SessionStore:
    """Секретні ключі AES, прив'язані до номера сесії."""

    def __init__(self) -> None:
        self._sessions: dict[str, AesKey] = {}
        self._lock = threading.Lock()

    def add(self, session_id: str, key: AesKey) -> bool:
        """Зберігає ключ сесії. Повертає False, якщо така сесія вже існує
        (її не можна перезаписати, інакше чужу сесію можна було б підмінити)."""
        with self._lock:
            if session_id in self._sessions:
                return False
            self._sessions[session_id] = key
            return True

    def get(self, session_id: str) -> AesKey | None:
        with self._lock:
            return self._sessions.get(session_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
