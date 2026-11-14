"""Логіка клієнта безпечного каналу (без введення-виведення, тож її легко тестувати).

Кроки відповідають sequence-діаграмі з методички:
  a. отримати публічний ключ сервера (і номер пари x-rsa-id)
  b. створити секретний ключ AES та вектор ініціалізації
  c. створити номер сесії
  d. зашифрувати ключ + номер сесії публічним ключем RSA і відправити серверу
  e. сервер підтверджує, що дані збережено
  f. зашифрувати повідомлення користувача AES і відправити (заголовок x-session-id)
  g. розшифрувати відповідь сервера

Лабораторна №7:
  * разом із повідомленням надсилається його хеш SHA-256, хеш відповіді клієнт також перевіряє;
  * якщо сервер відповів 440 (термін дії сесії закінчився), клієнт створює нову сесію
    й надсилає те саме повідомлення вже в ній.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable

import httpx

from cryptolib import (
    RSA_ID_HEADER,
    SESSION_ID_HEADER,
    AesKey,
    AesService,
    SESSION_EXPIRED_STATUS,
    CryptoError,
    HandshakePayload,
    HashedMessage,
    ProtocolError,
    RsaService,
)


class SecureChannelError(Exception):
    """Сервер відповів помилкою або відповідь має неправильний вигляд."""


class SessionExpiredError(SecureChannelError):
    """Сервер відповів 440: термін дії сесії закінчився."""


@dataclass(frozen=True)
class Session:
    session_id: str
    aes_key: AesKey
    rsa_id: int


@dataclass(frozen=True)
class SendResult:
    reply: str
    session_id: str
    rsa_id: int


class SecureChannelClient:
    def __init__(
        self,
        http: httpx.Client,
        rsa_service: RsaService | None = None,
        aes_service: AesService | None = None,
        reuse_session: bool = True,
        on_step: Callable[[str], None] | None = None,
    ) -> None:
        self._http = http
        self._rsa = rsa_service or RsaService()
        self._aes = aes_service or AesService()
        self._reuse_session = reuse_session
        self._on_step = on_step or (lambda _msg: None)
        self._session: Session | None = None

    def fetch_public_key(self) -> tuple[int, str]:
        """Публічний ключ сервера та номер пари (заголовок x-rsa-id)."""
        response = self._request("GET", "/api/secure-channel/public-key")
        try:
            rsa_id = int(response.headers[RSA_ID_HEADER])
        except (KeyError, ValueError) as exc:
            raise SecureChannelError(f"Сервер не повернув коректний заголовок {RSA_ID_HEADER}.") from exc
        self._on_step(f"Отримано публічний ключ сервера (x-rsa-id = {rsa_id})")
        return rsa_id, response.text

    def establish_session(self) -> Session:
        """Створення каналу симетричного шифрування."""
        rsa_id, public_key = self.fetch_public_key()

        aes_key = self._aes.generate_secret_key()
        session_id = str(uuid.uuid4())
        self._on_step(f"Створено ключ AES, вектор ініціалізації та номер сесії {session_id}")

        payload = HandshakePayload(session_id=session_id, aes_key=aes_key)
        try:
            encrypted = self._rsa.encrypt(public_key, payload.to_json())
        except CryptoError as exc:
            raise SecureChannelError(f"Не вдалося зашифрувати дані для сервера: {exc}") from exc

        self._request(
            "POST",
            "/api/secure-channel/sessions",
            json={"encrypted_data": encrypted},
            headers={RSA_ID_HEADER: str(rsa_id)},
        )
        self._on_step("Сервер підтвердив збереження ключа сесії")

        self._session = Session(session_id=session_id, aes_key=aes_key, rsa_id=rsa_id)
        return self._session

    def send_message(self, text: str) -> SendResult:
        """Надіслати повідомлення і розшифрувати відповідь.

        Якщо сесія протермінована (440) — створює нову й надсилає повідомлення в ній.
        """
        session = self._session if (self._reuse_session and self._session) else self.establish_session()
        try:
            return self._send(session, text)
        except SessionExpiredError:
            self._on_step("Сервер відповів 440: термін дії сесії закінчився, створюю нову сесію")
            return self._send(self.establish_session(), text)

    def _send(self, session: Session, text: str) -> SendResult:
        message = HashedMessage.create(text)
        self._on_step(f"Хеш повідомлення (SHA-256): {message.hash[:16]}…")
        response = self._request(
            "POST",
            "/api/secure-channel/messages",
            json={"encrypted_message": self._aes.encrypt(session.aes_key, message.to_json())},
            headers={SESSION_ID_HEADER: session.session_id},
        )
        self._on_step("Повідомлення надіслано зашифрованим, відповідь отримано")

        try:
            reply = HashedMessage.from_json(self._aes.decrypt(session.aes_key, response.json()["encrypted_message"]))
        except (CryptoError, ProtocolError, KeyError, ValueError) as exc:
            raise SecureChannelError(f"Не вдалося розшифрувати відповідь сервера: {exc}") from exc
        if not reply.is_valid():
            raise SecureChannelError("Хеш відповіді сервера не збігається: дані було змінено під час передачі.")
        self._on_step("Хеш відповіді збігається, дані цілісні")
        return SendResult(reply=reply.data, session_id=session.session_id, rsa_id=session.rsa_id)

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            response = self._http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise SecureChannelError(f"Не вдалося звернутися до сервера: {exc}") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            error = SessionExpiredError if response.status_code == SESSION_EXPIRED_STATUS else SecureChannelError
            raise error(f"Сервер відповів {response.status_code}: {detail}")
        return response
