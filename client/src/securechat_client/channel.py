"""Логіка клієнта безпечного каналу (без введення-виведення, тож її легко тестувати).

Кроки відповідають sequence-діаграмі з методички:
  a. отримати публічний ключ сервера (і номер пари x-rsa-id)
  b. створити секретний ключ AES та вектор ініціалізації
  c. створити номер сесії
  d. зашифрувати ключ + номер сесії публічним ключем RSA і відправити серверу
  e. сервер підтверджує, що дані збережено
  f. зашифрувати повідомлення користувача AES і відправити (заголовок x-session-id)
  g. розшифрувати відповідь сервера
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
    CryptoError,
    HandshakePayload,
    RsaService,
)


class SecureChannelError(Exception):
    """Сервер відповів помилкою або відповідь має неправильний вигляд."""


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
        reuse_session: bool = False,
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
        """Надіслати повідомлення і розшифрувати відповідь."""
        if self._session is None or not self._reuse_session:
            session = self.establish_session()
        else:
            session = self._session

        encrypted = self._aes.encrypt(session.aes_key, text)
        response = self._request(
            "POST",
            "/api/secure-channel/messages",
            json={"encrypted_message": encrypted},
            headers={SESSION_ID_HEADER: session.session_id},
        )
        self._on_step("Повідомлення надіслано зашифрованим, відповідь отримано")

        try:
            reply = self._aes.decrypt(session.aes_key, response.json()["encrypted_message"])
        except (CryptoError, KeyError, ValueError) as exc:
            raise SecureChannelError(f"Не вдалося розшифрувати відповідь сервера: {exc}") from exc
        return SendResult(reply=reply, session_id=session.session_id, rsa_id=session.rsa_id)

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
            raise SecureChannelError(f"Сервер відповів {response.status_code}: {detail}")
        return response
