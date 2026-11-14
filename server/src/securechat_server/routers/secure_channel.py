"""Завдання 3: протокол шифрованого каналу (див. sequence-діаграму в методичці).

1. GET  /api/secure-channel/public-key  — випадкова пара RSA; публічний ключ + заголовок x-rsa-id
2. POST /api/secure-channel/sessions    — клієнт надсилає RSA-зашифровані {session_id, key, iv}
3. POST /api/secure-channel/messages    — повідомлення, зашифроване AES; заголовок x-session-id

Лабораторна №7: у сесії є термін дії (після нього код 440), а повідомлення
передається разом із хешем SHA-256, який сервер перевіряє після розшифрування.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from cryptolib import RSA_ID_HEADER, CryptoError, HandshakePayload, HashedMessage, ProtocolError

from ..dependencies import get_valid_session
from ..schemas import EncryptedMessage, ErrorResponse, HandshakeRequest, HandshakeResponse
from ..store import Session

router = APIRouter(prefix="/api/secure-channel", tags=["secure-channel"])


@router.get(
    "/public-key",
    response_class=PlainTextResponse,
    responses={
        200: {
            "description": "Публічний ключ (base64). Номер пари — у заголовку x-rsa-id.",
            "headers": {RSA_ID_HEADER: {"description": "Номер пари RSA-ключів", "schema": {"type": "integer"}}},
        },
        503: {"model": ErrorResponse, "description": "На сервері немає жодної пари ключів"},
    },
    summary="Отримати випадковий публічний ключ сервера",
)
def get_public_key(request: Request) -> PlainTextResponse:
    picked = request.app.state.key_store.get_random()
    if picked is None:
        raise HTTPException(status_code=503, detail="На сервері немає жодної пари RSA-ключів.")
    key_id, keys = picked
    return PlainTextResponse(keys.public_key, headers={RSA_ID_HEADER: str(key_id)})


@router.post(
    "/sessions",
    response_model=HandshakeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Неправильні дані або не вдалося розшифрувати"},
        404: {"model": ErrorResponse, "description": "Пари ключів із таким x-rsa-id немає"},
        409: {"model": ErrorResponse, "description": "Сесія з таким номером уже існує"},
    },
    summary="Встановити сесію: передати серверу ключ AES, зашифрований RSA",
)
def create_session(
    body: HandshakeRequest,
    request: Request,
    x_rsa_id: Annotated[str | None, Header(description="Номер пари RSA-ключів, отриманий разом із публічним ключем")] = None,
) -> HandshakeResponse:
    if x_rsa_id is None:
        raise HTTPException(status_code=400, detail=f"Відсутній заголовок {RSA_ID_HEADER}.")
    try:
        rsa_id = int(x_rsa_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Заголовок {RSA_ID_HEADER} має бути цілим числом.") from None

    keys = request.app.state.key_store.get(rsa_id)
    if keys is None:
        raise HTTPException(status_code=404, detail=f"Пару RSA-ключів із id={rsa_id} не знайдено.")

    try:
        plain = request.app.state.rsa_service.decrypt(keys.private_key, body.encrypted_data)
        payload = HandshakePayload.from_json(plain)
        # Перевіряємо, що ключ AES придатний до роботи, ще до збереження сесії.
        request.app.state.aes_service.encrypt(payload.aes_key, "")
    except (CryptoError, ProtocolError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    now = request.app.state.clock()
    session = Session(
        session_id=payload.session_id,
        aes_key=payload.aes_key,
        created_at=now,
        expires_at=now + request.app.state.session_lifetime,
    )
    if not request.app.state.session_store.add(session):
        raise HTTPException(status_code=409, detail="Сесія з таким номером уже існує.")
    return HandshakeResponse(session_id=payload.session_id)


@router.post(
    "/messages",
    response_model=EncryptedMessage,
    responses={
        400: {"model": ErrorResponse, "description": "Не вдалося розшифрувати повідомлення або хеш не збігається"},
        404: {"model": ErrorResponse, "description": "Сесії з таким x-session-id немає"},
        440: {"model": ErrorResponse, "description": "Термін дії сесії закінчився: клієнт має створити нову сесію"},
    },
    summary="Надіслати зашифроване повідомлення й отримати зашифровану відповідь",
)
def send_message(
    body: EncryptedMessage,
    request: Request,
    session: Annotated[Session, Depends(get_valid_session)],
) -> EncryptedMessage:
    aes = request.app.state.aes_service
    try:
        message = HashedMessage.from_json(aes.decrypt(session.aes_key, body.encrypted_message))
    except (CryptoError, ProtocolError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not message.is_valid():
        raise HTTPException(status_code=400, detail="Хеш не збігається: дані було змінено під час передачі.")

    received_at = request.app.state.clock().strftime("%Y-%m-%d %H:%M:%S UTC")
    reply = HashedMessage.create(f"{message.data}. Received: {received_at}")
    try:
        return EncryptedMessage(encrypted_message=aes.encrypt(session.aes_key, reply.to_json()))
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
