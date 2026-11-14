"""Завдання 1: генерація пар RSA-ключів і видача публічного ключа за ідентифікатором."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from cryptolib import CryptoError

from ..schemas import ErrorResponse, GenerateKeysResponse

router = APIRouter(prefix="/api/crypto-keys", tags=["crypto-keys"])


@router.post(
    "/generate/rsa-keys",
    response_model=GenerateKeysResponse,
    responses={400: {"model": ErrorResponse, "description": "Не вдалося згенерувати ключі"}},
    summary="Згенерувати пару RSA-ключів",
)
def generate_rsa_keys(request: Request) -> GenerateKeysResponse:
    """Генерує пару ключів (private + public), зберігає її в пам'яті та повертає
    цілий ідентифікатор, за яким можна отримати публічний ключ."""
    try:
        keys = request.app.state.rsa_service.generate_crypto_keys()
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return GenerateKeysResponse(id=request.app.state.key_store.add(keys))


@router.get(
    "/rsa-public-key/{id}",
    response_class=PlainTextResponse,
    responses={404: {"model": ErrorResponse, "description": "Пари ключів із таким id немає"}},
    summary="Отримати публічний ключ за ідентифікатором",
)
def get_rsa_public_key(id: int, request: Request) -> PlainTextResponse:
    """Повертає публічний ключ як base64-рядок (DER, SubjectPublicKeyInfo)."""
    keys = request.app.state.key_store.get(id)
    if keys is None:
        raise HTTPException(status_code=404, detail=f"Пару RSA-ключів із id={id} не знайдено.")
    return PlainTextResponse(keys.public_key)
