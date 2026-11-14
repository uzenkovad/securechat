from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import FastAPI

from cryptolib import AesService, RsaService

from .routers import crypto_keys, secure_channel, sessions
from .store import KeyStore, SessionStore

log = logging.getLogger("securechat")

# За умовою: на старті сервер генерує та зберігає в пам'яті 10 пар RSA-ключів.
DEFAULT_INITIAL_KEY_COUNT = 10
# Скільки хвилин сесія дійсна (можна змінити змінною оточення SESSION_LIFETIME_MINUTES).
DEFAULT_SESSION_LIFETIME_MINUTES = 1.0


def session_lifetime_from_env() -> timedelta:
    raw = os.environ.get("SESSION_LIFETIME_MINUTES")
    if raw is None:
        return timedelta(minutes=DEFAULT_SESSION_LIFETIME_MINUTES)
    try:
        minutes = float(raw)
    except ValueError:
        raise RuntimeError(f"SESSION_LIFETIME_MINUTES має бути числом, а не {raw!r}") from None
    if minutes <= 0:
        raise RuntimeError("SESSION_LIFETIME_MINUTES має бути більшим за нуль")
    return timedelta(minutes=minutes)


def create_app(
    initial_key_count: int = DEFAULT_INITIAL_KEY_COUNT,
    session_lifetime: timedelta | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Фабрика застосунку. Параметри потрібні тестам (менше ключів, короткий термін сесії, підмінений годинник)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for _ in range(initial_key_count):
            app.state.key_store.add(app.state.rsa_service.generate_crypto_keys())
        log.info("Згенеровано %d пар RSA-ключів", len(app.state.key_store))
        yield

    app = FastAPI(
        title="SecureChat API",
        version="1.1.0",
        description=(
            "Лабораторні №6–7. Web API для RSA-ключів і шифрованого каналу між клієнтом і сервером "
            "(RSA захищає передачу ключа AES, далі повідомлення шифруються AES), термін дії сесій "
            "і перевірка цілісності повідомлень за хешем SHA-256. Увесь час на сервері — UTC."
        ),
        lifespan=lifespan,
    )
    app.state.rsa_service = RsaService()
    app.state.aes_service = AesService()
    app.state.key_store = KeyStore()
    app.state.session_store = SessionStore()
    app.state.session_lifetime = session_lifetime or session_lifetime_from_env()
    app.state.clock = clock or (lambda: datetime.now(timezone.utc))

    app.include_router(crypto_keys.router)
    app.include_router(secure_channel.router)
    app.include_router(sessions.router)

    @app.get("/health", tags=["service"], summary="Перевірка працездатності")
    def health() -> dict:
        return {"status": "ok", "rsa_keys": len(app.state.key_store), "sessions": len(app.state.session_store)}

    return app


app = create_app()
