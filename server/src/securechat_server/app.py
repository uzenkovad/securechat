from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Callable

from fastapi import FastAPI

from cryptolib import AesService, RsaService

from .routers import crypto_keys, secure_channel
from .store import KeyStore, SessionStore

log = logging.getLogger("securechat")

# За умовою: на старті сервер генерує та зберігає в пам'яті 10 пар RSA-ключів.
DEFAULT_INITIAL_KEY_COUNT = 10


def create_app(
    initial_key_count: int = DEFAULT_INITIAL_KEY_COUNT,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Фабрика застосунку. Параметри потрібні тестам (менше ключів, фіксований час)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for _ in range(initial_key_count):
            app.state.key_store.add(app.state.rsa_service.generate_crypto_keys())
        log.info("Згенеровано %d пар RSA-ключів", len(app.state.key_store))
        yield

    app = FastAPI(
        title="SecureChat API",
        version="1.0.0",
        description=(
            "Лабораторна №6. Web API для RSA-ключів і шифрованого каналу між клієнтом і сервером "
            "(RSA захищає передачу ключа AES, далі повідомлення шифруються AES)."
        ),
        lifespan=lifespan,
    )
    app.state.rsa_service = RsaService()
    app.state.aes_service = AesService()
    app.state.key_store = KeyStore()
    app.state.session_store = SessionStore()
    app.state.clock = clock or (lambda: datetime.now(timezone.utc))

    app.include_router(crypto_keys.router)
    app.include_router(secure_channel.router)

    @app.get("/health", tags=["service"], summary="Перевірка працездатності")
    def health() -> dict:
        return {"status": "ok", "rsa_keys": len(app.state.key_store), "sessions": len(app.state.session_store)}

    return app


app = create_app()
