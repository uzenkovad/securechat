"""Спільна перевірка сесії для всіх обробників, яким потрібна дійсна сесія.

Це аналог action filter з методички: код перевірки написаний один раз
і підключається до ендпоінта через Depends, а не дублюється в кожному обробнику.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Header, HTTPException, Request

from cryptolib import SESSION_EXPIRED_STATUS, SESSION_ID_HEADER

from .store import Session


def get_valid_session(
    request: Request,
    x_session_id: Annotated[str | None, Header(description="Номер сесії, до якої належить ключ AES")] = None,
) -> Session:
    if not x_session_id:
        raise HTTPException(status_code=400, detail=f"Відсутній заголовок {SESSION_ID_HEADER}.")

    store = request.app.state.session_store
    session = store.get(x_session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Сесію не знайдено. Спочатку встановіть канал.")

    if not session.is_valid(request.app.state.clock()):
        store.invalidate(x_session_id)
        raise HTTPException(
            status_code=SESSION_EXPIRED_STATUS,
            detail="Термін дії сесії закінчився. Створіть нову сесію.",
        )
    return session
