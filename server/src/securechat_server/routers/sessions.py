from __future__ import annotations

from fastapi import APIRouter, Request

from ..schemas import SessionInfo

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get(
    "",
    response_model=list[SessionInfo],
    summary="Усі сесії: дійсні й ті, термін дії яких минув",
)
def list_sessions(request: Request) -> list[SessionInfo]:
    now = request.app.state.clock()
    sessions = request.app.state.session_store.mark_expired(now)
    return [
        SessionInfo(
            session_id=s.session_id,
            status="invalid" if s.invalidated else "valid",
            expires_at=s.expires_at,
        )
        for s in sessions
    ]
