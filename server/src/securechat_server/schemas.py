from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class GenerateKeysResponse(BaseModel):
    id: int = Field(description="Ідентифікатор згенерованої пари ключів")


class HandshakeRequest(BaseModel):
    encrypted_data: str = Field(
        description="base64: RSA-зашифрований JSON {session_id, key, iv} (публічним ключем пари x-rsa-id)"
    )


class HandshakeResponse(BaseModel):
    status: str = Field(default="established", description="Підтвердження, що ключ сесії збережено")
    session_id: str


class EncryptedMessage(BaseModel):
    encrypted_message: str = Field(description="base64: AES-зашифрований JSON {data, hash}")


class ErrorResponse(BaseModel):
    detail: str


class SessionInfo(BaseModel):
    session_id: str = Field(description="Ідентифікатор сесії")
    status: Literal["valid", "invalid"] = Field(description="Стан: valid — дійсна, invalid — термін дії минув")
    expires_at: datetime = Field(description="Термін дії сесії (UTC)")
