import base64
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from cryptolib import AesService, HandshakePayload, RsaService
from securechat_server import create_app

FIXED_TIME = datetime(2026, 11, 13, 12, 30, 5, tzinfo=timezone.utc)

rsa = RsaService()
aes = AesService()


@pytest.fixture()
def client():
    app = create_app(initial_key_count=3, clock=lambda: FIXED_TIME)
    with TestClient(app) as c:  # with — щоб виконався lifespan (генерація ключів на старті)
        yield c


def open_session(client, session_id="s-1"):
    """Виконує рукостискання як клієнт; повертає (session_id, aes_key)."""
    r = client.get("/api/secure-channel/public-key")
    rsa_id, public_key = r.headers["x-rsa-id"], r.text
    aes_key = aes.generate_secret_key()
    encrypted = rsa.encrypt(public_key, HandshakePayload(session_id, aes_key).to_json())
    resp = client.post("/api/secure-channel/sessions", json={"encrypted_data": encrypted}, headers={"x-rsa-id": rsa_id})
    assert resp.status_code == 200, resp.text
    return session_id, aes_key




def test_server_generates_initial_keys_on_startup(client):
    assert client.get("/health").json()["rsa_keys"] == 3


def test_default_app_generates_ten_keys():
    with TestClient(create_app()) as c:
        assert c.get("/health").json()["rsa_keys"] == 10


def test_generate_returns_integer_id_and_key_is_retrievable(client):
    r = client.post("/api/crypto-keys/generate/rsa-keys")
    assert r.status_code == 200
    key_id = r.json()["id"]
    assert isinstance(key_id, int)

    pub = client.get(f"/api/crypto-keys/rsa-public-key/{key_id}")
    assert pub.status_code == 200
    assert base64.b64decode(pub.text, validate=True)


def test_each_generation_gets_new_id_and_new_key(client):
    first = client.post("/api/crypto-keys/generate/rsa-keys").json()["id"]
    second = client.post("/api/crypto-keys/generate/rsa-keys").json()["id"]
    assert first != second
    assert client.get(f"/api/crypto-keys/rsa-public-key/{first}").text != client.get(
        f"/api/crypto-keys/rsa-public-key/{second}"
    ).text


def test_public_key_unknown_id_returns_404(client):
    r = client.get("/api/crypto-keys/rsa-public-key/9999")
    assert r.status_code == 404
    assert "9999" in r.json()["detail"]


def test_public_key_non_integer_id_is_rejected(client):
    assert client.get("/api/crypto-keys/rsa-public-key/abc").status_code == 422


def test_generate_failure_returns_400_with_explanation():
    app = create_app(initial_key_count=0)

    class Broken:
        def generate_crypto_keys(self):
            from cryptolib import CryptoError

            raise CryptoError("збій генератора")

    app.state.rsa_service = Broken()
    with TestClient(app) as c:
        r = c.post("/api/crypto-keys/generate/rsa-keys")
    assert r.status_code == 400
    assert "збій генератора" in r.json()["detail"]




def test_public_key_endpoint_returns_key_and_rsa_id_header(client):
    r = client.get("/api/secure-channel/public-key")
    assert r.status_code == 200
    rsa_id = int(r.headers["x-rsa-id"])
    assert client.get(f"/api/crypto-keys/rsa-public-key/{rsa_id}").text == r.text


def test_public_key_endpoint_picks_among_stored_keys(client):
    ids = {int(client.get("/api/secure-channel/public-key").headers["x-rsa-id"]) for _ in range(60)}
    assert ids <= {1, 2, 3}
    assert len(ids) > 1  # вибір справді випадковий


def test_public_key_endpoint_503_when_no_keys():
    with TestClient(create_app(initial_key_count=0)) as c:
        assert c.get("/api/secure-channel/public-key").status_code == 503


def test_handshake_then_message_roundtrip(client):
    session_id, aes_key = open_session(client)

    cipher = aes.encrypt(aes_key, "Привіт, сервере!")
    resp = client.post("/api/secure-channel/messages", json={"encrypted_message": cipher}, headers={"x-session-id": session_id})

    assert resp.status_code == 200
    assert aes.decrypt(aes_key, resp.json()["encrypted_message"]) == "Привіт, сервере!. Received: 2026-11-13 12:30:05 UTC"


def test_reply_is_encrypted_not_plain_text(client):
    session_id, aes_key = open_session(client)
    resp = client.post(
        "/api/secure-channel/messages",
        json={"encrypted_message": aes.encrypt(aes_key, "secret")},
        headers={"x-session-id": session_id},
    )
    assert "secret" not in resp.text and "Received" not in resp.text


def test_sessions_are_independent(client):
    s1, k1 = open_session(client, "s-1")
    s2, k2 = open_session(client, "s-2")
    # повідомлення, зашифроване ключем сесії 1, не розшифровується ключем сесії 2
    resp = client.post(
        "/api/secure-channel/messages", json={"encrypted_message": aes.encrypt(k1, "hello")}, headers={"x-session-id": s2}
    )
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        assert aes.decrypt(k2, resp.json()["encrypted_message"]) != "hello. Received: 2026-11-13 12:30:05 UTC"


def test_handshake_unknown_rsa_id_returns_404(client):
    resp = client.post("/api/secure-channel/sessions", json={"encrypted_data": "AAAA"}, headers={"x-rsa-id": "999"})
    assert resp.status_code == 404


@pytest.mark.parametrize("headers", [{}, {"x-rsa-id": "abc"}])
def test_handshake_bad_rsa_id_header_returns_400(client, headers):
    resp = client.post("/api/secure-channel/sessions", json={"encrypted_data": "AAAA"}, headers=headers)
    assert resp.status_code == 400


def test_handshake_garbage_data_returns_400(client):
    resp = client.post("/api/secure-channel/sessions", json={"encrypted_data": "not base64!!"}, headers={"x-rsa-id": "1"})
    assert resp.status_code == 400


def test_handshake_encrypted_with_other_key_returns_400(client):
    other = rsa.generate_crypto_keys()
    payload = HandshakePayload("s-x", aes.generate_secret_key()).to_json()
    resp = client.post(
        "/api/secure-channel/sessions",
        json={"encrypted_data": rsa.encrypt(other.public_key, payload)},
        headers={"x-rsa-id": "1"},
    )
    assert resp.status_code == 400


def test_handshake_with_bad_structure_returns_400(client):
    public_key = client.get("/api/crypto-keys/rsa-public-key/1").text
    resp = client.post(
        "/api/secure-channel/sessions",
        json={"encrypted_data": rsa.encrypt(public_key, '{"hello": "world"}')},
        headers={"x-rsa-id": "1"},
    )
    assert resp.status_code == 400


def test_handshake_with_invalid_aes_key_returns_400(client):
    from cryptolib import AesKey

    public_key = client.get("/api/crypto-keys/rsa-public-key/1").text
    bad = HandshakePayload("s-bad", AesKey(key=base64.b64encode(b"short").decode(), iv="AAAA")).to_json()
    resp = client.post(
        "/api/secure-channel/sessions", json={"encrypted_data": rsa.encrypt(public_key, bad)}, headers={"x-rsa-id": "1"}
    )
    assert resp.status_code == 400


def test_duplicate_session_id_returns_409(client):
    open_session(client, "dup")
    public_key = client.get("/api/crypto-keys/rsa-public-key/1").text
    again = rsa.encrypt(public_key, HandshakePayload("dup", aes.generate_secret_key()).to_json())
    resp = client.post("/api/secure-channel/sessions", json={"encrypted_data": again}, headers={"x-rsa-id": "1"})
    assert resp.status_code == 409


def test_message_unknown_session_returns_404(client):
    resp = client.post("/api/secure-channel/messages", json={"encrypted_message": "AAAA"}, headers={"x-session-id": "nope"})
    assert resp.status_code == 404


def test_message_without_session_header_returns_400(client):
    assert client.post("/api/secure-channel/messages", json={"encrypted_message": "AAAA"}).status_code == 400


def test_message_garbage_returns_400(client):
    session_id, _ = open_session(client)
    resp = client.post(
        "/api/secure-channel/messages", json={"encrypted_message": "not base64!!"}, headers={"x-session-id": session_id}
    )
    assert resp.status_code == 400




def test_openapi_describes_all_endpoints(client):
    spec = client.get("/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    paths = spec["paths"]
    assert "post" in paths["/api/crypto-keys/generate/rsa-keys"]
    assert "get" in paths["/api/crypto-keys/rsa-public-key/{id}"]
    assert "get" in paths["/api/secure-channel/public-key"]
    assert "post" in paths["/api/secure-channel/sessions"]
    assert "post" in paths["/api/secure-channel/messages"]


def test_swagger_ui_is_served(client):
    assert client.get("/docs").status_code == 200
