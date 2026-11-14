import io
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from cryptolib import AesService, RsaService
from securechat_client import SecureChannelClient, SecureChannelError, SessionExpiredError
from securechat_client.cli import run_console
from securechat_server import create_app

FIXED_TIME = datetime(2026, 11, 13, 12, 30, 5, tzinfo=timezone.utc)


LIFETIME = timedelta(minutes=1)


class Clock:
    def __init__(self) -> None:
        self.now = FIXED_TIME

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture(scope="module")
def clock():
    return Clock()


@pytest.fixture(scope="module")
def app(clock):
    return create_app(initial_key_count=3, session_lifetime=LIFETIME, clock=clock)


@pytest.fixture()
def http(app):
    # TestClient — це httpx.Client, що ходить прямо в застосунок: справжній сервер не потрібен.
    with TestClient(app, base_url="http://testserver") as c:
        yield c


def test_full_flow_client_to_server_and_back(http):
    steps = []
    client = SecureChannelClient(http, on_step=steps.append)

    result = client.send_message("Привіт!")

    assert result.reply == "Привіт!. Received: 2026-11-13 12:30:05 UTC"
    assert result.session_id
    assert 1 <= result.rsa_id <= 3
    assert len(steps) == 6  # ключ, сесія, підтвердження, хеш, відповідь, перевірка хешу відповіді


def test_session_per_message_mode_creates_new_session_each_time(http):
    client = SecureChannelClient(http, reuse_session=False)
    first = client.send_message("one")
    second = client.send_message("two")
    assert first.session_id != second.session_id


def test_same_session_is_reused_by_default(http):
    client = SecureChannelClient(http)
    first = client.send_message("one")
    second = client.send_message("two")
    assert first.session_id == second.session_id
    assert second.reply.startswith("two. Received:")


class RecordingClient(TestClient):
    """TestClient, що запам'ятовує тіла всіх запитів — тобто те, що йде «по дроту»."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bodies: list[str] = []

    def send(self, request, **kwargs):
        self.bodies.append(request.content.decode("utf-8", errors="replace"))
        return super().send(request, **kwargs)


def test_plain_text_never_travels_over_the_wire(app):
    with RecordingClient(app) as spying:
        SecureChannelClient(spying).send_message("дуже секретний текст")

    assert len(spying.bodies) == 3  # public-key, sessions, messages
    assert not any("секретний" in body for body in spying.bodies)


def test_server_error_is_reported_as_secure_channel_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "На сервері немає жодної пари RSA-ключів."})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x") as http:
        with pytest.raises(SecureChannelError, match="503"):
            SecureChannelClient(http).send_message("hi")


def test_unreachable_server_is_reported_as_secure_channel_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x") as http:
        with pytest.raises(SecureChannelError, match="Не вдалося звернутися"):
            SecureChannelClient(http).send_message("hi")


def test_missing_rsa_id_header_is_reported():
    def handler(request):
        return httpx.Response(200, text="AAAA")

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x") as http:
        with pytest.raises(SecureChannelError, match="x-rsa-id"):
            SecureChannelClient(http).fetch_public_key()


class TamperingClient(TestClient):
    """Підміняє відповідь сервера на повідомлення сміттям."""

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"encrypted_message": "AAAA"}, request=request)
        return response


def test_tampered_reply_is_reported(app):
    with TamperingClient(app) as tampering:
        with pytest.raises(SecureChannelError, match="розшифрувати"):
            SecureChannelClient(tampering).send_message("hi")


def run_with_inputs(http, inputs, **kwargs):
    answers = iter(inputs)
    out = io.StringIO()
    code = run_console(SecureChannelClient(http, **kwargs), read=lambda _prompt: next(answers), out=out)
    return code, out.getvalue()


def test_console_prints_reply_and_session_number(http):
    code, output = run_with_inputs(http, ["Привіт", "exit"])
    assert code == 0
    assert "Відповідь сервера: Привіт. Received: 2026-11-13 12:30:05 UTC" in output
    assert "Номер сесії:" in output


def test_console_asks_again_after_each_message(http):
    _, output = run_with_inputs(http, ["one", "two", "three", ""])
    assert output.count("Відповідь сервера:") == 3


def test_console_keeps_working_after_server_error():
    state = {"fail": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["fail"]:
            state["fail"] = False
            return httpx.Response(500, json={"detail": "boom"})
        raise httpx.ConnectError("down")

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x") as http:
        code, output = run_with_inputs(http, ["a", "b", "exit"])
    assert code == 0
    assert output.count("Помилка:") == 2


def test_console_exits_on_eof(http):
    def read(_prompt):
        raise EOFError

    assert run_console(SecureChannelClient(http), read=read, out=io.StringIO()) == 0


def test_aes_service_is_shared_between_client_and_server():
    # Бібліотека одна на обох: клієнт і сервер використовують той самий клас.
    from securechat_server.app import AesService as server_aes

    assert server_aes is AesService


# --- лабораторна №7 ---


def test_expired_session_is_replaced_with_a_new_one(app, clock):
    clock.now = FIXED_TIME
    steps = []
    with TestClient(app) as http:
        client = SecureChannelClient(http, on_step=steps.append)
        first = client.send_message("one")

        clock.now = FIXED_TIME + LIFETIME + timedelta(seconds=1)
        second = client.send_message("two")
    clock.now = FIXED_TIME

    assert second.session_id != first.session_id
    assert second.reply.startswith("two. Received:")
    assert any("440" in step for step in steps)


def test_replaced_session_is_listed_as_invalid(app, clock):
    clock.now = FIXED_TIME
    with TestClient(app) as http:
        client = SecureChannelClient(http)
        client.send_message("one")
        clock.now = FIXED_TIME + LIFETIME + timedelta(seconds=1)
        client.send_message("two")
        sessions = http.get("/api/sessions").json()
    clock.now = FIXED_TIME

    assert sum(1 for s in sessions if s["status"] == "invalid") >= 1
    assert sum(1 for s in sessions if s["status"] == "valid") >= 1


def test_valid_session_is_reused_until_it_expires(app, clock):
    clock.now = FIXED_TIME
    with TestClient(app) as http:
        client = SecureChannelClient(http)
        first = client.send_message("one")
        clock.now = FIXED_TIME + LIFETIME  # рівно на межі сесія ще дійсна
        second = client.send_message("two")
    clock.now = FIXED_TIME
    assert first.session_id == second.session_id


def test_client_retries_only_once_if_the_new_session_is_expired_too():
    public_key = RsaService().generate_crypto_keys().public_key
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("/public-key"):
            return httpx.Response(200, text=public_key, headers={"x-rsa-id": "1"})
        if request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"status": "established"})
        return httpx.Response(440, json={"detail": "Термін дії сесії закінчився."})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x") as http:
        with pytest.raises(SessionExpiredError, match="440"):
            SecureChannelClient(http).send_message("hi")

    assert sum(path.endswith("/messages") for path in seen) == 2  # одна спроба й один повтор у новій сесії
    assert sum(path.endswith("/sessions") for path in seen) == 2


class TamperingAes(AesService):
    """Змінює дані у відповіді сервера, не чіпаючи хеш, — наче її підмінили дорогою."""

    def decrypt(self, key, cipher_text):
        text = super().decrypt(key, cipher_text)
        try:
            parsed = json.loads(text)
        except ValueError:
            return text
        if isinstance(parsed, dict) and "hash" in parsed:
            parsed["data"] += " (підмінено)"
            return json.dumps(parsed, ensure_ascii=False)
        return text


def test_reply_with_wrong_hash_is_rejected(http):
    client = SecureChannelClient(http, aes_service=TamperingAes())
    with pytest.raises(SecureChannelError, match="Хеш відповіді"):
        client.send_message("hi")


def test_console_continues_after_expired_session(app, clock):
    clock.now = FIXED_TIME
    answers = iter(["one", "two", "exit"])
    out = io.StringIO()

    def read(_prompt):
        value = next(answers)
        if value == "two":
            clock.now = FIXED_TIME + LIFETIME + timedelta(seconds=5)
        return value

    with TestClient(app) as http:
        run_console(SecureChannelClient(http), read=read, out=out)
    clock.now = FIXED_TIME

    assert out.getvalue().count("Відповідь сервера:") == 2
    assert "Помилка" not in out.getvalue()
