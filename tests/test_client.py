import io
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from cryptolib import AesService
from securechat_client import SecureChannelClient, SecureChannelError
from securechat_client.cli import run_console
from securechat_server import create_app

FIXED_TIME = datetime(2026, 11, 13, 12, 30, 5, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def app():
    return create_app(initial_key_count=3, clock=lambda: FIXED_TIME)


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
    assert len(steps) == 4  # ключ, сесія, підтвердження, відповідь


def test_new_session_for_every_message_by_default(http):
    client = SecureChannelClient(http)
    first = client.send_message("one")
    second = client.send_message("two")
    assert first.session_id != second.session_id


def test_reuse_session_keeps_the_same_session(http):
    client = SecureChannelClient(http, reuse_session=True)
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
