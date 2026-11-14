import base64

import pytest

from cryptolib import AesKey, AesService, CryptoError


@pytest.fixture()
def service() -> AesService:
    return AesService()


@pytest.fixture()
def key(service) -> AesKey:
    return service.generate_secret_key()


def test_generate_key_sizes(key):
    assert len(base64.b64decode(key.key)) == 32  # AES-256
    assert len(base64.b64decode(key.iv)) == 16  # розмір блоку AES


def test_generated_keys_are_unique(service, key):
    other = service.generate_secret_key()
    assert other.key != key.key
    assert other.iv != key.iv


@pytest.mark.parametrize(
    "text",
    ["", "a", "Привіт, світ!", "x" * 16, "x" * 17, "emoji 🔐 і кирилиця", "line1\nline2\ttab", "long " * 5000],
)
def test_encrypt_decrypt_roundtrip(service, key, text):
    cipher = service.encrypt(key, text)
    assert service.decrypt(key, cipher) == text


def test_cipher_text_is_base64_and_hides_plain_text(service, key):
    cipher = service.encrypt(key, "secret message")
    assert base64.b64decode(cipher, validate=True)
    assert "secret" not in cipher


def test_cipher_length_is_multiple_of_block(service, key):
    for n in (0, 1, 15, 16, 17, 100):
        raw = base64.b64decode(service.encrypt(key, "a" * n))
        assert len(raw) % 16 == 0


def test_known_answer_is_deterministic_for_same_key(service):
    fixed = AesKey(key=base64.b64encode(bytes(range(32))).decode(), iv=base64.b64encode(bytes(range(16))).decode())
    assert service.encrypt(fixed, "hello") == service.encrypt(fixed, "hello")
    assert service.decrypt(fixed, service.encrypt(fixed, "hello")) == "hello"


def test_wrong_key_does_not_return_original(service, key):
    other = service.generate_secret_key()
    cipher = service.encrypt(key, "secret message")
    try:
        result = service.decrypt(other, cipher)
    except CryptoError:
        return  # найчастіший випадок: некоректне доповнення
    assert result != "secret message"


def test_tampered_cipher_text_is_detected_or_changed(service, key):
    cipher = bytearray(base64.b64decode(service.encrypt(key, "secret message")))
    cipher[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(cipher)).decode()
    try:
        result = service.decrypt(key, tampered)
    except CryptoError:
        return
    assert result != "secret message"


def test_decrypt_invalid_base64_fails(service, key):
    with pytest.raises(CryptoError):
        service.decrypt(key, "not base64!!")


def test_decrypt_wrong_length_fails(service, key):
    with pytest.raises(CryptoError):
        service.decrypt(key, base64.b64encode(b"123").decode())


@pytest.mark.parametrize(
    "bad",
    [
        AesKey(key="not base64!!", iv=base64.b64encode(bytes(16)).decode()),
        AesKey(key=base64.b64encode(bytes(10)).decode(), iv=base64.b64encode(bytes(16)).decode()),
        AesKey(key=base64.b64encode(bytes(32)).decode(), iv=base64.b64encode(bytes(8)).decode()),
    ],
)
def test_invalid_key_material_is_rejected(service, bad):
    with pytest.raises(CryptoError):
        service.encrypt(bad, "text")
    with pytest.raises(CryptoError):
        service.decrypt(bad, "AAAAAAAAAAAAAAAAAAAAAA==")


def test_invalid_key_size_in_constructor():
    with pytest.raises(ValueError):
        AesService(key_size_bytes=20)
