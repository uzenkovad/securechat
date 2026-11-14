import base64

import pytest

from cryptolib import CryptoError, RsaService


@pytest.fixture(scope="module")
def service() -> RsaService:
    return RsaService()


@pytest.fixture(scope="module")
def keys(service):
    return service.generate_crypto_keys()


def test_generate_returns_base64_keys(keys):
    assert base64.b64decode(keys.public_key, validate=True)
    assert base64.b64decode(keys.private_key, validate=True)
    assert keys.public_key != keys.private_key


def test_generated_pairs_are_different(service, keys):
    other = service.generate_crypto_keys()
    assert other.public_key != keys.public_key
    assert other.private_key != keys.private_key


def test_encrypt_decrypt_roundtrip(service, keys):
    cipher = service.encrypt(keys.public_key, "Привіт, світ!")
    assert service.decrypt(keys.private_key, cipher) == "Привіт, світ!"


def test_cipher_text_is_base64_and_differs_from_plain_text(service, keys):
    cipher = service.encrypt(keys.public_key, "secret")
    assert base64.b64decode(cipher, validate=True)
    assert "secret" not in cipher


def test_encryption_is_randomized(service, keys):
    # OAEP додає випадковість: однаковий текст дає різні шифротексти,
    # але обидва розшифровуються в той самий текст.
    first = service.encrypt(keys.public_key, "same text")
    second = service.encrypt(keys.public_key, "same text")
    assert first != second
    assert service.decrypt(keys.private_key, first) == service.decrypt(keys.private_key, second)


def test_decrypt_with_wrong_private_key_fails(service, keys):
    other = service.generate_crypto_keys()
    cipher = service.encrypt(keys.public_key, "secret")
    with pytest.raises(CryptoError):
        service.decrypt(other.private_key, cipher)


def test_plain_text_longer_than_rsa_limit_is_rejected(service, keys):
    with pytest.raises(CryptoError):
        service.encrypt(keys.public_key, "x" * 300)


@pytest.mark.parametrize("bad_key", ["not base64!!", "", base64.b64encode(b"garbage").decode()])
def test_encrypt_with_invalid_public_key_fails(service, bad_key):
    with pytest.raises(CryptoError):
        service.encrypt(bad_key, "text")


def test_decrypt_invalid_cipher_text_fails(service, keys):
    with pytest.raises(CryptoError):
        service.decrypt(keys.private_key, "not base64!!")
    with pytest.raises(CryptoError):
        service.decrypt(keys.private_key, base64.b64encode(b"short").decode())


def test_public_key_cannot_be_used_as_private_key(service, keys):
    cipher = service.encrypt(keys.public_key, "secret")
    with pytest.raises(CryptoError):
        service.decrypt(keys.public_key, cipher)
