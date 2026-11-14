import pytest

from cryptolib import AesKey, AesService, HandshakePayload, ProtocolError, RsaService


def test_handshake_payload_roundtrip():
    payload = HandshakePayload(session_id="abc", aes_key=AesKey(key="a2V5", iv="aXY="))
    assert HandshakePayload.from_json(payload.to_json()) == payload


@pytest.mark.parametrize(
    "text",
    ["not json", "[]", "{}", '{"session_id":"s","key":"k"}', '{"session_id":"","key":"k","iv":"i"}', '{"session_id":1,"key":"k","iv":"i"}'],
)
def test_handshake_payload_rejects_bad_structure(text):
    with pytest.raises(ProtocolError):
        HandshakePayload.from_json(text)


def test_handshake_payload_fits_into_one_rsa_block():
    # Дані рукостискання (session_id + ключ AES-256 + IV) мають вміщатися в
    # одне RSA-OAEP шифрування: для 2048 біт — до 190 байтів.
    rsa = RsaService()
    aes = AesService()
    keys = rsa.generate_crypto_keys()
    payload = HandshakePayload(session_id="12345678-1234-1234-1234-123456789012", aes_key=aes.generate_secret_key())
    assert len(payload.to_json().encode()) <= 190
    cipher = rsa.encrypt(keys.public_key, payload.to_json())
    assert HandshakePayload.from_json(rsa.decrypt(keys.private_key, cipher)) == payload
