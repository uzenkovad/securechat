import hashlib

import pytest

from cryptolib import HashedMessage, ProtocolError, compute_hash


def test_compute_hash_is_sha256_hex_of_utf8():
    assert compute_hash("abc") == hashlib.sha256(b"abc").hexdigest()
    assert compute_hash("Привіт") == hashlib.sha256("Привіт".encode("utf-8")).hexdigest()


def test_same_text_same_hash_different_text_different_hash():
    assert compute_hash("a") == compute_hash("a")
    assert compute_hash("a") != compute_hash("b")


def test_created_message_is_valid():
    assert HashedMessage.create("Привіт, світе!").is_valid()
    assert HashedMessage.create("").is_valid()


def test_changed_data_is_detected():
    message = HashedMessage.create("переказати 100 грн")
    forged = HashedMessage(data="переказати 900 грн", hash=message.hash)
    assert not forged.is_valid()


def test_changed_hash_is_detected():
    assert not HashedMessage(data="hello", hash="0" * 64).is_valid()


def test_hash_comparison_ignores_letter_case():
    message = HashedMessage.create("hello")
    assert HashedMessage(data="hello", hash=message.hash.upper()).is_valid()


def test_json_roundtrip_keeps_cyrillic():
    message = HashedMessage.create("Привіт")
    restored = HashedMessage.from_json(message.to_json())
    assert restored == message
    assert "Привіт" in message.to_json()


@pytest.mark.parametrize(
    "text",
    ["not json", "[]", '{"data": "x"}', '{"hash": "x"}', '{"data": 1, "hash": "x"}', '{"data": "x", "hash": null}'],
)
def test_malformed_json_raises_protocol_error(text):
    with pytest.raises(ProtocolError):
        HashedMessage.from_json(text)
