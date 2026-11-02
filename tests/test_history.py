"""Tests for the read-only channel history module.

Builds a synthetic Repeater database with the same schema the plugin reads, then
encrypts known group-text packets so decryption can be asserted end to end.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import struct
import time

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from openhop_mcp.history import HistoryError, RepeaterHistory

SECRET = bytes(range(32))


def _encode(body: str, secret: bytes = SECRET, flags: int = 0, ts: int | None = None) -> str:
    """Build a group-text payload in the format the Repeater logs."""
    stamp = ts if ts is not None else int(time.time())
    plaintext = struct.pack("<I", stamp) + bytes([flags]) + body.encode() + b"\x00"
    encryptor = Cipher(algorithms.AES(secret[:16]), modes.ECB()).encryptor()
    padded = plaintext + b"\x00" * (-len(plaintext) % 16)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(secret, ciphertext, hashlib.sha256).digest()[:2]
    return (b"\x00" + mac + ciphertext).hex()


def _make_db(path, packets, channels=(("Public", SECRET),)):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE packets (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            type INTEGER,
            payload TEXT
        );
        CREATE TABLE companion_channels (
            id INTEGER PRIMARY KEY,
            companion_hash TEXT,
            channel_idx INTEGER,
            name TEXT,
            secret BLOB,
            updated_at REAL
        );
        """
    )
    for index, (name, secret) in enumerate(channels):
        conn.execute(
            "INSERT INTO companion_channels (companion_hash, channel_idx, name, secret, updated_at)"
            " VALUES (?, ?, ?, ?, ?)",
            ("0xf1", index, name, secret, time.time()),
        )
    now = time.time()
    for offset, payload in enumerate(packets):
        conn.execute(
            "INSERT INTO packets (timestamp, type, payload) VALUES (?, ?, ?)",
            (now - offset, 5, payload),
        )
    conn.commit()
    conn.close()


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "repeater.db"
    _make_db(
        path,
        [
            _encode("VK5ABC: hello mesh"),
            _encode("VK5XYZ: second message"),
            _encode("dup: repeated"),
            _encode("dup: repeated"),
        ],
    )
    return path


def test_channels_lists_names_without_secrets(db_path):
    result = RepeaterHistory(db_path).channels()
    assert result["count"] == 1
    entry = result["channels"][0]
    assert entry["name"] == "Public"
    assert entry["indices"] == [0]
    assert "secret" not in str(result).lower().replace("no secrets", "")


def test_messages_decrypts_and_dedupes(db_path):
    result = RepeaterHistory(db_path).messages("Public", days=1, limit=50)
    bodies = [m["message"] for m in result["messages"]]
    assert "VK5ABC: hello mesh" in bodies
    assert "VK5XYZ: second message" in bodies
    # Duplicate packet must collapse to a single message.
    assert bodies.count("dup: repeated") == 1
    assert result["unique_messages"] == 3


def test_messages_unknown_channel(db_path):
    result = RepeaterHistory(db_path).messages("Nope", days=1)
    assert result["error"] == "unknown channel"
    assert "Public" in result["known_channels"]


def test_messages_grep_filter(db_path):
    result = RepeaterHistory(db_path).messages("Public", days=1, grep="second")
    assert [m["message"] for m in result["messages"]] == ["VK5XYZ: second message"]


def test_wrong_secret_is_skipped(tmp_path):
    path = tmp_path / "repeater.db"
    _make_db(path, [_encode("Public: hi")], channels=(("Public", SECRET),))
    # Re-encode with a different secret so HMAC cannot match the stored key.
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM packets")
    conn.execute(
        "INSERT INTO packets (timestamp, type, payload) VALUES (?, 5, ?)",
        (time.time(), _encode("evil: injected", secret=b"\x01" * 32)),
    )
    conn.commit()
    conn.close()
    result = RepeaterHistory(path).messages("Public", days=1)
    assert result["messages"] == []


def test_missing_db_raises(tmp_path):
    with pytest.raises(HistoryError):
        RepeaterHistory(tmp_path / "absent.db").channels()
