"""Read-only access to the Repeater's SQLite database for channel history.

The Repeater REST API does not expose mesh conversation content. Group text
packets are logged in the ``packets`` table (``type=5``) as ciphertext and can
only be read back by decrypting them with the channel secret stored in
``companion_channels``.

Design constraints:

* The database is opened **read-only** via a ``file:...?mode=ro`` URI so the
  live WAL is never disturbed. The plugin runs as the Repeater service account,
  which already owns the file.
* Channel secrets are never returned to MCP clients. They are loaded into
  memory only to decrypt packets, and only the plaintext message body leaves
  this module.
* The same channel *name* exists under several ``companion_hash`` rows with
  different secrets. All candidates are tried and the first HMAC match wins.
* History is admin-only at the tool layer — message content is more sensitive
  than telemetry.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import struct
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GROUP_TEXT_TYPE = 5
SECRET_CACHE_SECONDS = 60.0


class HistoryError(RuntimeError):
    """Raised when the Repeater database cannot be read."""


def _open_ro(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise HistoryError(f"repeater database not found: {path}")
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise HistoryError(f"cannot open {path} read-only: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def _decode_payload(payload_hex: str, secret: bytes) -> tuple[int, int, str] | None:
    """Decrypt one group-text payload, or return None if the key does not match.

    Layout: ``[1B channel hash][2B HMAC][ciphertext...]``. The HMAC is
    HMAC-SHA256(secret, ciphertext) truncated to two bytes. The plaintext is
    ``uint32 LE timestamp | flags byte | C-string body``. Packets whose flags
    indicate an unsupported group-text subtype are dropped.
    """
    try:
        raw = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if len(raw) < 5:
        return None
    mac, ciphertext = raw[1:3], raw[3:]
    if not ciphertext:
        return None
    expected = hmac.new(secret, ciphertext, hashlib.sha256).digest()[:2]
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        decryptor = Cipher(algorithms.AES(secret[:16]), modes.ECB()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:  # pragma: no cover - malformed ciphertext
        return None
    if len(plaintext) < 5:
        return None
    timestamp = struct.unpack("<I", plaintext[:4])[0]
    flags = plaintext[4]
    if flags >> 2 != 0:
        return None
    body = plaintext[5:].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
    if not body:
        return None
    return timestamp, flags, body


class RepeaterHistory:
    """Query channel history from the Repeater's SQLite database."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._secrets: dict[str, list[bytes]] = {}
        self._secrets_loaded_at = 0.0

    # -- channel metadata -------------------------------------------------

    def _load_secrets(self, *, force: bool = False) -> dict[str, list[bytes]]:
        with self._lock:
            fresh = (time.monotonic() - self._secrets_loaded_at) < SECRET_CACHE_SECONDS
            if self._secrets and fresh and not force:
                return self._secrets
            conn = _open_ro(self.db_path)
            try:
                rows = conn.execute(
                    "SELECT name, secret FROM companion_channels"
                ).fetchall()
            finally:
                conn.close()
            secrets: dict[str, list[bytes]] = {}
            for row in rows:
                name = row["name"]
                secret = row["secret"]
                if not name or not secret:
                    continue
                blob = bytes(secret)
                if len(blob) < 16:
                    continue
                bucket = secrets.setdefault(str(name), [])
                if blob not in bucket:
                    bucket.append(blob)
            self._secrets = secrets
            self._secrets_loaded_at = time.monotonic()
            return secrets

    def channels(self) -> dict[str, Any]:
        """List configured channels. Names and indices only — never secrets."""
        conn = _open_ro(self.db_path)
        try:
            rows = conn.execute(
                "SELECT companion_hash, channel_idx, name FROM companion_channels "
                "ORDER BY companion_hash, channel_idx"
            ).fetchall()
        finally:
            conn.close()

        by_name: dict[str, dict[str, Any]] = {}
        for row in rows:
            name = row["name"]
            if not name:
                continue
            entry = by_name.setdefault(
                str(name), {"name": str(name), "indices": [], "companions": []}
            )
            if row["channel_idx"] not in entry["indices"]:
                entry["indices"].append(row["channel_idx"])
            if row["companion_hash"] not in entry["companions"]:
                entry["companions"].append(row["companion_hash"])

        channels = sorted(by_name.values(), key=lambda item: item["name"].lower())
        return {
            "count": len(channels),
            "channels": channels,
            "source": str(self.db_path),
        }

    # -- message history --------------------------------------------------

    def messages(
        self,
        channel: str | None = None,
        *,
        days: float = 7.0,
        limit: int = 100,
        grep: str | None = None,
        include_bogus_timestamps: bool = False,
    ) -> dict[str, Any]:
        """Return decrypted channel messages within the last ``days`` days."""
        days = max(0.01, float(days))
        limit = max(1, min(int(limit), 1000))
        cutoff = time.time() - (days * 86400.0)
        pattern = grep.lower() if grep else None

        secrets = self._load_secrets()
        if channel:
            candidates = {
                name: blobs
                for name, blobs in secrets.items()
                if name.lower() == channel.lower()
            }
            if not candidates:
                return {
                    "error": "unknown channel",
                    "channel": channel,
                    "known_channels": sorted(secrets),
                }
        else:
            candidates = secrets

        conn = _open_ro(self.db_path)
        try:
            rows = conn.execute(
                "SELECT id, timestamp, payload FROM packets "
                "WHERE type = ? AND timestamp >= ? ORDER BY id DESC",
                (GROUP_TEXT_TYPE, cutoff),
            ).fetchall()
        finally:
            conn.close()

        seen: set[tuple[int, str]] = set()
        matches: list[dict[str, Any]] = []
        scanned = 0
        for row in rows:
            payload = row["payload"]
            if not payload or len(str(payload)) < 10:
                continue
            scanned += 1
            for name, blobs in candidates.items():
                decoded = None
                for blob in blobs:
                    try:
                        decoded = _decode_payload(str(payload), blob)
                    except Exception:  # pragma: no cover - defensive
                        decoded = None
                    if decoded:
                        break
                if not decoded:
                    continue
                device_ts, _flags, body = decoded
                key = (device_ts, body)
                if key in seen:
                    break
                seen.add(key)
                # Device clocks are unreliable; flag implausible timestamps.
                bogus = device_ts < 1_600_000_000 or device_ts > time.time() + 86400
                if bogus and not include_bogus_timestamps:
                    break
                if pattern and pattern not in body.lower():
                    break
                sender = body.split(":", 1)[0] if ":" in body[:40] else ""
                matches.append(
                    {
                        "channel": name,
                        "device_timestamp": device_ts,
                        "logged_at": row["timestamp"],
                        "timestamp_bogus": bogus,
                        "sender": sender.strip(),
                        "message": body,
                        "packet_id": row["id"],
                    }
                )
                break

        matches.sort(key=lambda item: item["logged_at"], reverse=True)
        trimmed = matches[:limit]
        return {
            "channel": channel or "all",
            "days": days,
            "scanned_packets": scanned,
            "unique_messages": len(matches),
            "returned": len(trimmed),
            "truncated": len(matches) > len(trimmed),
            "messages": trimmed,
        }
