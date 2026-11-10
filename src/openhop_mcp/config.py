"""Configuration loading and validation for the openHop MCP plugin.

Configuration lives in ``$OPENHOP_PLUGIN_DATA/config.json`` and is seeded by the
plugin manager from the manifest defaults. The plugin deliberately fails closed:
invalid or unsafe settings abort startup instead of silently degrading security.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .security import ROLES, TokenEntry, hash_token

DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8765,
    "openhop_base_url": "http://127.0.0.1:8000",
    "openhop_api_key": "",
    "auth_tokens": [],
    "allowed_ips": ["127.0.0.1/32", "::1/128"],
    "read_only": True,
    "request_timeout_seconds": 15,
    "max_items": 200,
    "allow_insecure_bind": False,
    "max_auth_failures": 10,
    "auth_failure_window_seconds": 300,
    "auth_lockout_seconds": 900,
    "repeater_db_path": "/var/lib/openhop_repeater/repeater.db",
    "allow_message_history": True,
    "cache_ttl_seconds": 3,
    "audit_log": True,
    "audit_log_max_bytes": 1_000_000,
    "rate_limit_per_minute": 120,
}

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MIN_TOKEN_LENGTH = 16


class ConfigError(RuntimeError):
    """Raised when plugin configuration is missing or unsafe."""


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    openhop_base_url: str
    openhop_api_key: str
    auth_tokens: tuple[TokenEntry, ...]
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_ips_raw: tuple[str, ...]
    read_only: bool
    request_timeout_seconds: float
    max_items: int
    allow_insecure_bind: bool
    max_auth_failures: int
    auth_failure_window_seconds: float
    auth_lockout_seconds: float
    data_dir: Path = field(repr=False)
    token_file: Path = field(repr=False)
    repeater_db_path: str = ""
    allow_message_history: bool = True
    cache_ttl_seconds: float = 3.0
    audit_log: bool = True
    audit_log_max_bytes: int = 1_000_000
    rate_limit_per_minute: int = 120

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / "audit.log"


def _data_dir() -> Path:
    raw = os.environ.get("OPENHOP_PLUGIN_DATA")
    if raw:
        return Path(raw)
    # Fallback for local development/testing outside the plugin manager.
    return Path(os.environ.get("OPENHOP_MCP_DATA", "./data"))


def _read_config_file(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "config.json"
    if not path.exists():
        return dict(DEFAULT_CONFIG)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config.json is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError("config.json must contain a JSON object")
    merged = dict(DEFAULT_CONFIG)
    merged.update(loaded)
    return merged


def _parse_networks(values: Any) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not isinstance(values, list) or not values:
        raise ConfigError("allowed_ips must be a non-empty list of IPs or CIDR blocks")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in values:
        if not isinstance(item, str):
            raise ConfigError(f"allowed_ips entries must be strings, got {type(item).__name__}")
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ConfigError(f"invalid IP/CIDR in allowed_ips: {item!r} ({exc})") from exc
    return tuple(networks)


def _write_token(token_file: Path, token: str) -> None:
    token_file.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 up front so the token is never briefly world-readable.
    fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    with contextlib.suppress(OSError):
        token_file.chmod(0o600)


def _load_or_create_token(data_dir: Path, configured: str) -> str:
    token = configured.strip()
    if token:
        return token
    token_file = data_dir / "auth_token.txt"
    if token_file.exists():
        existing = token_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    generated = secrets.token_urlsafe(32)
    _write_token(token_file, generated)
    return generated


_HEX = frozenset("0123456789abcdef")


def _token_entry(name: str, role: str, token: str = "", token_sha256: str = "") -> TokenEntry:
    cleaned = token.strip()
    digest = token_sha256.strip().lower()
    if cleaned and digest:
        raise ConfigError(f"token {name!r}: set either token or token_sha256, not both")
    if not cleaned and not digest:
        raise ConfigError(f"token {name!r} is empty")
    if cleaned:
        if len(cleaned) < MIN_TOKEN_LENGTH:
            raise ConfigError(
                f"token {name!r} is too short ({len(cleaned)} chars); use at least {MIN_TOKEN_LENGTH}"
            )
        digest = hash_token(cleaned)
    elif len(digest) != 64 or not set(digest) <= _HEX:
        raise ConfigError(f"token {name!r}: token_sha256 must be 64 hex characters")
    normalised_role = role.strip().lower()
    if normalised_role not in ROLES:
        raise ConfigError(f"token {name!r} has invalid role {role!r}; use one of {sorted(ROLES)}")
    return TokenEntry(name=name.strip() or "unnamed", role=normalised_role, sha256=digest)


def _parse_auth_tokens(raw: dict[str, Any], data_dir: Path) -> tuple[TokenEntry, ...]:
    """Build the token table from configuration.

    Supported shapes:

    * ``auth_tokens``: list of objects ``{"name", "role", "token"}`` or
      ``{"name", "role", "token_sha256"}`` (preferred: the config file then
      holds no usable credential), or bare token strings (treated as admin).
    * empty: generate a random admin token and persist it to ``auth_token.txt``.
    """
    entries_raw = raw.get("auth_tokens") or []
    if not isinstance(entries_raw, list):
        raise ConfigError("auth_tokens must be a list")

    tokens: list[TokenEntry] = []
    for index, item in enumerate(entries_raw, start=1):
        if isinstance(item, str):
            tokens.append(_token_entry(f"token-{index}", "admin", item))
        elif isinstance(item, dict):
            name = str(item.get("name") or f"token-{index}")
            role = str(item.get("role") or "read")
            token = str(item.get("token") or "")
            token_sha256 = str(item.get("token_sha256") or "")
            tokens.append(_token_entry(name, role, token, token_sha256))
        else:
            raise ConfigError(
                f"auth_tokens[{index - 1}] must be an object or string, got {type(item).__name__}"
            )

    if not tokens:
        generated = _load_or_create_token(data_dir, "")
        tokens.append(_token_entry("generated", "admin", generated))

    seen: set[str] = set()
    for entry in tokens:
        if entry.sha256 in seen:
            raise ConfigError(f"duplicate token value configured for {entry.name!r}")
        seen.add(entry.sha256)

    return tuple(tokens)


def load_config() -> Config:
    data_dir = _data_dir()
    raw = _read_config_file(data_dir)

    host = str(raw.get("host", "127.0.0.1")).strip()
    try:
        port = int(raw.get("port", 8765))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"port must be an integer, got {raw.get('port')!r}") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"port out of range: {port}")

    base_url = str(raw.get("openhop_base_url", "http://127.0.0.1:8000")).rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise ConfigError("openhop_base_url must start with http:// or https://")

    api_key = str(raw.get("openhop_api_key") or os.environ.get("OPENHOP_API_KEY") or "").strip()
    allowed_ips_raw = raw.get("allowed_ips", DEFAULT_CONFIG["allowed_ips"])
    networks = _parse_networks(allowed_ips_raw)

    read_only = raw.get("read_only", True)
    if not isinstance(read_only, bool):
        raise ConfigError("read_only must be a boolean")

    allow_insecure_bind = raw.get("allow_insecure_bind", False)
    if not isinstance(allow_insecure_bind, bool):
        raise ConfigError("allow_insecure_bind must be a boolean")

    try:
        timeout = float(raw.get("request_timeout_seconds", 15))
    except (TypeError, ValueError) as exc:
        raise ConfigError("request_timeout_seconds must be a number") from exc
    if timeout <= 0:
        raise ConfigError("request_timeout_seconds must be positive")

    try:
        max_items = int(raw.get("max_items", 200))
    except (TypeError, ValueError) as exc:
        raise ConfigError("max_items must be an integer") from exc
    if max_items < 1:
        raise ConfigError("max_items must be >= 1")

    try:
        max_auth_failures = int(raw.get("max_auth_failures", 10))
    except (TypeError, ValueError) as exc:
        raise ConfigError("max_auth_failures must be an integer") from exc
    if max_auth_failures < 1:
        raise ConfigError("max_auth_failures must be >= 1")

    try:
        auth_failure_window_seconds = float(raw.get("auth_failure_window_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise ConfigError("auth_failure_window_seconds must be a number") from exc
    if auth_failure_window_seconds <= 0:
        raise ConfigError("auth_failure_window_seconds must be positive")

    try:
        auth_lockout_seconds = float(raw.get("auth_lockout_seconds", 900))
    except (TypeError, ValueError) as exc:
        raise ConfigError("auth_lockout_seconds must be a number") from exc
    if auth_lockout_seconds <= 0:
        raise ConfigError("auth_lockout_seconds must be positive")

    # --- Safety gates -------------------------------------------------------
    if host not in LOOPBACK_HOSTS and not allow_insecure_bind:
        raise ConfigError(
            "Refusing to bind to a non-loopback address without allow_insecure_bind=true. "
            "Set allowed_ips to specific addresses first, then explicitly acknowledge the bind."
        )

    for net in networks:
        if net.prefixlen == 0 and not allow_insecure_bind:
            raise ConfigError(
                f"allowed_ips contains {net}, which permits every address. "
                "Use specific IPs/CIDRs, or set allow_insecure_bind=true to acknowledge it."
            )

    allow_message_history = raw.get("allow_message_history", True)
    if not isinstance(allow_message_history, bool):
        raise ConfigError("allow_message_history must be a boolean")

    repeater_db_path = str(raw.get("repeater_db_path") or "").strip()
    if repeater_db_path and not Path(repeater_db_path).is_absolute():
        raise ConfigError("repeater_db_path must be an absolute path")

    try:
        cache_ttl_seconds = float(raw.get("cache_ttl_seconds", 3))
    except (TypeError, ValueError) as exc:
        raise ConfigError("cache_ttl_seconds must be a number") from exc
    if not 0 <= cache_ttl_seconds <= 300:
        raise ConfigError("cache_ttl_seconds must be between 0 and 300")

    audit_log = raw.get("audit_log", True)
    if not isinstance(audit_log, bool):
        raise ConfigError("audit_log must be a boolean")

    try:
        audit_log_max_bytes = int(raw.get("audit_log_max_bytes", 1_000_000))
    except (TypeError, ValueError) as exc:
        raise ConfigError("audit_log_max_bytes must be an integer") from exc
    if audit_log_max_bytes < 10_000:
        raise ConfigError("audit_log_max_bytes must be at least 10000")

    try:
        rate_limit_per_minute = int(raw.get("rate_limit_per_minute", 120))
    except (TypeError, ValueError) as exc:
        raise ConfigError("rate_limit_per_minute must be an integer") from exc
    if rate_limit_per_minute < 0:
        raise ConfigError("rate_limit_per_minute must be >= 0 (0 disables)")

    auth_tokens = _parse_auth_tokens(raw, data_dir)

    return Config(
        host=host,
        port=port,
        openhop_base_url=base_url,
        openhop_api_key=api_key,
        auth_tokens=auth_tokens,
        allowed_networks=networks,
        allowed_ips_raw=tuple(str(x) for x in allowed_ips_raw),
        read_only=read_only,
        request_timeout_seconds=timeout,
        max_items=max_items,
        allow_insecure_bind=allow_insecure_bind,
        max_auth_failures=max_auth_failures,
        auth_failure_window_seconds=auth_failure_window_seconds,
        auth_lockout_seconds=auth_lockout_seconds,
        data_dir=data_dir,
        token_file=data_dir / "auth_token.txt",
        repeater_db_path=repeater_db_path,
        allow_message_history=allow_message_history,
        cache_ttl_seconds=cache_ttl_seconds,
        audit_log=audit_log,
        audit_log_max_bytes=audit_log_max_bytes,
        rate_limit_per_minute=rate_limit_per_minute,
    )
