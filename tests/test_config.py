"""Unit tests for configuration loading and safety gates."""

from __future__ import annotations

import json

import pytest

from openhop_mcp.config import ConfigError, _parse_networks, load_config


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("OPENHOP_API_KEY", raising=False)


def _write(tmp_path, **overrides):
    config = {
        "host": "127.0.0.1",
        "port": 8765,
        "openhop_base_url": "http://127.0.0.1:8000",
        "auth_token": "test-token-abcdefghijklmnop",
        "allowed_ips": ["127.0.0.1/32"],
        "read_only": True,
    }
    config.update(overrides)
    (tmp_path / "config.json").write_text(json.dumps(config))
    return tmp_path


def _load(tmp_path, monkeypatch, **overrides):
    monkeypatch.setenv("OPENHOP_MCP_DATA", str(tmp_path))
    _write(tmp_path, **overrides)
    return load_config()


def test_parse_networks_accepts_cidrs():
    nets = _parse_networks(["127.0.0.1/32", "::1/128", "192.0.2.0/24"])
    assert len(nets) == 3


@pytest.mark.parametrize("value", [[], "127.0.0.1", [123], ["not-a-cidr"]])
def test_parse_networks_rejects_bad_input(value):
    with pytest.raises(ConfigError):
        _parse_networks(value)


def test_load_config_defaults_when_file_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENHOP_MCP_DATA", str(tmp_path))
    cfg = load_config()
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8765
    assert cfg.read_only is True
    assert len(cfg.auth_tokens) == 1
    assert cfg.auth_tokens[0].role == "admin"


def test_generated_token_is_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENHOP_MCP_DATA", str(tmp_path))
    cfg = load_config()
    token_file = tmp_path / "auth_token.txt"
    assert token_file.exists()
    assert token_file.read_text().strip() == cfg.auth_tokens[0].token
    assert (token_file.stat().st_mode & 0o777) == 0o600


def test_generated_token_is_stable_across_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENHOP_MCP_DATA", str(tmp_path))
    first = load_config().auth_tokens[0].token
    second = load_config().auth_tokens[0].token
    assert first == second


def test_legacy_single_token_becomes_admin(tmp_path, monkeypatch):
    cfg = _load(tmp_path, monkeypatch)
    assert len(cfg.auth_tokens) == 1
    assert cfg.auth_tokens[0].role == "admin"
    assert cfg.auth_tokens[0].name == "legacy"


def test_structured_tokens_parsed(tmp_path, monkeypatch):
    cfg = _load(
        tmp_path,
        monkeypatch,
        auth_token="",
        auth_tokens=[
            {"name": "dashboard", "role": "read", "token": "read-token-abcdefghijklmnop"},
            {"name": "ops", "role": "admin", "token": "admin-token-abcdefghijklmnop"},
        ],
    )
    assert len(cfg.auth_tokens) == 2
    roles = {entry.name: entry.role for entry in cfg.auth_tokens}
    assert roles == {"dashboard": "read", "ops": "admin"}


def test_bare_string_token_is_admin(tmp_path, monkeypatch):
    cfg = _load(
        tmp_path,
        monkeypatch,
        auth_token="",
        auth_tokens=["plain-token-abcdefghijklmnop"],
    )
    assert len(cfg.auth_tokens) == 1
    assert cfg.auth_tokens[0].role == "admin"


def test_duplicate_tokens_rejected(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="duplicate token"):
        _load(
            tmp_path,
            monkeypatch,
            auth_token="",
            auth_tokens=[
                {"name": "a", "role": "read", "token": "same-token-abcdefghijklmnop"},
                {"name": "b", "role": "admin", "token": "same-token-abcdefghijklmnop"},
            ],
        )


def test_invalid_role_rejected(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="invalid role"):
        _load(
            tmp_path,
            monkeypatch,
            auth_token="",
            auth_tokens=[
                {"name": "a", "role": "owner", "token": "token-abcdefghijklmnop"},
            ],
        )


def test_short_token_rejected(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="too short"):
        _load(tmp_path, monkeypatch, auth_token="short")


def test_rejects_non_loopback_bind_without_flag(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="non-loopback"):
        _load(tmp_path, monkeypatch, host="0.0.0.0")


def test_allows_non_loopback_bind_with_flag(tmp_path, monkeypatch):
    cfg = _load(tmp_path, monkeypatch, host="0.0.0.0", allow_insecure_bind=True)
    assert cfg.host == "0.0.0.0"


def test_rejects_wildcard_allowlist_without_flag(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="permits every address"):
        _load(tmp_path, monkeypatch, allowed_ips=["0.0.0.0/0"])


def test_allows_wildcard_allowlist_with_flag(tmp_path, monkeypatch):
    cfg = _load(
        tmp_path, monkeypatch, allowed_ips=["0.0.0.0/0"], allow_insecure_bind=True
    )
    assert cfg.allowed_ips_raw == ("0.0.0.0/0",)


def test_rejects_bad_port(tmp_path, monkeypatch):
    with pytest.raises(ConfigError):
        _load(tmp_path, monkeypatch, port=70000)


def test_rejects_non_bool_read_only(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="read_only must be a boolean"):
        _load(tmp_path, monkeypatch, read_only="yes")
