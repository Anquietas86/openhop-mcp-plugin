"""Tests for the openhop-mcp-token CLI."""

from __future__ import annotations

import io
import json

from openhop_mcp.security import hash_token
from openhop_mcp.tokens import main, mint


def test_mint_returns_matching_hash():
    result = mint("grafana", "read")
    assert len(result["token"]) >= 32
    entry = result["config_entry"]
    assert entry == {"name": "grafana", "role": "read", "token_sha256": hash_token(result["token"])}


def test_mint_cli_prints_token_then_entry(capsys):
    assert main(["mint", "--name", "bot", "--role", "admin"]) == 0
    out = capsys.readouterr().out.strip().split("\n", 1)
    token, entry = out[0], json.loads(out[1])
    assert entry["role"] == "admin"
    assert entry["token_sha256"] == hash_token(token)


def test_hash_cli_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("some-long-token-value-123\n"))
    assert main(["hash"]) == 0
    assert capsys.readouterr().out.strip() == hash_token("some-long-token-value-123")


def test_hash_cli_rejects_short(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("short"))
    assert main(["hash"]) == 1
