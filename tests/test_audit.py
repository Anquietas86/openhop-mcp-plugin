"""Tests for the audit log, per-token rate limiter, and their middleware."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from openhop_mcp.audit import AuditLog, AuditMiddleware, TokenRateLimiter
from openhop_mcp.security import current_auth


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _ctx(method="tools/call", params=None, request_id=1):
    return SimpleNamespace(method=method, params=params or {}, request_id=request_id)


def _run(mw, ctx, result=None, raises=None, name="dash", role="read"):
    async def call_next(_ctx):
        if raises:
            raise raises
        return result if result is not None else CallToolResult(content=[], is_error=False)

    async def go():
        token = current_auth.set({"name": name, "role": role, "ip": "192.0.2.5"})
        try:
            return await mw(ctx, call_next)
        finally:
            current_auth.reset(token)

    return asyncio.run(go())


def _records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_rate_limiter_allows_burst_then_blocks_then_refills():
    clock = Clock()
    limiter = TokenRateLimiter(3, clock=clock)
    assert [limiter.acquire("a") for _ in range(3)] == [0.0, 0.0, 0.0]
    wait = limiter.acquire("a")
    assert wait == pytest.approx(20.0)
    assert limiter.acquire("b") == 0.0  # other tokens unaffected
    clock.now += 20
    assert limiter.acquire("a") == 0.0


def test_rate_limiter_disabled_at_zero():
    limiter = TokenRateLimiter(0)
    assert not limiter.enabled
    assert all(limiter.acquire("a") == 0.0 for _ in range(1000))


def test_audit_records_tool_call(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(0))
    _run(mw, _ctx(params={"name": "openhop_stats", "arguments": {"limit": 5}}))
    (record,) = _records(tmp_path / "audit.log")
    assert record["token"] == "dash"
    assert record["role"] == "read"
    assert record["ip"] == "192.0.2.5"
    assert record["target"] == "openhop_stats"
    assert record["args"] == {"limit": 5}
    assert record["outcome"] == "ok"
    assert "duration_ms" in record
    assert (tmp_path / "audit.log").stat().st_mode & 0o777 == 0o600


def test_audit_truncates_and_redacts_args(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(0))
    _run(mw, _ctx(params={"name": "x", "arguments": {"grep": "a" * 500, "api_key": "sekrit"}}))
    (record,) = _records(tmp_path / "audit.log")
    assert len(record["args"]["grep"]) == 201
    assert record["args"]["api_key"] == "[redacted]"


def test_audit_records_tool_error(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(0))
    failed = CallToolResult(content=[TextContent(type="text", text="forbidden")], is_error=True)
    _run(mw, _ctx(params={"name": "openhop_set_mode"}), result=failed)
    (record,) = _records(tmp_path / "audit.log")
    assert record["outcome"] == "error"
    assert record["error"] == "forbidden"


def test_audit_records_exception_and_reraises(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(0))
    with pytest.raises(RuntimeError):
        _run(mw, _ctx(params={"name": "x"}), raises=RuntimeError("boom"))
    assert _records(tmp_path / "audit.log")[0]["outcome"] == "exception"


def test_rate_limited_tool_call_returns_error_result(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(1))
    _run(mw, _ctx(params={"name": "openhop_stats"}))
    result = _run(mw, _ctx(params={"name": "openhop_stats"}))
    assert result.is_error
    assert "rate limit" in result.content[0].text
    assert _records(tmp_path / "audit.log")[-1]["outcome"] == "rate_limited"


def test_rate_limited_resource_read_raises(tmp_path):
    mw = AuditMiddleware(None, TokenRateLimiter(1))
    _run(mw, _ctx("resources/read", {"uri": "openhop://stats"}))
    with pytest.raises(MCPError):
        _run(mw, _ctx("resources/read", {"uri": "openhop://stats"}))


def test_other_methods_and_notifications_pass_through(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    mw = AuditMiddleware(log, TokenRateLimiter(1))
    for _ in range(5):
        _run(mw, _ctx("tools/list"))
        _run(mw, _ctx("tools/call", {"name": "x"}, request_id=None))
    assert not (tmp_path / "audit.log").read_text()
