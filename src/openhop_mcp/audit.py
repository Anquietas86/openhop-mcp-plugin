"""Audit logging and per-token rate limiting for MCP operations.

Both run as an MCP server middleware, so they see every ``tools/call``,
``resources/read`` and ``prompts/get`` after the HTTP gate has resolved the
caller's identity, and before any handler runs.

Audit records are JSON lines in ``<plugin data>/audit.log`` (size-rotated).
They name the token, role, source address, operation and arguments, plus the
outcome and duration. Results are never logged, and argument values are
truncated and redacted, so channel message content does not end up on disk.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.handlers
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from .client import redact
from .security import current_auth

AUDITED_METHODS = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}
MAX_ARG_CHARS = 200
RATE_LIMITED_CODE = -32029


def _summarise_args(arguments: Any) -> Any:
    """Redact secrets and truncate long values so the log stays small and safe."""
    cleaned = redact(arguments)
    if isinstance(cleaned, dict):
        out: dict[str, Any] = {}
        for key, value in list(cleaned.items())[:20]:
            text = value if isinstance(value, (int, float, bool)) or value is None else str(value)
            if isinstance(text, str) and len(text) > MAX_ARG_CHARS:
                text = text[:MAX_ARG_CHARS] + "…"
            out[str(key)[:64]] = text
        return out
    return None


class AuditLog:
    """Append-only JSON-lines audit trail with size-based rotation."""

    def __init__(self, path: Path, *, max_bytes: int = 1_000_000, backups: int = 5) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger(f"openhop_mcp.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._handler = handler
        self._logger.addHandler(handler)
        with contextlib.suppress(OSError):
            path.chmod(0o600)

    def write(self, record: dict[str, Any]) -> None:
        self._logger.info(json.dumps(record, default=str, ensure_ascii=False))

    def close(self) -> None:
        self._logger.removeHandler(self._handler)
        self._handler.close()


class TokenRateLimiter:
    """Token-bucket limiter keyed by token name.

    ``per_minute`` operations are allowed on average, with bursts up to the
    same number. ``per_minute <= 0`` disables limiting.
    """

    def __init__(self, per_minute: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.refill_per_second = per_minute / 60.0
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.capacity > 0

    def acquire(self, key: str) -> float:
        """Take one unit for ``key``. Returns 0 if allowed, else seconds to wait."""
        if not self.enabled:
            return 0.0
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_second)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return 0.0
            self._buckets[key] = (tokens, now)
            return (1.0 - tokens) / self.refill_per_second


def _result_is_error(result: Any) -> bool:
    if isinstance(result, CallToolResult):
        return bool(result.is_error)
    if isinstance(result, dict):
        return bool(result.get("isError") or result.get("is_error"))
    return False


def _result_error_text(result: Any) -> str:
    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    for item in content or []:
        text = getattr(item, "text", None)
        if text is None and isinstance(item, dict):
            text = item.get("text")
        if text:
            return str(text)[:MAX_ARG_CHARS]
    return ""


class AuditMiddleware:
    """MCP server middleware: rate-limit, then run, then write an audit record."""

    def __init__(self, audit: AuditLog | None, limiter: TokenRateLimiter) -> None:
        self.audit = audit
        self.limiter = limiter

    async def __call__(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
        method = getattr(ctx, "method", "")
        if method not in AUDITED_METHODS or getattr(ctx, "request_id", None) is None:
            return await call_next(ctx)

        params = getattr(ctx, "params", None) or {}
        target = str(params.get(AUDITED_METHODS[method]) or "")
        auth = current_auth.get()
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "token": auth.get("name"),
            "role": auth.get("role"),
            "ip": auth.get("ip"),
            "method": method,
            "target": target,
            "args": _summarise_args(params.get("arguments")),
        }

        wait = self.limiter.acquire(str(auth.get("name")))
        if wait > 0:
            record.update(outcome="rate_limited", retry_after_seconds=round(wait, 1))
            self._write(record)
            message = f"rate limit exceeded for this token; retry in {wait:.1f}s"
            if method == "tools/call":
                return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)
            raise MCPError(RATE_LIMITED_CODE, message)

        started = time.perf_counter()
        try:
            result = await call_next(ctx)
        except Exception as exc:
            record.update(
                outcome="exception",
                error=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
            )
            self._write(record)
            raise
        record["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
        if _result_is_error(result):
            record.update(outcome="error", error=_result_error_text(result))
        else:
            record["outcome"] = "ok"
        self._write(record)
        return result

    def _write(self, record: dict[str, Any]) -> None:
        if self.audit is None:
            return
        try:
            self.audit.write(record)
        except Exception as exc:  # pragma: no cover - never fail a request over logging
            print(f"[openhop-mcp] audit log write failed: {exc}", file=sys.stderr, flush=True)
