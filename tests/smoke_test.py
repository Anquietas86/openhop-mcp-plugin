"""Local end-to-end smoke test for the openHop MCP plugin.

Starts the plugin as a real subprocess (the same way the plugin manager runs the
console script), exercises the security gate and the MCP handshake, then tears
it down. No external test framework required.

Usage:
    PYTHONPATH=src .venv/bin/python tests/smoke_test.py
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8799
DENY_PORT = 8800
TOKEN = "smoke-test-token-0123456789"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _wait(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _request(path: str, *, port: int = PORT, token: str | None = None,
             body: dict | None = None, session_id: str | None = None,
             timeout: float = 20.0) -> tuple[int, dict[str, str], bytes]:
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://{HOST}:{port}{path}", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _json_from_sse(raw: bytes) -> dict | None:
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("data: "):
            try:
                return json.loads(line[6:])
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(raw.decode())
    except json.JSONDecodeError:
        return None


def _write_config(data_dir: Path, **overrides) -> None:
    key = os.environ.get("OPENHOP_TEST_API_KEY", "").strip()
    if not key:
        key_file = Path("/tmp/pymc_key")
        if key_file.exists():
            key = key_file.read_text().strip()
    config = {
        "host": HOST,
        "port": PORT,
        "openhop_base_url": os.environ.get("OPENHOP_BASE_URL", "http://127.0.0.1:8000"),
        "openhop_api_key": key,
        "auth_token": TOKEN,
        "allowed_ips": ["127.0.0.1/32"],
        "read_only": True,
        "allow_insecure_bind": True,
        "request_timeout_seconds": 10,
    }
    config.update(overrides)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "config.json").write_text(json.dumps(config))


def _start(data_dir: Path, port: int) -> subprocess.Popen:
    env = dict(os.environ)
    env["OPENHOP_MCP_DATA"] = str(data_dir)
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "openhop_mcp.server"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if not _wait(port):
        output = ""
        if proc.stdout:
            try:
                proc.terminate()
                output = proc.stdout.read()[-3000:]
            except Exception:
                pass
        raise RuntimeError(f"server on port {port} failed to start. Output:\n{output}")
    return proc


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        print(f"{'PASS' if condition else 'FAIL'}: {name}{' — ' + detail if detail else ''}")
        if not condition:
            failures.append(name)

    allowed_dir = Path(tempfile.mkdtemp(prefix="openhop-mcp-allow-"))
    deny_dir = Path(tempfile.mkdtemp(prefix="openhop-mcp-deny-"))
    _write_config(allowed_dir)
    _write_config(
        deny_dir,
        port=DENY_PORT,
        allowed_ips=["203.0.113.9/32"],  # TEST-NET-3, never routable
    )

    # --- allowed app -------------------------------------------------------
    proc = _start(allowed_dir, PORT)
    try:
        status, _, _ = _request("/healthz")
        check("healthz without token returns 200", status == 200, str(status))

        init_body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "smoke", "version": "1"}}}

        status, headers, _ = _request("/mcp", body=init_body)
        check("mcp without token returns 401", status == 401, str(status))
        www_auth = next((v for k, v in headers.items() if k.lower() == "www-authenticate"), "")
        check("401 advertises Bearer", "bearer" in www_auth.lower(), www_auth)

        status, _, _ = _request("/mcp", token="wrong-token", body=init_body)
        check("mcp with wrong token returns 401", status == 401, str(status))

        status, headers, body = _request("/mcp", token=TOKEN, body=init_body)
        session_id = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
        parsed = _json_from_sse(body)
        check("initialize with valid token succeeds", status == 200 and parsed is not None,
              f"status={status} session={bool(session_id)}")

        if session_id:
            _request("/mcp", token=TOKEN,
                     body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                     session_id=session_id)
            status, _, body = _request(
                "/mcp", token=TOKEN,
                body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                session_id=session_id,
            )
            parsed = _json_from_sse(body)
            tools = [t["name"] for t in (parsed or {}).get("result", {}).get("tools", [])]
            expected = {"openhop_stats", "openhop_neighbors", "openhop_recent_packets",
                        "openhop_gps", "openhop_api_read"}
            check("tools/list returns read tools", status == 200 and expected.issubset(set(tools)),
                  f"{len(tools)} tools")
            check("write tools absent in read-only mode",
                  "openhop_send_advert" not in tools and "openhop_set_mode" not in tools)

            status, _, body = _request(
                "/mcp", token=TOKEN,
                body={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "openhop_stats", "arguments": {"summary": True}}},
                session_id=session_id,
            )
            parsed = _json_from_sse(body)
            text = json.dumps(parsed or {})
            check("openhop_stats returns live data", status == 200 and "local_hash" in text, text[:140])
        else:
            check("session id present", False, "no Mcp-Session-Id header")
    finally:
        _stop(proc)

    # --- denied app --------------------------------------------------------
    proc = _start(deny_dir, DENY_PORT)
    try:
        status, _, _ = _request("/healthz", port=DENY_PORT)
        check("healthz from denied IP returns 403", status == 403, str(status))
        status, _, _ = _request("/mcp", port=DENY_PORT, token=TOKEN, body=init_body)
        check("mcp from denied IP returns 403", status == 403, str(status))
    finally:
        _stop(proc)

    print()
    if failures:
        print(f"FAILED {len(failures)} check(s): {failures}")
        return 1
    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
