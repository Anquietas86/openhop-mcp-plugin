"""Install the built wheel on the openHop node via the Repeater plugin API.

Run this ON the node (or via ssh) after copying the wheel and API key to /tmp.
It deliberately prints only status/JSON bodies, never the key.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("OPENHOP_BASE_URL", "http://127.0.0.1:8000")
KEY_FILE = Path(os.environ.get("OPENHOP_KEY_FILE", "/tmp/.pymc_key"))


def _default_wheel() -> str:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from openhop_mcp import __version__

    return f"/tmp/openhop_mcp_plugin-{__version__}-py3-none-any.whl"


WHEEL = os.environ.get("OPENHOP_WHEEL") or _default_wheel()
# Comma-separated CIDRs permitted to reach the MCP endpoint. Override this with
# the address of the host that will connect, e.g. "127.0.0.1/32,192.0.2.10/32".
ALLOWED_IPS = os.environ.get("OPENHOP_ALLOWED_IPS", "127.0.0.1/32,::1/128")


def call(method: str, path: str, payload: dict | None = None, timeout: float = 300.0):
    key = KEY_FILE.read_text().strip()
    headers = {"X-API-Key": key, "Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        with contextlib.suppress(json.JSONDecodeError):
            body = json.loads(body)
        return exc.code, body


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "install"

    if action == "install":
        status, body = call("POST", "/api/plugins/install", {"wheel_path": WHEEL})
        print("install:", status, json.dumps(body, indent=2))
        return 0 if status == 200 else 1

    if action == "list":
        status, body = call("GET", "/api/plugins/")
        print("list:", status, json.dumps(body, indent=2))
        return 0 if status == 200 else 1

    if action == "configure":
        api_key = KEY_FILE.read_text().strip()
        settings = {
            "id": "openhop.mcp",
            "restart": False,
            "config": {
                "host": "0.0.0.0",
                "port": 8765,
                "openhop_base_url": "http://127.0.0.1:8000",
                "openhop_api_key": api_key,
                "auth_tokens": [],
                "allowed_ips": [ip.strip() for ip in ALLOWED_IPS.split(",") if ip.strip()],
                "read_only": True,
                "request_timeout_seconds": 15,
                "max_items": 200,
                "allow_insecure_bind": True,
            },
        }
        status, body = call("POST", "/api/plugins/settings", settings)
        print("configure:", status, json.dumps(body, indent=2))
        return 0 if status == 200 else 1

    if action == "enable":
        status, body = call("POST", "/api/plugins/enable", {"id": "openhop.mcp"})
        print("enable:", status, json.dumps(body, indent=2))
        return 0 if status == 200 else 1

    if action == "status":
        status, body = call("GET", "/api/plugins/openhop.mcp")
        print("status:", status, json.dumps(body, indent=2))
        return 0 if status == 200 else 1

    if action == "logs":
        status, body = call("GET", "/api/plugins/logs?id=openhop.mcp&tail=120")
        print("logs:", status, json.dumps(body, indent=2)[:8000])
        return 0 if status == 200 else 1

    print(f"unknown action: {action}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
