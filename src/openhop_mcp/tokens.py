"""``openhop-mcp-token``: mint, hash and rotate MCP bearer tokens.

The plugin only ever needs a token's SHA-256 digest. Minting prints the
plaintext once (hand it to the client) and an ``auth_tokens`` entry holding
only the digest (paste it into the plugin config). The config file then holds
nothing an attacker could replay.

Rotation is: mint a new token under the same name, swap the config entry,
restart the plugin, update the client. The old token stops working on restart.

Examples::

    openhop-mcp-token mint --name grafana --role read
    echo -n "$TOKEN" | openhop-mcp-token hash
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys

from .config import MIN_TOKEN_LENGTH
from .security import ROLES, hash_token

TOKEN_BYTES = 32


def mint(name: str, role: str) -> dict[str, object]:
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return {
        "token": token,
        "config_entry": {"name": name, "role": role, "token_sha256": hash_token(token)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="openhop-mcp-token",
        description="Mint or hash bearer tokens for the openHop MCP plugin.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    mint_p = sub.add_parser("mint", help="generate a new random token")
    mint_p.add_argument("--name", required=True, help="label shown in logs and openhop_whoami")
    mint_p.add_argument("--role", choices=sorted(ROLES), default="read")

    sub.add_parser("hash", help="print the token_sha256 for a token read from stdin")

    args = parser.parse_args(argv)

    if args.command == "mint":
        result = mint(args.name, args.role)
        print("Token (give this to the MCP client; it is not stored anywhere):", file=sys.stderr)
        print(result["token"])
        print("\nAdd this entry to auth_tokens in the plugin config:", file=sys.stderr)
        print(json.dumps(result["config_entry"], indent=2))
        return 0

    token = sys.stdin.read().strip()
    if len(token) < MIN_TOKEN_LENGTH:
        print(f"token must be at least {MIN_TOKEN_LENGTH} characters", file=sys.stderr)
        return 1
    print(hash_token(token))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
