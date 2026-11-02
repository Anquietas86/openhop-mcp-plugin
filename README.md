# openHop MCP Server plugin

An [openHop Repeater](https://github.com/openhop-dev/openhop_repeater) plugin that
exposes mesh telemetry as a [Model Context Protocol](https://modelcontextprotocol.io)
server over Streamable HTTP.

Installs entirely locally — no catalogue submission or PR required. See the
upstream guide: "You can upload a wheel to your own test installation without a
catalogue listing or PR."

## Security model

The MCP endpoint is protected by **two independent, fail-closed controls**:

1. **Source IP allowlist** — the TCP peer address must fall inside a configured
   CIDR. Requests from anywhere else get `403`.
2. **Bearer token with role** — every request needs `Authorization: Bearer <token>`
   (or `X-Auth-Token: <token>`). Missing or wrong tokens get `401`.

`GET /healthz` is exempt from the token check but still requires an allowed
source address. It returns only `{"status":"ok"}`.

### Multiple keys and roles

You can issue several tokens, each with a name and a role:

- **`read`** — telemetry tools only. This is what a dashboard, Grafana, or an
  AI assistant should use.
- **`admin`** — telemetry plus mutating tools. Only granted when `read_only` is
  `false`.

Role enforcement happens per request inside the plugin. A `read` token cannot
call a write tool even if the tool is registered — the handler returns a
permission error without touching the Repeater API. Call `openhop_whoami` to see
which identity and role a token has.

The plugin stores token hashes nowhere; it compares against the configured
values in constant time. Use `auth_tokens` for the multi-key form. The legacy
single `auth_token` string still works and is treated as one `admin` token named
`legacy`, so existing deployments upgrade without changes.

Additional guardrails:

- Binding to a non-loopback address requires `allow_insecure_bind: true`, so a
  careless edit cannot quietly expose the plugin to the LAN.
- An empty or `0.0.0.0/0` allowlist is rejected unless the same flag is set.
- If no token is configured, the plugin generates a random admin token on first
  start and writes it to `<plugin data>/auth_token.txt` with mode `0600`.
- Tokens shorter than 16 characters and duplicate token values are rejected at
  startup.
- Failed authentication is throttled per source IP: 10 failures inside 5 minutes
  triggers a 15-minute lockout (`429` with `Retry-After`). A successful request
  clears the counter.
- The Repeater API key is never logged or forwarded to clients.
- Read-only mode defaults to **true**. Write tools are not even registered unless
  the operator sets `read_only: false`.

Note: openHop plugin API tokens are administrator-equivalent. The plugin needs
one to read most endpoints. Treat its config file accordingly.

## Configuration

The plugin manager seeds `config.json` in the plugin's persistent data directory
from the manifest defaults. Edit it via the Repeater's Plugins page or
`POST /api/plugins/settings`, then restart the plugin.

| Key | Default | Notes |
| --- | --- | --- |
| `host` | `127.0.0.1` | Bind address. Non-loopback needs `allow_insecure_bind`. |
| `port` | `8765` | MCP endpoint port. |
| `openhop_base_url` | `http://127.0.0.1:8000` | Repeater REST API base URL. |
| `openhop_api_key` | `""` | Repeater `X-API-Key`. Falls back to `OPENHOP_API_KEY` env var. |
| `auth_token` | `""` | Bearer token clients must present. Empty = generated and persisted. |
| `allowed_ips` | `["127.0.0.1/32","::1/128"]` | CIDRs allowed to connect. |
| `read_only` | `true` | When false, advert/mode tools are registered. |
| `request_timeout_seconds` | `15` | Upstream request timeout. |
| `max_items` | `200` | Hard cap for list-returning tools. |
| `allow_insecure_bind` | `false` | Acknowledge LAN exposure / wide allowlists. |
| `max_auth_failures` | `10` | Failed auth attempts allowed per source IP within the window. |
| `auth_failure_window_seconds` | `300` | Sliding window for counting failures. |
| `auth_lockout_seconds` | `900` | Lockout duration once the failure limit is hit. |

After changing config, restart the plugin (settings writes with `restart: true`
do this automatically).

## Tools

| Tool | Purpose |
| --- | --- |
| `openhop_stats` | System overview (or full stats with `summary=false`). |
| `openhop_neighbors` | Neighbour list, optional zero-hop filter and sorting. |
| `openhop_recent_packets` | Recent packets with type/route filters. |
| `openhop_packet_stats` | Packet counters for N hours. |
| `openhop_packet_type_stats` | Counts grouped by packet type. |
| `openhop_route_stats` | Counts grouped by route type. |
| `openhop_noise_floor` | Noise floor statistics. |
| `openhop_gps` | GPS diagnostics and NMEA attributes. |
| `openhop_hardware` | Host CPU/RAM/disk/temperature stats. |
| `openhop_api_read` | Constrained GET against an allowlisted `/api/` path. |
| `openhop_send_advert` | *Write, only when `read_only=false`.* |
| `openhop_set_mode` | *Write, only when `read_only=false`.* |

## Client configuration

Point an MCP client at `http://<host>:<port>/mcp` and send the bearer token in the
`Authorization` header. Example for an MCP client that accepts headers:

```json
{
  "mcpServers": {
    "openhop": {
      "type": "streamable-http",
      "url": "http://<repeater-host>:8765/mcp",
      "headers": { "Authorization": "Bearer <token-from-auth_token.txt>" }
    }
  }
}
```

## Install locally

```bash
python -m build --wheel
curl -X POST -H "X-API-Key: $OPENHOP_API_KEY" \
  -F "wheel=@dist/openhop_mcp_plugin-0.1.0-py3-none-any.whl" \
  http://127.0.0.1:8000/api/plugins/install
```

Or with a host path:

```bash
curl -X POST -H "X-API-Key: $OPENHOP_API_KEY" -H "Content-Type: application/json" \
  -d '{"wheel_path":"/tmp/openhop_mcp_plugin-0.1.0-py3-none-any.whl"}' \
  http://127.0.0.1:8000/api/plugins/install
```

Then enable and start:

```bash
curl -X POST -H "X-API-Key: $OPENHOP_API_KEY" -H "Content-Type: application/json" \
  -d '{"id":"openhop.mcp"}' http://127.0.0.1:8000/api/plugins/enable
```

Check logs:

```bash
curl -H "X-API-Key: $OPENHOP_API_KEY" \
  "http://127.0.0.1:8000/api/plugins/logs?id=openhop.mcp&tail=100"
```

## Development

```bash
uv venv --python python3 .venv
uv pip install --python .venv/bin/python build setuptools wheel
.venv/bin/python -m build --wheel
```

Validate the wheel against the real Repeater parser without starting Repeater:

```bash
git clone --no-checkout https://github.com/openhop-dev/openhop_repeater.git repeater-source
git -C repeater-source checkout --detach <baseline-sha>
PYTHONPATH="$PWD/repeater-source" .venv/bin/python validate_wheel.py
```
