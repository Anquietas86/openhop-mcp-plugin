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
values in constant time. Configure all credentials in the `auth_tokens` list;
each entry takes a `name`, a `role` (`read` or `admin`), and a `token`.

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
| `auth_tokens` | `[]` | List of `{name, role, token}` entries. Empty = one admin token generated and persisted. |
| `allowed_ips` | `["127.0.0.1/32","::1/128"]` | CIDRs allowed to connect. |
| `read_only` | `true` | When false, advert/mode tools are registered. |
| `request_timeout_seconds` | `15` | Upstream request timeout. |
| `max_items` | `200` | Hard cap for list-returning tools. |
| `allow_insecure_bind` | `false` | Acknowledge LAN exposure / wide allowlists. |
| `max_auth_failures` | `10` | Failed auth attempts allowed per source IP within the window. |
| `auth_failure_window_seconds` | `300` | Sliding window for counting failures. |
| `auth_lockout_seconds` | `900` | Lockout duration once the failure limit is hit. |
| `repeater_db_path` | `/var/lib/openhop_repeater/repeater.db` | Repeater SQLite database, read-only. |
| `allow_message_history` | `true` | Register the channel-history tools. Content stays admin-only. |

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
| `openhop_logs` | Repeater application logs, filterable by level or id. |
| `openhop_processes` | Host process CPU/memory usage. |
| `openhop_mqtt_status` | MQTT bridge and per-broker connection state. |
| `openhop_web_frontends` | Configured web frontends and selection. |
| `openhop_setup_info` | Radio presets, serial ports, site info, hardware options. |
| `openhop_room_messages` | Room-server messages (not channel chat). |
| `openhop_channels` | Channel names and indices from the Repeater DB. No secrets. |
| `openhop_channel_messages` | *Admin-only.* Decrypted channel history from the Repeater DB (max 90 days per call). |
| `openhop_api_read` | GET against an explicit allowlist of telemetry `/api/` paths. |
| `openhop_whoami` | Name and role of the calling token. |
| `openhop_validate_config` | *Admin-only.* Validate the Repeater's `config.yaml`. |
| `openhop_send_advert` | *Write, admin, only when `read_only=false`.* Transmits an advert. |
| `openhop_set_mode` | *Write, admin, only when `read_only=false`.* `forward`, `monitor` or `no_tx`. |
| `openhop_set_duty_cycle` | *Write, admin, only when `read_only=false`.* |
| `openhop_update_duty_cycle_config` | *Write, admin, only when `read_only=false`.* |
| `openhop_update_advert_rate_limit` | *Write, admin, only when `read_only=false`.* |
| `openhop_publish_neighbors` | *Write, admin, only when `read_only=false`.* |
| `openhop_query_neighbor_scopes` | *Write, admin, only when `read_only=false`.* Queries one zero-hop neighbour over the air. |

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) so clients can tell reads from writes.

`openhop_api_read` only reaches the telemetry paths listed in
`src/openhop_mcp/api_policy.py` (stats, packets, noise floor, airtime, CRC,
neighbour links, rooms, MQTT status and similar). Everything else is refused,
including plugin settings, config export, identity export, transport keys,
auth tokens, companion data, streaming routes, and GET handlers that change
state. Paths containing percent-escapes, dot segments or doubled slashes are
rejected rather than decoded.

## Client configuration

Point an MCP client at `http://<host>:<port>/mcp` and send the bearer token in the
`Authorization` header. Example for an MCP client that accepts headers:

```json
{
  "mcpServers": {
    "openhop": {
      "type": "streamable-http",
      "url": "http://<repeater-host>:8765/mcp",
      "headers": { "Authorization": "Bearer <token-from-auth_tokens>" }
    }
  }
}
```

## Install

### Option 1 — GUI (recommended)

1. Open the Repeater web UI and go to **Plugins**.
2. Click **Install plugin** and choose the built wheel
   (`openhop_mcp_plugin-<version>-py3-none-any.whl`).
3. Open the plugin's settings, fill in `auth_tokens` and `allowed_ips`
   (see [Configuration](#configuration)), then **Enable**.

No shell access needed, and the plugin manager creates and owns its venv.

### Option 2 — CLI / API

Build the wheel first if you have not already:

```bash
python -m build --wheel
```

Then upload it to the node and install by host path:

```bash
curl -X POST -H "X-API-Key: $OPENHOP_API_KEY" -H "Content-Type: application/json" \
  -d '{"wheel_path":"/tmp/openhop_mcp_plugin-<version>-py3-none-any.whl"}' \
  http://127.0.0.1:8000/api/plugins/install
```

Enable and start:

```bash
curl -X POST -H "X-API-Key: $OPENHOP_API_KEY" -H "Content-Type: application/json" \
  -d '{"id":"openhop.mcp"}' http://127.0.0.1:8000/api/plugins/enable
```

Check logs:

```bash
curl -H "X-API-Key: $OPENHOP_API_KEY" \
  "http://127.0.0.1:8000/api/plugins/logs?id=openhop.mcp&tail=100"
```

Installing a new wheel replaces the code but does **not** cycle the running
process — disable then enable the plugin to load the new build.

## Development

```bash
uv venv --python python3 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest -q          # unit tests
.venv/bin/python tests/smoke_test.py   # starts the server and checks the gate end to end
.venv/bin/python -m build --wheel
```

The version lives in one place, `src/openhop_mcp/__init__.py`. Bump
`openhop-plugin.json` to match; `tests/test_version.py` fails if they drift.

Set `OPENHOP_SMOKE_LIVE=1` (and `OPENHOP_BASE_URL` / `OPENHOP_TEST_API_KEY`)
to make the smoke test require live data from a real Repeater.

Validate the wheel against the real Repeater parser without starting Repeater:

```bash
git clone --no-checkout https://github.com/openhop-dev/openhop_repeater.git repeater-source
git -C repeater-source checkout --detach <baseline-sha>
PYTHONPATH="$PWD/repeater-source" .venv/bin/python validate_wheel.py
```
