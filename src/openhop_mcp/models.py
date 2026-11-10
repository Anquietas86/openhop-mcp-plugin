"""Typed tool outputs.

Returning these models (instead of ``dict[str, Any]``) gives MCP clients an
``outputSchema`` for each tool and ``structuredContent`` in each result, so a
client can validate and use fields directly instead of parsing text.

Fields mirror what the Repeater returns. Everything except counts is optional,
because Repeater versions differ in what they report.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class WhoAmI(_Model):
    name: str
    role: Literal["read", "admin"] | str


class GpsFix(_Model):
    fix: Any = None
    latitude: float | None = None
    longitude: float | None = None
    satellites: int | None = None


class StatsSummary(_Model):
    local_hash: str | None = None
    node_name: str | None = None
    mode: str | None = None
    version: str | None = None
    core_version: str | None = None
    uptime_seconds: float | None = None
    rx_count: int | None = None
    forwarded_count: int | None = None
    dropped_count: int | None = None
    rx_per_hour: int | None = None
    forwarded_per_hour: int | None = None
    noise_floor_dbm: float | None = None
    crc_error_count: int | None = None
    max_airtime_percent: float | None = None
    duty_cycle_enforced: bool | None = None
    neighbor_count: int = 0
    recent_packet_count: int = 0
    gps: GpsFix = Field(default_factory=GpsFix)


class Neighbor(_Model):
    pubkey: str | None = None
    node_name: str | None = None
    contact_type: Any = None
    is_repeater: bool | None = None
    route_type: Any = None
    zero_hop: bool | None = None
    rssi: float | None = None
    snr: float | None = None
    advert_count: int | None = None
    last_seen: float | None = None
    first_seen: float | None = None
    latitude: float | None = None
    longitude: float | None = None


class NeighborList(_Model):
    count: int
    returned: int
    neighbors: list[Neighbor]


class Packet(_Model):
    id: int | None = None
    timestamp: float | None = None
    type: int | None = None
    route: int | None = None
    rssi: float | None = None
    snr: float | None = None
    is_duplicate: bool | int | None = None
    drop_reason: str | None = None
    packet_hash: str | None = None
    payload_length: int | None = None
    original_path: Any = None
    forwarded_path: Any = None
    transmitted: bool | int | None = None
    airtime_ms: float | None = None


class PacketList(_Model):
    count: int
    packets: list[Packet]
    source: Literal["api", "database"]
    fallback_error: str | None = None


class LogEntry(_Model):
    id: int | None = None
    timestamp: Any = None
    level: str | None = None
    logger: str | None = None
    message: str | None = None


class LogList(_Model):
    count: int
    returned: int
    logs: list[LogEntry]


class Process(_Model):
    pid: int | None = None
    name: str | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    memory_mb: float | None = None


class ProcessList(_Model):
    count: int
    returned: int
    processes: list[Process]


class Broker(_Model):
    name: str | None = None
    host: str | None = None
    enabled: bool | None = None
    connected: bool | None = None
    reconnecting: bool | None = None
    format: str | None = None
    neighbors: Any = None


class MqttStatus(_Model):
    handler_active: bool | None = None
    broker_count: int
    brokers: list[Broker]


class Frontend(_Model):
    id: str | None = None
    kind: str | None = None
    name: str | None = None
    version: str | None = None
    available: bool | None = None
    enabled: bool | None = None
    selected: bool | None = None


class FrontendList(_Model):
    count: int
    selected: Any = None
    frontends: list[Frontend]


class ChannelInfo(_Model):
    name: str
    indices: list[int | None]
    companions: list[str | None]


class ChannelList(_Model):
    count: int
    channels: list[ChannelInfo]


class ChannelMessage(_Model):
    channel: str
    device_timestamp: int
    logged_at: float | None = None
    timestamp_bogus: bool
    sender: str
    message: str
    packet_id: int | None = None


class ChannelMessages(_Model):
    channel: str
    days: float
    scanned_packets: int
    unique_messages: int
    returned: int
    truncated: bool
    messages: list[ChannelMessage]


# -- analysis -----------------------------------------------------------------


class Distribution(_Model):
    mean: float | None = None
    median: float | None = None
    min: float | None = None
    max: float | None = None
    stdev: float | None = None
    mad: float | None = None


class LinkSnapshot(_Model):
    peer_hash: str | None = None
    path_hash_size: int | None = None
    sample_count: int | None = None
    duplicate_sample_count: int | None = None
    last_seen: float | None = None
    age_seconds: float | None = None
    active: bool | None = None
    last_rssi: float | None = None
    last_snr: float | None = None
    ewma_rssi: float | None = None
    ewma_snr: float | None = None
    ewma_score: float | None = None


class LinkQuality(_Model):
    peer_hash: str | None = None
    path_hash_size: int | None = None
    hours: int
    observations: int = 0
    per_hour: float | None = None
    duplicate_ratio: float | None = None
    rssi: Distribution = Field(default_factory=Distribution)
    snr: Distribution = Field(default_factory=Distribution)
    snr_trend_db: float | None = None
    trend: str = "insufficient data"
    largest_gap_seconds: float | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    mean_path_hops: float | None = None
    links: list[LinkSnapshot] | None = Field(
        default=None, description="Present when no peer_hash was given: candidate links to pick from."
    )


class AirtimeHeadroom(_Model):
    hours: float
    buckets: int
    bucket_seconds: float
    tx_percent: Distribution
    rx_percent: Distribution
    channel_busy_percent_mean: float | None = None
    max_airtime_percent: float | None = None
    peak_headroom_percent: float | None = None
    buckets_near_limit: int | None = None
    buckets_over_limit: int | None = None
    status: str
    radio: dict[str, int] = Field(default_factory=dict)


class NoiseEvent(_Model):
    start: float
    end: float
    direction: Literal["high", "low"]
    samples: int
    peak_dbm: float
    peak_delta_db: float


class NoiseAnomalies(_Model):
    hours: int
    samples: int
    baseline: Distribution
    event_count: int
    events: list[NoiseEvent]
    note: str | None = None
