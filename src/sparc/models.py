"""Immutable records shared by SPARC modules."""

from dataclasses import dataclass
from enum import Enum
import math
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


class Role(str, Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


class SparcError(Exception):
    """Domain error with a stable public category."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", code) is None:
            raise ValueError("code must be a nonempty snake_case category")
        if not isinstance(message, str):
            raise TypeError("message must be a string")
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class Identity:
    private_key: Ed25519PrivateKey
    public_bytes: bytes
    fingerprint: str


@dataclass(frozen=True)
class Timings:
    hash_ns: int | None = None
    sign_ns: int | None = None
    encrypt_ns: int | None = None
    decrypt_ns: int | None = None
    verify_ns: int | None = None


@dataclass(frozen=True)
class Inspection:
    message_id: str
    sequence: int
    sha256: str
    computed_sha256: str | None
    signature: bytes
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    plaintext_bytes: int
    timings: Timings


@dataclass(frozen=True)
class ProtectedRecord:
    frame: bytes
    inspection: Inspection | None = None


@dataclass(frozen=True)
class OpenedRecord:
    payload: dict
    inspection: Inspection | None = None
    sequence: int | None = None
    direction: int | None = None


@dataclass(frozen=True)
class ServiceEvent:
    kind: str
    data: dict


@dataclass(frozen=True)
class DeliveryReceipt:
    message_id: str
    started_ns: int
    finished_ns: int
    plaintext_bytes: int
    characters: int
    frame_bytes: int


@dataclass(frozen=True)
class Limits:
    text_bytes: int = 16384
    handshake_json_bytes: int = 8192
    frame_bytes: int = 131072
    pending_requests: int = 100
    event_queue: int = 1024
    outbound_queue: int = 1024
    control_queue: int = 100
    completed_receipts: int = 100
    chat_history: int = 500
    cancel_poll_seconds: float = 1.0
    hello_timeout_seconds: float = 20.0
    client_auth_timeout_seconds: float = 150.0
    responder_finished_timeout_seconds: float = 150.0
    pairing_timeout_seconds: float = 120.0
    handshake_timeout_seconds: float = 300.0
    client_finished_timeout_seconds: float = 10.0
    frame_timeout_seconds: float = 10.0
    delivery_timeout_seconds: float = 10.0
    connection_window_seconds: float = 60.0
    connections_per_source: int = 20
    connections_global: int = 60
    source_buckets: int = 256
    record_rate: float = 200.0
    record_burst: int = 400
    heartbeat_seconds: float = 5.0
    peer_timeout_seconds: float = 15.0
    reconnect_delays: tuple[float, ...] = (1.0, 2.0, 4.0)
    audit_aggregate_seconds: float = 5.0
    benchmark_records: int = 1000
    benchmark_bytes: int = 16777216
    resource_sample_seconds: float = 1.0

    def __post_init__(self) -> None:
        integer_fields = (
            "text_bytes", "handshake_json_bytes", "frame_bytes", "pending_requests",
            "event_queue", "outbound_queue", "control_queue", "completed_receipts",
            "chat_history", "connections_per_source", "connections_global",
            "source_buckets", "record_burst", "benchmark_records", "benchmark_bytes",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")

        time_fields = (
            "cancel_poll_seconds", "hello_timeout_seconds", "client_auth_timeout_seconds",
            "responder_finished_timeout_seconds", "pairing_timeout_seconds",
            "handshake_timeout_seconds", "client_finished_timeout_seconds",
            "frame_timeout_seconds", "delivery_timeout_seconds", "connection_window_seconds",
            "record_rate", "heartbeat_seconds", "peer_timeout_seconds",
            "audit_aggregate_seconds", "resource_sample_seconds",
        )
        for name in time_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a finite positive number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")

        delays = self.reconnect_delays
        if not isinstance(delays, tuple):
            raise TypeError("reconnect_delays must be a tuple")
        if len(delays) > 3:
            raise ValueError("reconnect_delays may contain at most three attempts")
        for delay in delays:
            if isinstance(delay, bool) or not isinstance(delay, (int, float)):
                raise TypeError("reconnect delays must be finite positive numbers")
            if not math.isfinite(delay) or delay <= 0:
                raise ValueError("reconnect delays must be finite positive numbers")

        if self.cancel_poll_seconds > 1:
            raise ValueError("cancel_poll_seconds must not exceed one second")
        if self.frame_bytes < 58:
            raise ValueError("frame_bytes must fit a nonempty encrypted record")
        if self.handshake_json_bytes >= self.frame_bytes:
            raise ValueError("handshake_json_bytes must be below frame_bytes")
        if self.text_bytes >= self.frame_bytes:
            raise ValueError("text_bytes must be below frame_bytes")
        if self.heartbeat_seconds >= self.peer_timeout_seconds:
            raise ValueError("heartbeat_seconds must be below peer_timeout_seconds")
