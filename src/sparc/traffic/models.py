"""Immutable scalar records used by traffic capture analysis."""

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class PacketRow:
    number: int
    timestamp: str
    captured_length: int
    wire_length: int
    highest_protocol: str
    src: str | None
    dst: str | None
    src_port: int | None
    dst_port: int | None
    tcp_stream: int | None
    tcp_flags: str | None
    retransmission: bool | None


@dataclass(frozen=True)
class ConversionResult:
    complete: bool
    packet_count: int
    elapsed_ns: int
    source_bytes: int
    output_bytes: int
    packets_s: float | None
    versions: dict
    metadata: dict


@dataclass(frozen=True)
class TrafficReport:
    metadata: dict
    packet_count: int
    captured_bytes: int
    duration_s: Decimal | None
    captured_bytes_s: Decimal | None
    protocol_counts: dict[str, int]
    directional_bytes: list[dict]
    tcp_conversations: list[dict]
    packet_size_distribution: dict
    retransmission_indications: int
    conversion: ConversionResult
