"""Build the small deterministic Ethernet PCAP used by capture integration tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


_SOURCE_MAC = bytes.fromhex("020000000001")
_PEER_MAC = bytes.fromhex("020000000002")
_IPV4_SOURCE = bytes((10, 0, 0, 1))
_IPV4_PEER = bytes((10, 0, 0, 2))
_IPV6_SOURCE = bytes.fromhex("20010db8000000000000000000000001")
_IPV6_PEER = bytes.fromhex("20010db8000000000000000000000002")
_PAYLOAD = b"ABCD"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data) if data else ()
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(destination: bytes, source: bytes, ether_type: int, payload: bytes) -> bytes:
    return destination + source + struct.pack("!H", ether_type) + payload


def _ipv4_packet(protocol: int, payload: bytes, *, identification: int) -> bytes:
    total_length = 20 + len(payload)
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        protocol,
        0,
        _IPV4_SOURCE,
        _IPV4_PEER,
    )
    checksum = _checksum(header_without_checksum)
    header = header_without_checksum[:10] + struct.pack("!H", checksum) + header_without_checksum[12:]
    return header + payload


def _tcp_segment(
    source_port: int,
    destination_port: int,
    *,
    sequence: int,
    acknowledgement: int,
    flags: int,
) -> bytes:
    header_without_checksum = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    pseudo_header = _IPV4_SOURCE + _IPV4_PEER + struct.pack("!BBH", 0, 6, len(header_without_checksum))
    checksum = _checksum(pseudo_header + header_without_checksum)
    return header_without_checksum[:16] + struct.pack("!H", checksum) + header_without_checksum[18:]


def _udp_segment(
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
    payload: bytes,
    *,
    ipv6: bool,
) -> bytes:
    length = 8 + len(payload)
    header_without_checksum = struct.pack("!HHHH", source_port, destination_port, length, 0)
    if ipv6:
        pseudo_header = source + destination + struct.pack("!I3xB", length, 17)
    else:
        pseudo_header = source + destination + struct.pack("!BBH", 0, 17, length)
    checksum = _checksum(pseudo_header + header_without_checksum + payload) or 0xFFFF
    return struct.pack("!HHHH", source_port, destination_port, length, checksum) + payload


def _tcp_frame(*, reverse: bool) -> bytes:
    if reverse:
        source_mac, destination_mac = _PEER_MAC, _SOURCE_MAC
        source_ip, destination_ip = _IPV4_PEER, _IPV4_SOURCE
        source_port, destination_port = 47655, 12345
        identification, sequence, acknowledgement, flags = 2, 2, 2, 0x12
    else:
        source_mac, destination_mac = _SOURCE_MAC, _PEER_MAC
        source_ip, destination_ip = _IPV4_SOURCE, _IPV4_PEER
        source_port, destination_port = 12345, 47655
        identification, sequence, acknowledgement, flags = 1, 1, 0, 0x02

    tcp = _tcp_segment(
        source_port,
        destination_port,
        sequence=sequence,
        acknowledgement=acknowledgement,
        flags=flags,
    )
    if reverse:
        # The TCP checksum pseudo-header follows the packet's reversed IP addresses.
        tcp = _tcp_segment_reversed(source_port, destination_port, sequence, acknowledgement, flags)
    ip = _ipv4_packet(protocol=6, payload=tcp, identification=identification)
    if reverse:
        ip = _ipv4_packet_reversed(tcp, identification)
    return _ethernet(destination_mac, source_mac, 0x0800, ip)


def _tcp_segment_reversed(
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
) -> bytes:
    header_without_checksum = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    pseudo_header = _IPV4_PEER + _IPV4_SOURCE + struct.pack("!BBH", 0, 6, len(header_without_checksum))
    checksum = _checksum(pseudo_header + header_without_checksum)
    return header_without_checksum[:16] + struct.pack("!H", checksum) + header_without_checksum[18:]


def _ipv4_packet_reversed(payload: bytes, identification: int) -> bytes:
    total_length = 20 + len(payload)
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        6,
        0,
        _IPV4_PEER,
        _IPV4_SOURCE,
    )
    checksum = _checksum(header_without_checksum)
    header = header_without_checksum[:10] + struct.pack("!H", checksum) + header_without_checksum[12:]
    return header + payload


def _arp_frame() -> bytes:
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1,
        _SOURCE_MAC,
        _IPV4_SOURCE,
        b"\0" * 6,
        _IPV4_PEER,
    )
    return _ethernet(b"\xff" * 6, _SOURCE_MAC, 0x0806, arp)


def _ipv6_udp_frame() -> bytes:
    udp = _udp_segment(_IPV6_SOURCE, _IPV6_PEER, 3333, 4444, _PAYLOAD, ipv6=True)
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(udp),
        17,
        64,
        _IPV6_SOURCE,
        _IPV6_PEER,
    )
    return _ethernet(_PEER_MAC, _SOURCE_MAC, 0x86DD, header + udp)


def _fixture_packets() -> list[tuple[bytes, dict]]:
    first_tcp = _tcp_frame(reverse=False)
    second_tcp = _tcp_frame(reverse=True)
    udp = _udp_segment(_IPV4_SOURCE, _IPV4_PEER, 1111, 2222, _PAYLOAD, ipv6=False)
    ipv4_udp = _ethernet(
        _PEER_MAC,
        _SOURCE_MAC,
        0x0800,
        _ipv4_packet(protocol=17, payload=udp, identification=3),
    )
    return [
        (first_tcp, {"number": 1, "timestamp": "1", "protocol": "TCP", "src": "10.0.0.1", "dst": "10.0.0.2", "src_port": 12345, "dst_port": 47655}),
        (second_tcp, {"number": 2, "timestamp": "2", "protocol": "TCP", "src": "10.0.0.2", "dst": "10.0.0.1", "src_port": 47655, "dst_port": 12345}),
        (ipv4_udp, {"number": 3, "timestamp": "3", "protocol": "UDP", "src": "10.0.0.1", "dst": "10.0.0.2", "src_port": 1111, "dst_port": 2222}),
        (_arp_frame(), {"number": 4, "timestamp": "4", "protocol": "ARP", "src": None, "dst": None, "src_port": None, "dst_port": None}),
        (_ipv6_udp_frame(), {"number": 5, "timestamp": "5", "protocol": "UDP", "src": "2001:db8::1", "dst": "2001:db8::2", "src_port": 3333, "dst_port": 4444}),
    ]


def build_fixture(destination: Path) -> dict:
    """Write a deterministic five-packet little-endian PCAP and its JSON manifest."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    packets = _fixture_packets()
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    manifest_packets = []
    byte_total = 0
    for index, (frame, metadata) in enumerate(packets, start=1):
        output.extend(struct.pack("<IIII", index, 0, len(frame), len(frame)))
        output.extend(frame)
        byte_total += len(frame)
        manifest_packets.append(
            {
                **metadata,
                "captured_length": len(frame),
                "wire_length": len(frame),
            }
        )

    capture_bytes = bytes(output)
    destination.write_bytes(capture_bytes)
    manifest = {
        "packet_count": len(packets),
        "source_bytes": len(capture_bytes),
        "source_sha256": hashlib.sha256(capture_bytes).hexdigest(),
        "captured_bytes": byte_total,
        "wire_bytes": byte_total,
        "packets": manifest_packets,
    }
    manifest_path = destination.with_name(f"{destination.stem}-manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
