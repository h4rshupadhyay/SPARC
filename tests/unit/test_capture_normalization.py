"""Scalar normalization contract for default PyShark XML packets."""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import FrozenInstanceError
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest


def _capture():
    from sparc.traffic.capture import normalize_packet

    return normalize_packet


def _packet(**overrides):
    values = dict(
        number="7",
        sniff_timestamp="0001.123456789012345678900",
        captured_length="60",
        length="60",
        highest_layer="FRAME",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _row(**packet_overrides):
    return _capture()(_packet(**packet_overrides))


def _assert_parse_error(packet, field=None):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        _capture()(packet)
    assert caught.value.code == "capture_parse_failed"
    assert caught.value.message.startswith(("Invalid capture field:", "Could not read capture field:"))
    if field:
        assert field in caught.value.message
    return caught.value.message


def _xml_layer(name, fields):
    layer = ET.Element("proto", {"name": name})
    for field_name, shown in fields:
        ET.SubElement(layer, "field", {"name": f"{name}.{field_name}", "show": shown, "value": "raw"})
    from pyshark.packet.layers.xml_layer import XmlLayer

    return XmlLayer(layer)


def test_missing_layers_normalize_to_none():
    class FrameOnly:
        number = "7"
        sniff_timestamp = "0001.123456789012345678900"
        captured_length = "60"
        length = "60"
        highest_layer = "FRAME"

        @property
        def sniff_time(self):
            raise AssertionError("sniff_time accessed")

    packet = FrameOnly()
    row = _capture()(packet)
    assert (row.number, row.timestamp, row.captured_length, row.wire_length) == (
        7, "0001.123456789012345678900", 60, 60
    )
    assert row.highest_protocol == "FRAME"
    assert (row.src, row.dst, row.src_port, row.dst_port, row.tcp_stream, row.tcp_flags, row.retransmission) == (
        None, None, None, None, None, None, None
    )


def test_ipv4_ipv6_tcp_udp_fields():
    cases = [
        (_packet(ip=SimpleNamespace(src="192.0.2.1", dst="192.0.2.2"),
                 tcp=SimpleNamespace(srcport="123", dstport="443", stream="4", flags="0x0010",
                                     field_names=[]), highest_layer="TLS"),
         ("192.0.2.1", "192.0.2.2", 123, 443, 4, "0x0010", None, "TLS")),
        (_packet(ipv6=SimpleNamespace(src="2001:db8::1", dst="2001:db8::2"),
                 udp=SimpleNamespace(srcport="53", dstport="0"), highest_layer="UDP"),
         ("2001:db8::1", "2001:db8::2", 53, 0, None, None, None, "UDP")),
        (_packet(arp=SimpleNamespace(src="ignored")),
         (None, None, None, None, None, None, None, "FRAME")),
        (_packet(tcp=SimpleNamespace(srcport="9", dstport=None, stream=None, flags=None, field_names=[])),
         (None, None, 9, None, None, None, None, "FRAME")),
    ]
    for packet, expected in cases:
        row = _capture()(packet)
        assert (row.src, row.dst, row.src_port, row.dst_port, row.tcp_stream,
                row.tcp_flags, row.retransmission, row.highest_protocol) == expected

    # Real PyShark XML layer objects exercise its public sanitized fields and
    # first-value behavior, including a present label with an empty display.
    from pyshark.packet.packet import Packet

    frame = _xml_layer("frame", [("number", "7"), ("time_epoch", "1.25"), ("cap_len", "60"), ("len", "60")])
    ip = _xml_layer("ip", [("src", "192.0.2.10"), ("src", "192.0.2.11"), ("dst", "192.0.2.20")])
    tcp = _xml_layer("tcp", [("srcport", "0"), ("dstport", "65535"), ("stream", "0"),
                              ("flags", "0x0002"), ("analysis_retransmission", "")])
    real_packet = Packet(layers=[frame, ip, tcp], frame_info=frame, number=None,
                         length=None, captured_length=None, sniff_time=None)
    row = _capture()(real_packet)
    assert (row.src, row.dst, row.src_port, row.dst_port, row.tcp_stream, row.tcp_flags, row.retransmission) == (
        "192.0.2.10", "192.0.2.20", 0, 65535, 0, "0x0002", True
    )

    both = _packet(ip=SimpleNamespace(src="v4", dst=None), ipv6=SimpleNamespace(src="v6", dst="v6dst"),
                   tcp=SimpleNamespace(srcport=None, dstport="8", stream=None, flags=None, field_names=[]),
                   udp=SimpleNamespace(srcport="99", dstport="100"))
    row = _capture()(both)
    assert (row.src, row.dst, row.src_port, row.dst_port) == ("v4", None, None, 8)


def test_frame_source_precedence_and_fallback():
    fallback = SimpleNamespace(number="90", time_epoch="9.5", cap_len="900", len="901")
    row = _capture()(_packet(number="1", sniff_timestamp="2.00", captured_length="3", length="4",
                              frame_info=fallback))
    assert (row.number, row.timestamp, row.captured_length, row.wire_length) == (1, "2.00", 3, 4)
    row = _capture()(_packet(number=None, sniff_timestamp=None, captured_length=None, length=None, frame_info=fallback))
    assert (row.number, row.timestamp, row.captured_length, row.wire_length) == (90, "9.5", 900, 901)
    assert "captured_length" in _assert_parse_error(
        _packet(captured_length="bad", frame_info=SimpleNamespace(cap_len="5")), "captured_length"
    )
    assert "number" in _assert_parse_error(_packet(number=None), "number")


@pytest.mark.parametrize("field,packet_field", [("captured_length", "captured_length"), ("wire_length", "length")])
@pytest.mark.parametrize("bad", [-1, True, 1.5, "-1", "1.0", "0x10", " 1", "", None])
def test_invalid_frame_lengths_rejected(field, packet_field, bad):
    fallback_field = "cap_len" if packet_field == "captured_length" else "len"
    frame = SimpleNamespace(number="1", time_epoch="1", cap_len="1", len="1")
    if bad is None:
        setattr(frame, fallback_field, None)
    message = _assert_parse_error(_packet(**{packet_field: bad, "frame_info": frame}), field)
    if str(bad):
        assert str(bad) not in message


@pytest.mark.parametrize("field,value", [("number", True), ("number", -1)])
def test_invalid_required_number(field, value):
    assert field in _assert_parse_error(_packet(**{field: value}), field)


@pytest.mark.parametrize("stream", [True, -1])
def test_invalid_stream(stream):
    tcp = SimpleNamespace(srcport=None, dstport=None, stream=stream, flags=None, field_names=[])
    assert "tcp.stream" in _assert_parse_error(_packet(tcp=tcp), "tcp.stream")


@pytest.mark.parametrize("field,packet_field", [
    ("number", "number"),
    ("captured_length", "captured_length"),
    ("wire_length", "length"),
    ("tcp.stream", "tcp.stream"),
])
@pytest.mark.parametrize("as_text", [False, True])
def test_integer_fields_above_signed_64_bit_range_rejected(field, packet_field, as_text):
    value = 2**63 if not as_text else str(2**63)
    if packet_field == "tcp.stream":
        tcp = SimpleNamespace(srcport=None, dstport=None, stream=value, flags=None, field_names=[])
        packet = _packet(tcp=tcp)
    else:
        packet = _packet(**{packet_field: value})
    _assert_parse_error(packet, field)


@pytest.mark.parametrize("field,packet_field", [
    ("number", "number"),
    ("captured_length", "captured_length"),
    ("wire_length", "length"),
    ("tcp.stream", "tcp.stream"),
])
def test_signed_64_bit_maximum_is_valid_for_integer_fields(field, packet_field):
    value = 2**63 - 1
    if packet_field == "tcp.stream":
        tcp = SimpleNamespace(srcport=None, dstport=None, stream=value, flags=None, field_names=[])
        packet = _packet(tcp=tcp)
    else:
        packet = _packet(**{packet_field: value})
    row = _capture()(packet)
    expected = {
        "number": row.number,
        "captured_length": row.captured_length,
        "wire_length": row.wire_length,
        "tcp.stream": row.tcp_stream,
    }[field]
    assert expected == value


def test_extremely_long_integer_uses_safe_parse_error_without_echoing_input():
    value = "9" * 5000
    message = _assert_parse_error(_packet(number=value), "number")
    assert value not in message


def test_extremely_long_leading_zero_number_is_accepted():
    assert _row(number="0" * 5000 + "7").number == 7


@pytest.mark.parametrize("field", ["number", "highest_layer"])
def test_sparc_error_from_packet_property_is_wrapped(field):
    from sparc.models import SparcError

    class BadPacket:
        number = "1"
        sniff_timestamp = "1"
        captured_length = "1"
        length = "1"

        @property
        def number(self):
            if field == "number":
                raise SparcError("unsafe_code", "sentinel")
            return "1"

        @property
        def highest_layer(self):
            if field == "highest_layer":
                raise SparcError("unsafe_code", "sentinel")
            return "FRAME"

    message = _assert_parse_error(BadPacket())
    assert "sentinel" not in message


@pytest.mark.parametrize("port", [-1, 65536, True])
def test_invalid_ports(port):
    tcp = SimpleNamespace(srcport=port, dstport=None, stream=None, flags=None, field_names=[])
    assert "tcp.srcport" in _assert_parse_error(_packet(tcp=tcp), "tcp.srcport")


def test_port_zero_is_valid():
    tcp = SimpleNamespace(srcport="0", dstport=0, stream="0", flags=None, field_names=[])
    row = _capture()(_packet(tcp=tcp))
    assert (row.src_port, row.dst_port, row.tcp_stream) == (0, 0, 0)


@pytest.mark.parametrize("timestamp", ["000000000000.123456789012345678901234", "-000.000", "0"])
def test_timestamp_text_is_exact_and_validated(timestamp):
    assert _row(sniff_timestamp=timestamp).timestamp == timestamp


@pytest.mark.parametrize("timestamp", [1, 1.0, True, "NaN", "Infinity", "1e3", " 1", "1 ", "+1", ".1", "1.", ""])
def test_bad_timestamp_text_rejected(timestamp):
    assert "timestamp" in _assert_parse_error(_packet(sniff_timestamp=timestamp), "timestamp")


@pytest.mark.parametrize("marker", ["analysis_retransmission", "analysis_fast_retransmission", "analysis_spurious_retransmission"])
@pytest.mark.parametrize("display", ["", "0", None])
def test_retransmission_marker_presence(marker, display):
    tcp = SimpleNamespace(srcport=None, dstport=None, stream=None, flags=None, field_names=[marker], **{marker: display})
    row = _capture()(_packet(tcp=tcp))
    assert row.retransmission is True


def test_retransmission_unrelated_and_safe_errors():
    for names in ([], ["analysis_out_of_order", "analysis_lost_segment", "analysis_duplicate_ack"]):
        row = _capture()(_packet(tcp=SimpleNamespace(srcport=None, dstport=None, stream=None,
                                                     flags=None, field_names=names)))
        assert row.retransmission is None
    assert _row(highest_layer="").highest_protocol == "FRAME"
    class BadPacket:
        number = "1"
        sniff_timestamp = "1"
        captured_length = "1"
        length = "1"

        @property
        def highest_layer(self):
            raise RuntimeError("secret sentinel")

    msg = _assert_parse_error(BadPacket())
    assert "secret sentinel" not in msg


def test_optional_present_malformed_values_are_errors():
    tcp = SimpleNamespace(srcport="", dstport=None, stream=None, flags=None, field_names=[])
    assert "tcp.srcport" in _assert_parse_error(_packet(tcp=tcp), "tcp.srcport")
    ip = SimpleNamespace(src=" 192.0.2.1", dst=None)
    assert "ip.src" in _assert_parse_error(_packet(ip=ip), "ip.src")


def test_normalization_module_does_not_import_pyshark():
    code = (
        "import sys; import sparc.traffic.models; import sparc.traffic.capture; "
        "assert not any(name == 'pyshark' or name.startswith('pyshark.') for name in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=Path(__file__).resolve().parents[2])

    from sparc.traffic.models import ConversionResult, PacketRow, TrafficReport

    row = PacketRow(number=1, timestamp="1", captured_length=1, wire_length=1, highest_protocol="FRAME",
                    src=None, dst=None, src_port=None, dst_port=None, tcp_stream=None, tcp_flags=None,
                    retransmission=None)
    with pytest.raises(FrozenInstanceError):
        row.number = 2
    conversion = ConversionResult(complete=False, packet_count=0, elapsed_ns=0, source_bytes=0,
                                  output_bytes=0, packets_s=None, versions={}, metadata={})
    report = TrafficReport(metadata={}, packet_count=0, captured_bytes=0, duration_s=Decimal("0"),
                           captured_bytes_s=Decimal("0"), protocol_counts={}, directional_bytes=[],
                           tcp_conversations=[], packet_size_distribution={}, retransmission_indications=0,
                           conversion=conversion)
    assert report.packet_count == 0
