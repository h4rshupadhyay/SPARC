"""Real decoder agreement and analysis-only temporary artifact ownership."""

from decimal import Decimal
import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import xml.etree.ElementTree as ET

import pytest

from sparc.models import SparcError
from sparc.traffic.capture import find_tshark
from sparc.traffic.pdml import export_xml


pytestmark = pytest.mark.tshark
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SOURCE = FIXTURES / "traffic-small.pcap"


def _tool():
    try:
        explicit = os.environ.get("SPARC_TEST_TSHARK")
        return find_tshark(Path(explicit) if explicit else None)
    except SparcError as error:
        if error.code == "tshark_missing":
            pytest.skip("TShark executable unavailable")
        raise


def test_fixture_exports_agree_with_source(tmp_path):
    from sparc.traffic.sqlite_index import import_sqlite
    tool = _tool()
    manifest = json.loads((FIXTURES / "traffic-small-manifest.json").read_text())
    original = (SOURCE.read_bytes(), SOURCE.stat().st_mode)
    database, xml = tmp_path / "index.sqlite", tmp_path / "details.xml"
    report = import_sqlite(SOURCE, database, tool, Event())
    converted = export_xml(SOURCE, xml, tool, Event())
    assert report.packet_count == converted.packet_count == manifest["packet_count"] == 5
    assert report.captured_bytes == 262
    assert report.duration_s == Decimal("4")
    assert report.captured_bytes_s == Decimal("65.5")
    assert report.conversion.source_bytes == converted.source_bytes == 366
    assert report.conversion.output_bytes == database.stat().st_size
    assert converted.output_bytes == xml.stat().st_size
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        rows = connection.execute("SELECT number,timestamp,captured_length,wire_length,src,dst,src_port,dst_port FROM packets ORDER BY number").fetchall()
        for actual, expected in zip(rows, manifest["packets"], strict=True):
            number, timestamp, length, wire, src, dst, sport, dport = actual
            assert number == expected["number"]
            assert Decimal(timestamp) == Decimal(expected["timestamp"])
            assert (length, wire, src, dst, sport, dport) == tuple(expected[key] for key in ("captured_length", "wire_length", "src", "dst", "src_port", "dst_port"))
        assert connection.execute("SELECT src,dst,src_port,dst_port,tcp_stream,tcp_flags,retransmission FROM packets WHERE number=4").fetchone() == (None,) * 7
        metadata = {key: json.loads(value) for key, value in connection.execute("SELECT key,value FROM metadata")}
        assert metadata["complete"] is True
        assert metadata["source_sha256"] == manifest["source_sha256"]
    packets = ET.parse(xml).getroot().findall("packet")
    assert len(packets) == 5
    for packet, expected in zip(packets, manifest["packets"], strict=True):
        fields = {field.get("name"): field.get("show") for field in packet.iter("field")}
        assert int(fields["frame.number"]) == expected["number"]
        assert int(fields["frame.cap_len"]) == expected["captured_length"]
        assert Decimal(fields["frame.time_epoch"]) == Decimal(expected["timestamp"])
        if expected["src"] is not None:
            prefix = "ipv6" if ":" in expected["src"] else "ip"
            transport = expected["protocol"].lower()
            assert fields[f"{prefix}.src"] == expected["src"]
            assert fields[f"{prefix}.dst"] == expected["dst"]
            assert int(fields[f"{transport}.srcport"]) == expected["src_port"]
            assert int(fields[f"{transport}.dstport"]) == expected["dst_port"]
    assert (SOURCE.read_bytes(), SOURCE.stat().st_mode) == original
    assert hashlib.sha256(original[0]).hexdigest() == manifest["source_sha256"]


@pytest.mark.parametrize("outcome", ["success", "cancel", "summary_error", "cleanup_error"])
def test_analysis_temp_index_cleanup(tmp_path, monkeypatch, outcome):
    module = importlib.import_module("sparc.traffic.sqlite_index")
    analyze = getattr(module, "analyze_capture", None)
    assert callable(analyze), "analysis-only facade is not implemented"
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    if outcome == "success":
        report = analyze(SOURCE, _tool(), Event())
        assert report.packet_count == 5
        assert report.conversion.output_bytes > 0
        assert report.metadata["artifact_retained"] is False
        assert report.metadata["measurement_scope"] == "analysis_temporary_index"
    else:
        code = {"cancel": "capture_cancelled", "summary_error": "traffic_summary_failed", "cleanup_error": "capture_cleanup_failed"}[outcome]
        def fail(source, destination, *args, **kwargs):
            destination.write_bytes(b"owned incomplete index")
            raise SparcError(code, "safe failure")
        monkeypatch.setattr(module, "import_sqlite", fail)
        with pytest.raises(SparcError) as caught:
            analyze(SOURCE, Path("unused"), Event())
        assert caught.value.code == code
    assert list(tmp_path.iterdir()) == []


def test_filtered_index_labels_filter_and_pdml_is_unfiltered(tmp_path):
    from sparc.traffic.sqlite_index import import_sqlite
    tool = _tool()
    report = import_sqlite(SOURCE, tmp_path / "index.sqlite", tool, Event(), "tcp.port == 47655")
    converted = export_xml(SOURCE, tmp_path / "details.xml", tool, Event())
    assert report.packet_count == 2
    assert report.captured_bytes == 108
    assert report.duration_s == Decimal("1")
    assert report.captured_bytes_s == Decimal("108")
    assert report.metadata["display_filter"] == "tcp.port == 47655"
    assert converted.packet_count == 5
    assert converted.metadata["display_filter"] is None
    assert report.metadata["source_sha256"] == converted.metadata["source_sha256"]
