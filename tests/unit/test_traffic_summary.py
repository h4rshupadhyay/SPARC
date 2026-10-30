"""Exact, bounded summaries of completed traffic indexes."""

from __future__ import annotations

from decimal import Decimal, getcontext
import importlib
import json
from pathlib import Path
import sqlite3
import threading

import pytest


def _modules():
    try:
        summary = importlib.import_module("sparc.traffic.summary")
    except ModuleNotFoundError as error:
        if error.name == "sparc.traffic.summary":
            pytest.fail("T2b traffic summary implementation is not present yet", pytrace=False)
        raise
    index = importlib.import_module("sparc.traffic.sqlite_index")
    return summary, index


def _row(
    number,
    timestamp=None,
    length=60,
    protocol="FRAME",
    src=None,
    dst=None,
    src_port=None,
    dst_port=None,
    stream=None,
    retransmission=None,
):
    from sparc.traffic.models import PacketRow

    return PacketRow(
        number=number,
        timestamp=timestamp if timestamp is not None else f"1700000000.{number:09d}",
        captured_length=length,
        wire_length=length,
        highest_protocol=protocol,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=stream,
        tcp_flags="0x0002" if stream is not None else None,
        retransmission=retransmission,
    )


def _metadata(**changes):
    result = {
        "source_name": "synthetic.pcap",
        "source_sha256": "a" * 64,
        "source_bytes": 366,
        "display_filter": None,
        "versions": {"python": "3.13", "pyshark": "0.6", "tshark": None},
        "evidence_type": "synthetic_fixture",
        "definitions": {
            "index": "query index",
            "timestamps": "exact source epoch text",
            "captured_bytes_s": "included captured bytes over included time interval",
            "retransmissions": "dissector indications",
        },
    }
    result.update(changes)
    return result


def _write(index, rows, path: Path, metadata=None):
    return index._write_index(
        iter(rows), path, _metadata() if metadata is None else metadata, threading.Event()
    )


def _metadata_from(path):
    with sqlite3.connect(path) as db:
        return {key: json.loads(value) for key, value in db.execute("SELECT key, value FROM metadata")}


def _summary(path):
    summary, _ = _modules()
    return summary.summarize_database(path)


@pytest.mark.parametrize(
    "timestamps, expected_duration, expected_rate",
    [
        ([], None, None),
        (["9.0"], None, None),
        (["9.0", "9.0"], Decimal("0"), None),
        (["9.2", "9.1"], Decimal("-0.1"), None),
    ],
)
def test_capture_order_duration_matrix(tmp_path, timestamps, expected_duration, expected_rate):
    _, index = _modules()
    path = tmp_path / "index.sqlite"
    rows = [_row(i * 3 + 1, timestamp=timestamp, length=17) for i, timestamp in enumerate(timestamps)]
    _write(index, rows, path)
    report = _summary(path)
    assert report.packet_count == len(rows)
    assert report.captured_bytes == 17 * len(rows)
    assert report.duration_s == expected_duration
    assert report.captured_bytes_s == expected_rate


def test_decimal_interval_ignores_caller_context_and_rate_uses_50_digits(tmp_path):
    _, index = _modules()
    path = tmp_path / "precise.sqlite"
    rows = [
        _row(2, timestamp="1000000000000000000000000000.000000000000000001", length=100),
        _row(8, timestamp="1000000000000000000000000000.000000000000000003", length=80),
    ]
    original_context = getcontext().copy()
    try:
        getcontext().prec = 3
        _write(index, rows, path)
        report = _summary(path)
        assert report.duration_s == Decimal("0.000000000000000002")
        assert report.captured_bytes == 180
        assert report.captured_bytes_s == Decimal("90000000000000000000")
        assert getcontext().prec == 3
    finally:
        getcontext().prec = original_context.prec
        getcontext().rounding = original_context.rounding

    third = tmp_path / "third.sqlite"
    _write(index, [_row(1, timestamp="0", length=1), _row(2, timestamp="3", length=0)], third)
    # The capture has one byte over three seconds; this checks the exact local
    # precision and rounding contract without a float conversion.
    assert _summary(third).captured_bytes_s == Decimal(
        "0.33333333333333333333333333333333333333333333333333"
    )


def test_packet_bins_retransmissions_and_original_timestamp_text(tmp_path):
    _, index = _modules()
    path = tmp_path / "bins.sqlite"
    lengths = [0, 63, 64, 127, 128, 511, 512, 1023, 1024, 1518, 1519]
    rows = [
        _row(i + 1, timestamp=f"1700000000.{11-i:02d}", length=size, retransmission=flag)
        for i, (size, flag) in enumerate(zip(lengths, [True, False, None] * 4))
    ]
    _write(index, rows, path)
    report = _summary(path)
    assert report.packet_size_distribution == {
        "0-63": 2,
        "64-127": 2,
        "128-511": 2,
        "512-1023": 2,
        "1024-1518": 2,
        "1519+": 1,
    }
    assert report.retransmission_indications == 4
    assert report.captured_bytes == sum(lengths)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT timestamp FROM packets WHERE number=1").fetchone()[0] == rows[0].timestamp


def test_directional_nulls_tcp_reverse_direction_and_deterministic_order(tmp_path):
    _, index = _modules()
    path = tmp_path / "groups.sqlite"
    rows = [
        _row(1, length=10, protocol="B", src="z", dst="a", src_port=9, dst_port=1, stream=4),
        _row(3, length=20, protocol="A", src="a", dst="z", src_port=1, dst_port=9, stream=4),
        _row(5, length=30, protocol="A"),
        _row(7, length=30, protocol="B"),
        _row(9, length=5, protocol="A", src=None, dst="x", src_port=None, dst_port=1),
    ]
    _write(index, rows, path)
    report = _summary(path)
    assert report.protocol_counts == {"A": 3, "B": 2}
    assert report.captured_bytes == 95
    assert report.directional_bytes[0] == {
        "src": None, "dst": None, "src_port": None, "dst_port": None,
        "packet_count": 2, "captured_bytes": 60,
    }
    tcp = report.tcp_conversations
    assert tcp == [{
        "tcp_stream": 4, "src": "z", "dst": "a", "src_port": 9, "dst_port": 1,
        "packet_count": 2, "captured_bytes": 30,
    }]
    assert report.duration_s == Decimal("0.000000008")


def test_top_100_group_limits_report_all_groups_and_exact_large_totals(tmp_path):
    _, index = _modules()
    path = tmp_path / "many-groups.sqlite"
    maximum = 2**63 - 1
    rows = [
        _row(i + 1, length=maximum, protocol=f"P{i:03}", src=f"10.0.0.{i}",
             dst="target", src_port=i, dst_port=7, stream=i)
        for i in range(101)
    ]
    _write(index, rows, path)
    report = _summary(path)
    assert report.packet_count == 101
    assert report.captured_bytes == maximum * 101
    assert len(report.protocol_counts) == len(report.directional_bytes) == len(report.tcp_conversations) == 100
    assert "P100" not in report.protocol_counts
    assert report.metadata["presentation_limit"] == 100
    assert report.metadata["group_totals"] == {
        "protocol_counts": 101, "directional_bytes": 101, "tcp_conversations": 101,
    }
    assert report.metadata["truncated"] == {
        "protocol_counts": True, "directional_bytes": True, "tcp_conversations": True,
    }


@pytest.mark.parametrize("kind", ["missing", "corrupt", "incomplete", "schema", "count", "scalar"])
def test_invalid_indexes_fail_safely_without_mutating_database(tmp_path, kind):
    from sparc.models import SparcError

    _, index = _modules()
    path = tmp_path / "invalid.sqlite"
    if kind == "missing":
        before = None
    elif kind == "corrupt":
        path.write_bytes(b"not sqlite")
        before = path.read_bytes()
    else:
        _write(index, [_row(1)], path)
        with sqlite3.connect(path) as db:
            if kind == "incomplete":
                db.execute("UPDATE metadata SET value='false' WHERE key='complete'")
            elif kind == "schema":
                db.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")
            elif kind == "count":
                db.execute("UPDATE metadata SET value='2' WHERE key='packet_count'")
            else:
                db.execute("PRAGMA ignore_check_constraints=ON")
                db.execute("UPDATE packets SET captured_length=-1")
        before = path.read_bytes()
    with pytest.raises(SparcError) as caught:
        _summary(path)
    assert caught.value.code == "traffic_summary_failed"
    assert caught.value.message == "Could not summarize the completed traffic index"
    if before is None:
        assert not path.exists()
    else:
        assert path.read_bytes() == before


def test_private_t2a_index_has_explicit_unmeasured_conversion(tmp_path):
    _, index = _modules()
    path = tmp_path / "private.sqlite"
    _write(index, [_row(2, length=19)], path)
    report = _summary(path)
    assert report.conversion.complete is True
    assert report.conversion.packet_count == 1
    assert report.conversion.source_bytes == 366
    assert report.conversion.output_bytes == path.stat().st_size
    assert report.conversion.elapsed_ns == 0
    assert report.conversion.packets_s is None
    assert report.conversion.metadata["measurement_scope"] == "not_measured"
    assert "conversion" not in _metadata_from(path)


def test_summary_rejects_missing_required_metadata_and_malformed_checkpoint(tmp_path):
    from sparc.models import SparcError

    _, index = _modules()
    missing = tmp_path / "missing-metadata.sqlite"
    _write(index, [_row(1)], missing)
    with sqlite3.connect(missing) as db:
        db.execute("DELETE FROM metadata WHERE key='source_sha256'")
    before = missing.read_bytes()
    with pytest.raises(SparcError) as caught:
        _summary(missing)
    assert caught.value.code == "traffic_summary_failed"
    assert missing.read_bytes() == before

    malformed = tmp_path / "malformed-conversion.sqlite"
    _write(index, [_row(1)], malformed)
    with sqlite3.connect(malformed) as db:
        db.execute("INSERT INTO metadata(key,value) VALUES('conversion','{}')")
    with pytest.raises(SparcError) as caught:
        _summary(malformed)
    assert caught.value.code == "traffic_summary_failed"


def test_public_import_publishes_one_capture_with_checkpoint_and_final_timing(tmp_path, monkeypatch):
    summary, index = _modules()
    source = tmp_path / "source.pcap"
    source.write_bytes(b"synthetic source")
    tshark = tmp_path / "fake tshark"
    tshark.write_text("#!/bin/sh\nprintf 'TShark 4.6.6\\n'\n", encoding="utf-8")
    tshark.chmod(0o755)
    destination = tmp_path / "out.sqlite"
    calls, closed = [], []

    def iter_capture(*args, **kwargs):
        calls.append((args, kwargs))
        def packets():
            try:
                yield _row(1, timestamp="10", length=60, protocol="TCP", src="a", dst="b", src_port=1, dst_port=2, stream=0)
                yield _row(2, timestamp="12", length=80, protocol="TCP", src="b", dst="a", src_port=2, dst_port=1, stream=0)
            finally:
                closed.append(True)
        return packets()

    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", iter_capture)
    if hasattr(index, "iter_capture"):
        monkeypatch.setattr(index, "iter_capture", iter_capture)
    clock = iter([100, 130, 175])
    if hasattr(index, "perf_counter_ns"):
        monkeypatch.setattr(index, "perf_counter_ns", lambda: next(clock))
    elif hasattr(index, "time"):
        monkeypatch.setattr(index.time, "perf_counter_ns", lambda: next(clock))
    else:
        pytest.fail("public importer must expose its monotonic timing source for deterministic contract checks")

    report = index.import_sqlite(source, destination, tshark, threading.Event())
    assert len(calls) == 1 and closed == [True]
    assert report.packet_count == 2 and report.captured_bytes == 140
    assert report.duration_s == Decimal("2") and report.captured_bytes_s == Decimal("70")
    assert report.metadata["conversion"]["elapsed_ns"] == 30
    assert report.metadata["conversion"]["measurement_scope"] == "import_prepublication_checkpoint"
    assert report.conversion.elapsed_ns == 75
    assert report.conversion.output_bytes == destination.stat().st_size
    assert report.conversion.metadata["measurement_scope"] == "import_through_final_publication"
    assert report.conversion.metadata["checkpoint_elapsed_ns"] == 30
    reopened = summary.summarize_database(destination)
    assert reopened.metadata["conversion"]["elapsed_ns"] == 30


def test_public_summary_failure_preserves_prior_destination_and_source(tmp_path, monkeypatch):
    summary, index = _modules()
    from sparc.models import SparcError

    source = tmp_path / "source.pcap"
    source.write_bytes(b"source bytes")
    old_source, destination = source.read_bytes(), tmp_path / "out.sqlite"
    destination.write_bytes(b"previous destination")
    old_destination = destination.read_bytes()
    tshark = tmp_path / "fake tshark"
    tshark.write_text("#!/bin/sh\nprintf 'TShark 4.6.6\\n'\n", encoding="utf-8")
    tshark.chmod(0o755)
    closed, calls = [], []

    def iter_capture(*args, **kwargs):
        calls.append(1)
        def packets():
            try:
                yield _row(1)
            finally:
                closed.append(True)
        return packets()

    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", iter_capture)
    if hasattr(index, "iter_capture"):
        monkeypatch.setattr(index, "iter_capture", iter_capture)
    monkeypatch.setattr(summary, "summarize_database", lambda _path: (_ for _ in ()).throw(
        SparcError("traffic_summary_failed", "Could not summarize the completed traffic index")
    ))
    with pytest.raises(SparcError) as caught:
        index.import_sqlite(source, destination, tshark, threading.Event())
    assert caught.value.code == "traffic_summary_failed"
    assert len(calls) == 1 and closed == [True]
    assert source.read_bytes() == old_source
    assert destination.read_bytes() == old_destination
    assert list(tmp_path.glob(".out.sqlite.*")) == []


def test_public_import_detects_source_change_before_replacing_output(tmp_path, monkeypatch):
    _, index = _modules()
    source = tmp_path / "source.pcap"
    source.write_bytes(b"before")
    destination = tmp_path / "out.sqlite"
    destination.write_bytes(b"old output")
    tshark = tmp_path / "fake tshark"
    tshark.write_text("#!/bin/sh\nprintf 'TShark 4.6.6\\n'\n", encoding="utf-8")
    tshark.chmod(0o755)
    calls = []

    def iter_capture(*args, **kwargs):
        calls.append(1)
        yield _row(1)
        source.write_bytes(b"after")

    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", iter_capture)
    if hasattr(index, "iter_capture"):
        monkeypatch.setattr(index, "iter_capture", iter_capture)
    with pytest.raises(Exception) as caught:
        index.import_sqlite(source, destination, tshark, threading.Event())
    assert getattr(caught.value, "code", None) == "capture_source_changed"
    assert calls == [1]
    assert destination.read_bytes() == b"old output"
    assert list(tmp_path.glob(".out.sqlite.*")) == []
