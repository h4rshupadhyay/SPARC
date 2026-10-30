"""Contracts for bounded transactional SQLite traffic-index publication."""

from __future__ import annotations

import errno
import importlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import threading
from decimal import Decimal

import pytest


def _index_module():
    try:
        return importlib.import_module("sparc.traffic.sqlite_index")
    except ModuleNotFoundError as error:
        if error.name == "sparc.traffic.sqlite_index":
            pytest.fail("T2a SQLite traffic index implementation is not present yet", pytrace=False)
        raise


def _packet(
    number: int,
    *,
    timestamp: str | None = None,
    protocol: str = "FRAME",
    src: str | None = None,
    dst: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    stream: int | None = None,
    flags: str | None = None,
    retransmission: bool | None = None,
):
    from sparc.traffic.models import PacketRow

    return PacketRow(
        number=number,
        timestamp=timestamp if timestamp is not None else f"1700000000.{number:09d}",
        captured_length=60,
        wire_length=60,
        highest_protocol=protocol,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=stream,
        tcp_flags=flags,
        retransmission=retransmission,
    )


def _metadata(**overrides):
    metadata = {
        "source_name": "traffic ; 'quoted'.pcap",
        "source_sha256": "a" * 64,
        "source_bytes": 366,
        "display_filter": 'tcp.port == 443 && frame contains "x ; y"',
        "versions": {"python": "3.10.14", "pyshark": "0.6", "tshark": "4.6.6"},
        "evidence_type": "synthetic_fixture",
        "definitions": {
            "index": "A query index, not a lossless capture replacement",
            "timestamps": "Exact source epoch text",
            "captured_bytes_s": "Included captured frame bytes divided by first-to-last included interval",
            "retransmissions": "Dissector indications, not end-to-end loss or attack proof",
        },
        "display_options": {"enabled": True, "missing": None, "values": [1, "quoted ' unicode ☃"]},
    }
    metadata.update(overrides)
    return metadata


def _assert_error(call, code: str):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        call()
    assert caught.value.code == code
    return caught.value


_DEFAULT_METADATA = object()


def _write(module, rows, destination: Path, metadata=_DEFAULT_METADATA, cancel=None):
    return module._write_index(
        rows,
        destination,
        _metadata() if metadata is _DEFAULT_METADATA else metadata,
        threading.Event() if cancel is None else cancel,
    )


def _staging_files(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.*.tmp*"))


def _read_metadata(connection: sqlite3.Connection) -> dict:
    return {
        key: json.loads(value)
        for key, value in connection.execute("SELECT key, value FROM metadata ORDER BY key")
    }


def _public_import(module, source: Path, destination: Path, cancel=None):
    return module.import_sqlite(
        source,
        destination,
        Path("/no-launch/tshark"),
        threading.Event() if cancel is None else cancel,
    )


def test_sqlite_nulls_fields_indexes_and_parameters(tmp_path):
    module = _index_module()
    destination = tmp_path / "index.sqlite"
    source_metadata = _metadata(
        display_filter='udp.port == 2222; "quoted"',
        injected="x'); DROP TABLE packets; --",
        schema_version=99,
        packet_count=999,
        complete=False,
    )
    original_metadata = json.loads(json.dumps(source_metadata))
    rows = [
        _packet(1),
        _packet(
            2,
            timestamp="1700000000.12345678901234567890",
            protocol="TCP ' quoted ☃; DROP TABLE packets; --",
            src="2001:db8::1",
            dst="2001:db8::2",
            src_port=12345,
            dst_port=47655,
            stream=7,
            flags="0x0002",
            retransmission=True,
        ),
        _packet(
            3,
            protocol="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=1234,
            dst_port=443,
            stream=7,
            flags="0x0010",
            retransmission=False,
        ),
        _packet(
            4,
            protocol="UDP",
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=1111,
            dst_port=2222,
        ),
    ]

    assert _write(module, iter(rows), destination, source_metadata) == 4
    assert source_metadata == original_metadata
    assert destination.is_file()

    with sqlite3.connect(destination) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(packets)")]
        assert columns == [
            "number", "timestamp", "captured_length", "wire_length", "highest_protocol",
            "src", "dst", "src_port", "dst_port", "tcp_stream", "tcp_flags", "retransmission",
        ]
        records = connection.execute(
            "SELECT number, timestamp, highest_protocol, src, dst, src_port, dst_port, "
            "tcp_stream, tcp_flags, retransmission FROM packets ORDER BY number"
        ).fetchall()
        assert records[0] == (1, "1700000000.000000001", "FRAME", None, None, None, None, None, None, None)
        assert records[1] == (
            2, "1700000000.12345678901234567890", "TCP ' quoted ☃; DROP TABLE packets; --", "2001:db8::1", "2001:db8::2",
            12345, 47655, 7, "0x0002", 1,
        )
        assert records[2][-1] == 0
        assert records[3][-1] is None
        null_types = connection.execute(
            "SELECT typeof(src), typeof(src_port), typeof(tcp_stream), typeof(tcp_flags), "
            "typeof(retransmission) FROM packets WHERE number = ?",
            (1,),
        ).fetchone()
        assert null_types == ("null", "null", "null", "null", "null")

        index_names = {row[1] for row in connection.execute("PRAGMA index_list(packets)")}
        assert {"packets_timestamp_idx", "packets_tcp_stream_idx"} <= index_names
        assert not any(name.endswith("number_idx") for name in index_names)
        assert connection.execute("PRAGMA index_info(packets_timestamp_idx)").fetchone()[2] == "timestamp"
        assert connection.execute("PRAGMA index_info(packets_tcp_stream_idx)").fetchone()[2] == "tcp_stream"
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 4

        stored = _read_metadata(connection)
        assert stored["schema_version"] == 1
        assert stored["packet_count"] == 4
        assert stored["complete"] is True
        assert stored["display_filter"] == source_metadata["display_filter"]
        assert stored["display_options"] == source_metadata["display_options"]
        assert stored["injected"] == source_metadata["injected"]
        assert stored["versions"] == source_metadata["versions"]
        assert stored["definitions"] == source_metadata["definitions"]
    assert not _staging_files(destination)


def test_none_filter_is_stored_as_json_null(tmp_path):
    module = _index_module()
    destination = tmp_path / "no-filter.sqlite"
    assert _write(module, iter(()), destination, _metadata(display_filter=None)) == 0
    with sqlite3.connect(destination) as connection:
        raw = connection.execute("SELECT value FROM metadata WHERE key = 'display_filter'").fetchone()[0]
        assert raw == "null"
        assert json.loads(raw) is None


def test_cancel_preserves_existing_output(tmp_path):
    module = _index_module()
    destination = tmp_path / "existing.sqlite"
    sentinel = b"prior index bytes must survive"
    destination.write_bytes(sentinel)
    cancel = threading.Event()
    consumed = []
    closed = []

    def rows():
        try:
            yield _packet(1)
            consumed.append(1)
            yield _packet(2)
            consumed.append(2)
            cancel.set()
            yield _packet(3)
        finally:
            closed.append(True)

    _assert_error(lambda: _write(module, rows(), destination, cancel=cancel), "capture_cancelled")
    assert consumed == [1, 2]
    assert closed == [True]
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)

    pre_cancel = threading.Event()
    pre_cancel.set()
    never_consumed = []
    _assert_error(
        lambda: _write(module, (never_consumed.append(1) for _ in range(1)), destination, cancel=pre_cancel),
        "capture_cancelled",
    )
    assert never_consumed == []
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)

def test_capture_cleanup_error_is_preserved_and_not_published(tmp_path):
    module = _index_module()
    destination = tmp_path / "existing.sqlite"
    sentinel = b"prior database bytes"
    destination.write_bytes(sentinel)

    class CleanupFailureRows:
        def __iter__(self):
            return self

        def __next__(self):
            raise RuntimeError("reader failure detail")

        def close(self):
            from sparc.models import SparcError

            raise SparcError("capture_cleanup_failed", "Offline capture cleanup could not be confirmed")

    error = _assert_error(
        lambda: _write(module, CleanupFailureRows(), destination),
        "capture_cleanup_failed",
    )
    assert "reader failure detail" not in error.message
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)


def test_source_alias_is_rejected(tmp_path):
    module = _index_module()
    source = tmp_path / "source.pcap"
    source.write_bytes(b"saved capture bytes")
    original_bytes = source.read_bytes()
    original_mode = stat.S_IMODE(source.stat().st_mode)
    aliases = [("same path", source)]

    symlink = tmp_path / "source-symlink.pcap"
    hardlink = tmp_path / "source-hardlink.pcap"
    link_parent = tmp_path / "source-alias-parent"
    for label, action, path in (
        ("symlink", lambda: os.symlink(source, symlink), symlink),
        ("hardlink", lambda: os.link(source, hardlink), hardlink),
        ("symlinked parent", lambda: os.symlink(tmp_path, link_parent, target_is_directory=True), link_parent / source.name),
    ):
        try:
            action()
        except (NotImplementedError, OSError) as error:
            unsupported = {errno.EOPNOTSUPP, errno.ENOSYS}
            if hasattr(errno, "ENOTSUP"):
                unsupported.add(errno.ENOTSUP)
            if isinstance(error, OSError) and error.errno not in unsupported:
                raise
            pytest.skip(f"OS does not support required {label} test: {error}")
        aliases.append((label, path))

    for _label, destination in aliases:
        _assert_error(lambda d=destination: _public_import(module, source, d), "traffic_output_alias")
        assert source.read_bytes() == original_bytes
        assert stat.S_IMODE(source.stat().st_mode) == original_mode


def test_public_import_composes_summary_and_checkpoint(tmp_path, monkeypatch):
    module = _index_module()
    source = tmp_path / "saved.pcap"
    source.write_bytes(b"valid saved capture")
    tshark = tmp_path / "fake tshark"
    tshark.write_text("#!/bin/sh\nprintf 'TShark 4.6.6\\n'\n", encoding="utf-8")
    tshark.chmod(0o755)
    destination = tmp_path / "published" / "nested" / "index.sqlite"
    capture_calls = []
    iterator_closed = []

    def fake_iter_capture(*args, **kwargs):
        capture_calls.append((args, kwargs))

        def rows():
            try:
                yield _packet(1, protocol="TCP", src="10.0.0.1", dst="10.0.0.2", src_port=1234, dst_port=443, stream=0, flags="0x0002")
            finally:
                iterator_closed.append(True)

        return rows()

    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", fake_iter_capture)
    if hasattr(module, "iter_capture"):
        monkeypatch.setattr(module, "iter_capture", fake_iter_capture)

    report = module.import_sqlite(source, destination, tshark, threading.Event())
    assert len(capture_calls) == 1
    assert iterator_closed == [True]
    assert destination.is_file()
    assert report.packet_count == 1
    assert report.captured_bytes == 60
    assert report.metadata["conversion"]["measurement_scope"] == "import_prepublication_checkpoint"
    assert report.conversion.metadata["measurement_scope"] == "import_through_final_publication"
    assert report.conversion.output_bytes == destination.stat().st_size
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1


def test_public_import_hash_is_bounded_and_cancellable(tmp_path, monkeypatch):
    module = _index_module()
    source = tmp_path / "large saved capture.pcap"
    source_bytes = b"capture-data" * 10000
    source.write_bytes(source_bytes)
    tshark = tmp_path / "fake tshark"
    tshark.write_text("#!/bin/sh\nprintf 'TShark 4.6.6\\n'\n", encoding="utf-8")
    tshark.chmod(0o755)
    original_mode = stat.S_IMODE(source.stat().st_mode)
    destination = tmp_path / "index.sqlite"
    previous = b"previous selected index"
    destination.write_bytes(previous)
    cancel = threading.Event()
    reads = []
    decoder_calls = []

    original_open = Path.open

    class SourceReader:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def read(self, size=-1):
            reads.append(size)
            data = self.handle.read(size)
            if data:
                cancel.set()
            return data

        def __getattr__(self, name):
            return getattr(self.handle, name)

    def recording_open(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)
        if Path(path) == source and args and args[0] == "rb":
            return SourceReader(handle)
        return handle

    def should_not_decode(*args, **kwargs):
        decoder_calls.append((args, kwargs))
        return iter(())

    monkeypatch.setattr(Path, "open", recording_open)
    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", should_not_decode)

    _assert_error(
        lambda: module.import_sqlite(source, destination, tshark, cancel),
        "capture_cancelled",
    )
    assert len(reads) == 1
    assert 0 < reads[0] <= 64 * 1024
    assert decoder_calls == []
    assert destination.read_bytes() == previous
    assert source.read_bytes() == source_bytes
    assert stat.S_IMODE(source.stat().st_mode) == original_mode
    assert not _staging_files(destination)


def test_public_import_closes_stage_descriptor_when_fsync_fails(tmp_path, monkeypatch):
    module = _index_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "index.sqlite"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\nprintf 'TShark test\\n'\n")
    tool.chmod(0o755)
    import sparc.traffic.capture as capture
    monkeypatch.setattr(capture, "iter_capture", lambda *args: iter([_packet(1)]))
    original = os.fsync
    regular = []

    def sync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            regular.append(fd)
            if len(regular) == 2:
                raise OSError("disk fault")
        return original(fd)

    monkeypatch.setattr(os, "fsync", sync)
    _assert_error(lambda: module.import_sqlite(source, destination, tool, threading.Event()), "traffic_index_failed")
    assert len(regular) == 2
    with pytest.raises(OSError):
        os.fstat(regular[-1])
    assert destination.read_bytes() == b"prior"


@pytest.mark.parametrize("bad_value", [
    Decimal("1.25"),
    b"bytes",
    {1: "non-string key"},
    {"nested": ("tuple",)},
    math.nan,
    "invalid surrogate \ud800",
    object(),
])
def test_metadata_encoding_rejects_unsupported_values_before_mutation(tmp_path, bad_value):
    module = _index_module()
    destination = tmp_path / "prior.sqlite"
    sentinel = b"existing database"
    destination.write_bytes(sentinel)
    metadata = _metadata(extra=bad_value)

    error = _assert_error(
        lambda: _write(module, iter(()), destination, metadata),
        "invalid_traffic_metadata",
    )
    assert "extra" not in error.message
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)


@pytest.mark.parametrize("bad_root", [[], "metadata", None])
def test_metadata_root_must_be_an_object_before_mutation(tmp_path, bad_root):
    module = _index_module()
    destination = tmp_path / "prior.sqlite"
    sentinel = b"existing database"
    destination.write_bytes(sentinel)
    _assert_error(
        lambda: _write(module, iter(()), destination, bad_root),
        "invalid_traffic_metadata",
    )
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_name": 17},
        {"source_sha256": "not-a-digest"},
        {"source_sha256": "A" * 64},
        {"source_bytes": True},
        {"display_filter": 5},
        {"versions": {"python": 3.10, "pyshark": "0.6", "tshark": "4.6.6"}},
        {"versions": {"python": "3.10.14", "pyshark": None}},
        {"evidence_type": "decoder-guessed"},
        {"definitions": {"timestamps": "missing fixed definitions"}},
    ],
)
def test_invalid_required_metadata_is_rejected_before_mutation(tmp_path, changes):
    module = _index_module()
    destination = tmp_path / "prior.sqlite"
    sentinel = b"existing database"
    destination.write_bytes(sentinel)
    metadata = _metadata(**changes)
    _assert_error(
        lambda: _write(module, iter(()), destination, metadata),
        "invalid_traffic_metadata",
    )
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)


def test_streaming_batch_bound(tmp_path):
    module = _index_module()
    destination = tmp_path / "streamed.sqlite"
    observations = []

    def rows():
        for number in range(1, 1202):
            if number in {501, 1001}:
                temp_files = _staging_files(destination)
                assert len(temp_files) == 1, "writer must stage to one same-directory temporary database"
                if os.name == "posix":
                    assert stat.S_IMODE(temp_files[0].stat().st_mode) == 0o600
                uri = f"file:{temp_files[0].as_posix()}?mode=ro"
                with sqlite3.connect(uri, uri=True) as connection:
                    count = connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
                    metadata = _read_metadata(connection)
                expected = number - 1
                assert count == expected
                assert metadata["complete"] is False
                observations.append((number, count, metadata["complete"]))
            yield _packet(number)

    assert _write(module, rows(), destination) == 1201
    assert observations == [(501, 500, False), (1001, 1000, False)]
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1201
        stored = _read_metadata(connection)
    assert stored["packet_count"] == 1201
    assert stored["complete"] is True
    assert not _staging_files(destination)


def test_integrity_or_replace_failure_does_not_publish(tmp_path, monkeypatch):
    module = _index_module()
    destination = tmp_path / "existing.sqlite"
    sentinel = b"previous database bytes"
    destination.write_bytes(sentinel)

    real_connect = sqlite3.connect

    class FailingIntegrityCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            return ("not ok",)

        def fetchall(self):
            return [("not ok",)]

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class IntegrityConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args, **kwargs):
            cursor = self.connection.execute(sql, *args, **kwargs)
            if sql.strip().lower() == "pragma integrity_check":
                return FailingIntegrityCursor(cursor)
            return cursor

        def __getattr__(self, name):
            return getattr(self.connection, name)

    monkeypatch.setattr(
        module.sqlite3,
        "connect",
        lambda *args, **kwargs: IntegrityConnection(real_connect(*args, **kwargs)),
    )
    _assert_error(lambda: _write(module, iter([_packet(1)]), destination), "traffic_index_failed")
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)
    monkeypatch.setattr(module.sqlite3, "connect", real_connect)

    real_replace = os.replace

    def fail_replace(*args, **kwargs):
        raise OSError("replace failure sentinel")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    _assert_error(lambda: _write(module, iter([_packet(1)]), destination), "traffic_index_failed")
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)
    monkeypatch.setattr(module.os, "replace", real_replace)

    real_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory sync failure sentinel")
        return real_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fail_directory_fsync)
    error = _assert_error(
        lambda: _write(module, iter([_packet(1)]), destination),
        "traffic_publication_uncertain",
    )
    assert "directory sync failure sentinel" not in error.message
    assert destination.read_bytes() != sentinel
    with sqlite3.connect(destination) as connection:
        metadata = _read_metadata(connection)
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1
    assert metadata["complete"] is True
    assert not _staging_files(destination)


@pytest.mark.parametrize("bad_number", [500, 2**80])
def test_row_failure_after_committed_batch_preserves_existing_output(tmp_path, bad_number):
    module = _index_module()
    destination = tmp_path / "prior.sqlite"
    sentinel = b"previous index bytes"
    destination.write_bytes(sentinel)

    def rows():
        for number in range(1, 501):
            yield _packet(number)
        staged = _staging_files(destination)
        assert len(staged) == 1
        with sqlite3.connect(f"file:{staged[0].as_posix()}?mode=ro", uri=True) as connection:
            assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 500
            assert _read_metadata(connection)["complete"] is False
        yield _packet(bad_number)

    error = _assert_error(lambda: _write(module, rows(), destination), "traffic_index_failed")
    assert error.message == "Could not build the traffic index"
    assert destination.read_bytes() == sentinel
    assert not _staging_files(destination)
