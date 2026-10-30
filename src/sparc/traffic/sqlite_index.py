"""Bounded, transactional SQLite storage for normalized traffic packets."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
from dataclasses import replace
from threading import Event
from typing import Any, Iterator

from sparc.models import SparcError

from .models import PacketRow, TrafficReport


_BATCH_SIZE = 500
_METADATA_ERROR = "Traffic index metadata is invalid"
_INDEX_ERROR = "Could not build the traffic index"
_SOURCE_ERROR = "Saved capture source is unavailable"
_ALIAS_ERROR = "Capture source and index destination must be different files"
_SUMMARY_ERROR = "Could not summarize the completed traffic index"
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1

_PACKET_COLUMNS = (
    "number, timestamp, captured_length, wire_length, highest_protocol, "
    "src, dst, src_port, dst_port, tcp_stream, tcp_flags, retransmission"
)
_INSERT_PACKET = f"INSERT INTO packets ({_PACKET_COLUMNS}) VALUES ({','.join('?' for _ in range(12))})"
_CREATE_PACKETS = """
CREATE TABLE packets (
    number INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    captured_length INTEGER NOT NULL,
    wire_length INTEGER NOT NULL,
    highest_protocol TEXT NOT NULL,
    src TEXT,
    dst TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    tcp_stream INTEGER,
    tcp_flags TEXT,
    retransmission INTEGER CHECK(retransmission IN (0, 1) OR retransmission IS NULL)
)
"""
_CREATE_METADATA = "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_json_value(value: Any, active: set[int]) -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and _has_surrogate(value):
            raise ValueError
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in active:
            raise ValueError
        active.add(identity)
        try:
            for item in value:
                _validate_json_value(item, active)
        finally:
            active.remove(identity)
        return
    if isinstance(value, dict):
        identity = id(value)
        if identity in active:
            raise ValueError
        active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str) or _has_surrogate(key):
                    raise ValueError
                _validate_json_value(item, active)
        finally:
            active.remove(identity)
        return
    raise ValueError


def _json_text(value: Any) -> str:
    try:
        _validate_json_value(value, set())
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR) from error


def _validated_metadata(metadata: Any) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(metadata, dict):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    values = dict(metadata)

    source_name = values.get("source_name")
    if (
        not isinstance(source_name, str)
        or not source_name
        or Path(source_name).name != source_name
        or "/" in source_name
        or "\\" in source_name
    ):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    source_hash = values.get("source_sha256")
    if not isinstance(source_hash, str) or _SHA256.fullmatch(source_hash) is None:
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    source_size = values.get("source_bytes")
    if isinstance(source_size, bool) or not isinstance(source_size, int) or source_size < 0:
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    display_filter = values.get("display_filter")
    if display_filter is not None and not isinstance(display_filter, str):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)

    versions = values.get("versions")
    required_versions = {"python", "pyshark", "tshark"}
    if not isinstance(versions, dict) or not required_versions <= versions.keys():
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    if any(versions[name] is not None and not isinstance(versions[name], str) for name in required_versions):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)

    evidence_type = values.get("evidence_type")
    if not isinstance(evidence_type, str) or evidence_type not in {
        "synthetic_fixture", "simulation", "physical_device", "unspecified"
    }:
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    definitions = values.get("definitions")
    required_definitions = {"index", "timestamps", "captured_bytes_s", "retransmissions"}
    if not isinstance(definitions, dict) or not required_definitions <= definitions.keys():
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    if any(not isinstance(definitions[name], str) or not definitions[name] for name in required_definitions):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)

    values["schema_version"] = 1
    values["packet_count"] = 0
    values["complete"] = False
    if any(not isinstance(key, str) or _has_surrogate(key) for key in values):
        raise SparcError("invalid_traffic_metadata", _METADATA_ERROR)
    serialized = {key: _json_text(value) for key, value in values.items()}
    return values, serialized


def _check_cancel(cancel: Event) -> None:
    if cancel.is_set():
        raise SparcError("capture_cancelled", "Traffic indexing was canceled")


def _row_values(row: Any) -> tuple[Any, ...]:
    if not isinstance(row, PacketRow):
        raise SparcError("traffic_index_failed", _INDEX_ERROR)
    values = (
        row.number,
        row.timestamp,
        row.captured_length,
        row.wire_length,
        row.highest_protocol,
        row.src,
        row.dst,
        row.src_port,
        row.dst_port,
        row.tcp_stream,
        row.tcp_flags,
        row.retransmission,
    )
    integer_positions = (0, 2, 3, 7, 8, 9)
    for position in integer_positions:
        value = values[position]
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < _INT64_MIN
            or value > _INT64_MAX
        ):
            raise SparcError("traffic_index_failed", _INDEX_ERROR)
    for position in (1, 4):
        if not isinstance(values[position], str):
            raise SparcError("traffic_index_failed", _INDEX_ERROR)
    if values[10] is not None and not isinstance(values[10], str):
        raise SparcError("traffic_index_failed", _INDEX_ERROR)
    for position in (5, 6):
        if values[position] is not None and not isinstance(values[position], str):
            raise SparcError("traffic_index_failed", _INDEX_ERROR)
    if row.retransmission is not None and not isinstance(row.retransmission, bool):
        raise SparcError("traffic_index_failed", _INDEX_ERROR)
    retransmission = None if row.retransmission is None else int(row.retransmission)
    return (*values[:11], retransmission)


def _write_index(
    rows: Iterator[PacketRow],
    destination: Path,
    metadata: dict,
    cancel: Event,
) -> int:
    """Build a bounded, same-directory temporary index and publish on success."""
    values, serialized = _validated_metadata(metadata)
    _check_cancel(cancel)
    destination = Path(destination)
    parent = destination.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except Exception as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error

    iterator: Any = None
    iterator_closed = False
    connection: sqlite3.Connection | None = None
    temporary_path: Path | None = None
    temporary_fd: int | None = None
    file_fd: int | None = None
    directory_fd: int | None = None
    replaced = False
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    published_count = 0

    def close_iterator() -> None:
        nonlocal iterator_closed
        if iterator is None or iterator_closed:
            return
        iterator_closed = True
        close = getattr(iterator, "close", None)
        if callable(close):
            close()

    def remember_cleanup(error: Exception) -> None:
        nonlocal cleanup_error
        if cleanup_error is None:
            cleanup_error = error

    try:
        _check_cancel(cancel)
        iterator = iter(rows)
        _check_cancel(cancel)

        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(parent),
        )
        temporary_path = Path(temporary_name)
        if os.name == "posix":
            os.fchmod(temporary_fd, 0o600)
        os.close(temporary_fd)
        temporary_fd = None

        _check_cancel(cancel)
        connection = sqlite3.connect(str(temporary_path))
        _check_cancel(cancel)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(_CREATE_PACKETS)
        connection.execute("CREATE INDEX packets_timestamp_idx ON packets(timestamp)")
        connection.execute("CREATE INDEX packets_tcp_stream_idx ON packets(tcp_stream)")
        connection.execute(_CREATE_METADATA)
        for key, text in serialized.items():
            _check_cancel(cancel)
            connection.execute("INSERT INTO metadata (key, value) VALUES (?, ?)", (key, text))
        _check_cancel(cancel)
        connection.commit()

        total_inserted = 0
        exhausted = False
        while not exhausted:
            batch: list[tuple[Any, ...]] = []
            for _ in range(_BATCH_SIZE):
                _check_cancel(cancel)
                try:
                    row = next(iterator)
                except StopIteration:
                    _check_cancel(cancel)
                    exhausted = True
                    break
                _check_cancel(cancel)
                batch.append(_row_values(row))

            if exhausted:
                close_iterator()

            for row_values in batch:
                _check_cancel(cancel)
                connection.execute(_INSERT_PACKET, row_values)
            batch_count = total_inserted + len(batch)
            values["packet_count"] = batch_count
            values["complete"] = bool(exhausted)
            count_text = _json_text(batch_count)
            complete_text = _json_text(bool(exhausted))
            _check_cancel(cancel)
            connection.execute(
                "UPDATE metadata SET value = ? WHERE key = ?",
                (count_text, "packet_count"),
            )
            _check_cancel(cancel)
            connection.execute(
                "UPDATE metadata SET value = ? WHERE key = ?",
                (complete_text, "complete"),
            )
            _check_cancel(cancel)
            connection.commit()
            total_inserted = batch_count

        _check_cancel(cancel)
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        if integrity_rows != [("ok",)]:
            raise SparcError("traffic_index_failed", _INDEX_ERROR)

        closing_connection = connection
        connection = None
        closing_connection.close()

        _check_cancel(cancel)
        file_fd = os.open(temporary_path, os.O_RDONLY)
        _check_cancel(cancel)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None

        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(parent, directory_flags)
        _check_cancel(cancel)
        os.replace(temporary_path, destination)
        replaced = True
        temporary_path = None
        os.fsync(directory_fd)
        os.close(directory_fd)
        directory_fd = None
        published_count = total_inserted
    except Exception as error:
        primary_error = error
    finally:
        try:
            close_iterator()
        except Exception as error:
            remember_cleanup(error)

        if connection is not None:
            try:
                connection.rollback()
            except Exception as error:
                remember_cleanup(error)
            try:
                connection.close()
            except Exception as error:
                remember_cleanup(error)
            connection = None

        for descriptor in (temporary_fd, file_fd, directory_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception as error:
                    remember_cleanup(error)

        if temporary_path is not None and not replaced:
            for owned_path in (
                temporary_path,
                Path(f"{temporary_path}-journal"),
                Path(f"{temporary_path}-wal"),
                Path(f"{temporary_path}-shm"),
            ):
                try:
                    owned_path.unlink()
                except FileNotFoundError:
                    pass
                except Exception as error:
                    remember_cleanup(error)

    if replaced and (primary_error is not None or cleanup_error is not None):
        error = primary_error or cleanup_error
        raise SparcError("traffic_publication_uncertain", "Traffic index publication durability is uncertain") from error
    if cleanup_error is not None:
        if isinstance(cleanup_error, SparcError):
            raise cleanup_error
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from cleanup_error
    if primary_error is not None:
        if isinstance(primary_error, SparcError):
            raise primary_error
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from primary_error
    return published_count


def _preflight_public_paths(source: Path, destination: Path) -> tuple[Path, Path]:
    try:
        source_stat = source.stat()
        if not stat.S_ISREG(source_stat.st_mode) or not os.access(source, os.R_OK):
            raise SparcError("capture_source_unavailable", _SOURCE_ERROR)
        with source.open("rb"):
            pass
    except SparcError:
        raise
    except (OSError, RuntimeError) as error:
        raise SparcError("capture_source_unavailable", _SOURCE_ERROR) from error

    try:
        source_resolved = source.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise SparcError("capture_source_unavailable", _SOURCE_ERROR) from error
    try:
        destination_resolved = destination.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error

    if os.path.normcase(os.path.abspath(source_resolved)) == os.path.normcase(os.path.abspath(destination_resolved)):
        raise SparcError("traffic_output_alias", _ALIAS_ERROR)

    try:
        destination_stat = destination.stat()
    except FileNotFoundError:
        destination_stat = None
    except (OSError, RuntimeError) as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error
    if destination_stat is not None:
        if stat.S_ISDIR(destination_stat.st_mode):
            raise SparcError("traffic_index_failed", _INDEX_ERROR)
        try:
            if os.path.samefile(source, destination):
                raise SparcError("traffic_output_alias", _ALIAS_ERROR)
        except SparcError:
            raise
        except (OSError, RuntimeError) as error:
            raise SparcError("traffic_index_failed", _INDEX_ERROR) from error

    parent = destination.parent
    try:
        parent_stat = parent.stat()
    except FileNotFoundError:
        parent_stat = None
    except (OSError, RuntimeError) as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error
    if parent_stat is not None and not stat.S_ISDIR(parent_stat.st_mode):
        raise SparcError("traffic_index_failed", _INDEX_ERROR)
    return source, destination


def _source_fingerprint(source: Path) -> tuple[int, int, int, int, int]:
    info = source.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)


def _hash_source(source: Path, cancel: Event) -> tuple[str, int]:
    _check_cancel(cancel)
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as handle:
        while True:
            _check_cancel(cancel)
            chunk = handle.read(64 * 1024)
            _check_cancel(cancel)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    _check_cancel(cancel)
    return digest.hexdigest(), size


def _observe_versions(tshark: Path, cancel: Event) -> dict[str, str | None]:
    _check_cancel(cancel)
    tshark_version = None
    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            subprocess.run([str(tshark), "--version"], stdout=stdout_file, stderr=stderr_file,
                           timeout=2, check=False)
            stdout_file.seek(0)
            for line in stdout_file.read(8192).decode("utf-8", errors="replace").splitlines():
                if line.strip():
                    tshark_version = line.strip()[:512]
                    break
    except (OSError, subprocess.SubprocessError, RuntimeError):
        pass
    _check_cancel(cancel)
    from importlib.metadata import PackageNotFoundError, version
    try:
        pyshark_version = version("pyshark")
    except PackageNotFoundError:
        pyshark_version = None
    _check_cancel(cancel)
    return {"python": platform.python_version(), "pyshark": pyshark_version, "tshark": tshark_version}


def _replace_and_sync(stage: Path, destination: Path, cancel: Event) -> int:
    directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    replaced = False
    try:
        _check_cancel(cancel)
        os.replace(stage, destination)
        replaced = True
        os.fsync(directory_fd)
        os.close(directory_fd)
        directory_fd = None
        return destination.stat().st_size
    except Exception as error:
        if replaced:
            raise SparcError("traffic_publication_uncertain",
                             "Traffic artifact publication durability is uncertain") from error
        raise
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError as error:
                if replaced:
                    raise SparcError("traffic_publication_uncertain",
                                     "Traffic artifact publication durability is uncertain") from error
                raise


def import_sqlite(
    source: Path,
    destination: Path,
    tshark: Path,
    cancel: Event,
    display_filter: str | None = None,
) -> TrafficReport:
    """Build a private index, compose its report, then publish it atomically."""
    started_ns = time.perf_counter_ns()
    _check_cancel(cancel)
    source = Path(source)
    destination = Path(destination)
    _preflight_public_paths(source, destination)
    try:
        summary_module = importlib.import_module("sparc.traffic.summary")
    except ModuleNotFoundError as error:
        if error.name == "sparc.traffic.summary":
            raise SparcError("traffic_summary_failed", _SUMMARY_ERROR) from error
        raise

    source = source.resolve(strict=True)
    destination = destination.absolute()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error

    try:
        before_stat = _source_fingerprint(source)
        source_digest, source_bytes = _hash_source(source, cancel)
        after_hash_stat = _source_fingerprint(source)
        if before_stat != after_hash_stat or source_bytes != before_stat[2]:
            raise SparcError("capture_source_changed", "Saved capture changed while it was being indexed")
    except SparcError:
        raise
    except (OSError, RuntimeError) as error:
        raise SparcError("capture_source_unavailable", _SOURCE_ERROR) from error

    try:
        from . import capture as capture_module

        tshark_path = capture_module.find_tshark(Path(tshark))
    except SparcError:
        raise
    except Exception as error:
        raise SparcError("tshark_missing", "TShark is required for traffic capture") from error

    versions = _observe_versions(tshark_path, cancel)
    metadata = {
        "source_name": source.name,
        "source_sha256": source_digest,
        "source_bytes": source_bytes,
        "display_filter": display_filter,
        "versions": versions,
        "evidence_type": "unspecified",
        "definitions": {
            "index": "A query index, not a lossless capture replacement",
            "timestamps": "Exact source epoch text",
            "captured_bytes_s": "Included captured frame bytes divided by first-to-last included interval",
            "retransmissions": "Dissector indications, not end-to-end loss or attack proof",
        },
    }

    try:
        stage_fd, stage_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp",
                                                dir=str(destination.parent))
        if os.name == "posix":
            os.fchmod(stage_fd, 0o600)
        os.close(stage_fd)
        stage = Path(stage_name)
    except OSError as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error

    published = False
    stage_owned = True
    connection = None
    directory_fd = None
    try:
        _check_cancel(cancel)
        rows = capture_module.iter_capture(source, tshark_path, cancel, display_filter)
        packet_count = _write_index(rows, stage, metadata, cancel)
        # The writer confirms iterator close before returning. This first summary
        # is also part of the checkpoint's measured work.
        summary_module.summarize_database(stage)
        _check_cancel(cancel)
        checkpoint_elapsed = time.perf_counter_ns() - started_ns
        checkpoint_rate = (packet_count * 1_000_000_000 / checkpoint_elapsed
                           if checkpoint_elapsed > 0 else None)
        checkpoint = {
            "complete": True,
            "packet_count": packet_count,
            "elapsed_ns": checkpoint_elapsed,
            "source_bytes": source_bytes,
            "packets_s": checkpoint_rate,
            "measurement_scope": "import_prepublication_checkpoint",
        }

        connection = sqlite3.connect(str(stage))
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                           ("conversion", _json_text(checkpoint)))
        connection.commit()
        result_rows = connection.execute("PRAGMA integrity_check").fetchmany(2)
        if result_rows != [("ok",)]:
            raise SparcError("traffic_index_failed", _INDEX_ERROR)
        connection.close()
        connection = None

        with stage.open("rb") as handle:
            os.fsync(handle.fileno())
        candidate = summary_module.summarize_database(stage)
        _check_cancel(cancel)

        try:
            current_stat = _source_fingerprint(source)
            current_digest, current_bytes = _hash_source(source, cancel)
            final_stat = _source_fingerprint(source)
        except (OSError, RuntimeError) as error:
            raise SparcError("capture_source_unavailable", _SOURCE_ERROR) from error
        if (current_stat != before_stat or final_stat != before_stat or current_digest != source_digest
                or current_bytes != source_bytes):
            raise SparcError("capture_source_changed", "Saved capture changed while it was being indexed")
        _preflight_public_paths(source, destination)
        _check_cancel(cancel)

        final_output_bytes = _replace_and_sync(stage, destination, cancel)
        published = True
        stage_owned = False
        elapsed_ns = time.perf_counter_ns() - started_ns
        packets_s = (packet_count * 1_000_000_000 / elapsed_ns) if elapsed_ns > 0 else None
        final_conversion = replace(
            candidate.conversion,
            elapsed_ns=elapsed_ns,
            output_bytes=final_output_bytes,
            packets_s=packets_s,
            metadata={
                **candidate.conversion.metadata,
                "measurement_scope": "import_through_final_publication",
                "checkpoint_elapsed_ns": checkpoint_elapsed,
                "checkpoint_measurement_scope": "import_prepublication_checkpoint",
            },
        )
        return replace(candidate, conversion=final_conversion)
    except Exception as error:
        if published:
            raise SparcError("traffic_publication_uncertain",
                             "Traffic index publication durability is uncertain") from error
        if isinstance(error, SparcError):
            raise
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
            connection.close()
        if directory_fd is not None:
            os.close(directory_fd)
        if stage_owned:
            for owned in (stage, Path(f"{stage}-journal"), Path(f"{stage}-wal"), Path(f"{stage}-shm")):
                try:
                    owned.unlink()
                except FileNotFoundError:
                    pass


def analyze_capture(
    source: Path,
    tshark: Path,
    cancel: Event,
    display_filter: str | None = None,
) -> TrafficReport:
    """Summarize one verified temporary index and remove it before returning."""
    _check_cancel(cancel)
    source = Path(source)
    try:
        if not stat.S_ISREG(source.stat().st_mode):
            raise OSError("Not a regular file")
        with source.open("rb"):
            pass
    except (OSError, RuntimeError) as error:
        raise SparcError("capture_source_unavailable", _SOURCE_ERROR) from error
    _check_cancel(cancel)
    try:
        owned = tempfile.TemporaryDirectory(prefix="sparc-traffic-analysis-")
    except OSError as error:
        raise SparcError("traffic_index_failed", _INDEX_ERROR) from error
    try:
        report = import_sqlite(source, Path(owned.name) / "index.sqlite", tshark, cancel, display_filter)
    finally:
        try:
            owned.cleanup()
        except OSError as error:
            raise SparcError("capture_cleanup_failed", "Temporary traffic index cleanup could not be confirmed") from error
    return replace(report, metadata={
        **report.metadata, "artifact_retained": False,
        "measurement_scope": "analysis_temporary_index",
    })
