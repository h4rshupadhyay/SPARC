"""Deterministic CSV exports for synthetic analysis results."""

import csv
from dataclasses import asdict
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Iterable
import uuid

import Crypto
import cryptography

from ..models import SparcError
from ..storage import _sync_parent_directory
from ..storage import atomic_write
from .models import BenchmarkResult
from .models import LabResult
from .sensitivity import _decimal_seed


_LAB_TRIAL_COLUMNS = (
    "case_index",
    "mode",
    "bit_index",
    "synthetic_key_hex",
    "block_hex",
    "synthetic_modified_key_hex",
    "modified_block_hex",
    "baseline_ciphertext_hex",
    "modified_ciphertext_hex",
    "bit_percent",
    "byte_percent",
    "hex_percent",
)
_LAB_SUMMARY_COLUMNS = ("mode", "metric", "count", "mean", "min", "max", "population_std")
_BENCHMARK_COLUMNS = (
    "row_type",
    "metadata_json",
    "complete",
    "operation",
    "payload_bytes",
    "elapsed_ns",
    "success",
    "message_id",
    "characters",
    "frame_bytes",
    "started_ns",
    "finished_ns",
    "error",
    "error_class",
    "encoded_bytes",
    "context_json",
    "count",
    "mean_ns",
    "median_ns",
    "p95_ns",
    "throughput_bytes_s",
    "confirmed_count",
    "elapsed_interval_ns",
    "goodput_bytes_s",
    "characters_s",
)
_BENCHMARK_SAMPLE_FIELDS = (
    "operation",
    "payload_bytes",
    "elapsed_ns",
    "success",
    "message_id",
    "characters",
    "frame_bytes",
    "started_ns",
    "finished_ns",
    "error",
    "error_class",
    "encoded_bytes",
)
_BENCHMARK_SUMMARY_FIELDS = (
    "operation",
    "payload_bytes",
    "count",
    "mean_ns",
    "median_ns",
    "p95_ns",
    "throughput_bytes_s",
    "confirmed_count",
    "elapsed_interval_ns",
    "goodput_bytes_s",
    "characters_s",
)
_SENSITIVE_NAME_PARTS = {"private", "session", "secret", "password", "key"}


def _metadata_json(metadata: dict) -> str:
    try:
        return json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise SparcError("analysis_export_failed", "Analysis metadata is not JSON serializable") from error


def _check_safe_tree(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise SparcError("analysis_export_failed", "Analysis metadata keys must be strings")
            separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
            parts = set(part for part in re.split(r"[^a-z0-9]+", separated.lower()) if part)
            if parts & _SENSITIVE_NAME_PARTS:
                raise SparcError("analysis_export_failed", "Analysis metadata contains a secret-bearing field name")
            _check_safe_tree(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _check_safe_tree(nested)


def _csv_value(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _csv_bytes(fieldnames: tuple[str, ...], rows: Iterable[dict]) -> bytes:
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_value(value) for key, value in row.items() if key in fieldnames})
    return text.getvalue().encode("utf-8")


def _lab_metadata(result: LabResult, run_id: str) -> dict:
    return {
        "synthetic_operands": True,
        "run_id": run_id,
        "utc": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "library_versions": {
            "cryptography": cryptography.__version__,
            "pycryptodome": Crypto.__version__,
        },
        "seed": _decimal_seed(result.seed),
        "cases": result.cases,
        "requested_trials": result.cases * 384,
        "units": {
            "bit_percent": "percent of 128 ciphertext bits changed",
            "byte_percent": "percent of 16 ciphertext bytes changed",
            "hex_percent": "percent of 32 lowercase hexadecimal positions changed",
        },
        "definitions": {
            "bit_percent": "100 times changed ciphertext bits divided by 128",
            "byte_percent": "100 times changed ciphertext bytes divided by 16",
            "hex_percent": "100 times changed lowercase hexadecimal positions divided by 32",
            "population_std": "population standard deviation over retained synthetic trials",
        },
        "evidence_mode": "synthetic_local",
    }


def _stage_file(destination: Path, data: bytes) -> Path:
    descriptor = -1
    temporary_path: str | None = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        if os.name == "posix":
            os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        staged = Path(temporary_path)
        temporary_path = None
        return staged
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _restore_destination(destination: Path, previous: bytes | None, mode: int | None) -> None:
    if previous is None:
        destination.unlink(missing_ok=True)
        return
    descriptor = -1
    temporary_path: str | None = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{destination.name}.rollback.", suffix=".tmp", dir=destination.parent
        )
        if mode is not None and os.name == "posix":
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(previous)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def export_lab(result: LabResult, directory: Path) -> tuple[Path, Path]:
    """Write per-trial and summary CSVs, staging both before publication."""
    directory = Path(directory)
    trials_path = directory / "sensitivity_trials.csv"
    summary_path = directory / "sensitivity_summary.csv"
    run_id = uuid.uuid4().hex
    metadata_json = _metadata_json(_lab_metadata(result, run_id))
    complete = "true" if result.complete else "false"

    trial_rows = []
    for trial in result.trials:
        trial_rows.append(
            {
                "case_index": trial.case_index,
                "mode": trial.mode,
                "bit_index": trial.bit_index,
                "synthetic_key_hex": trial.key.hex(),
                "block_hex": trial.block.hex(),
                "synthetic_modified_key_hex": trial.modified_key.hex(),
                "modified_block_hex": trial.modified_block.hex(),
                "baseline_ciphertext_hex": trial.baseline_ciphertext.hex(),
                "modified_ciphertext_hex": trial.modified_ciphertext.hex(),
                "bit_percent": trial.difference.bit_percent,
                "byte_percent": trial.difference.byte_percent,
                "hex_percent": trial.difference.hex_percent,
                "metadata_json": metadata_json,
                "complete": complete,
            }
        )

    summary_rows = []
    for mode in ("plaintext", "key"):
        for metric in ("bit_percent", "byte_percent", "hex_percent"):
            stats = result.summary[mode][metric]
            summary_rows.append(
                {
                    "mode": mode,
                    "metric": metric,
                    "count": stats["count"],
                    "mean": stats["mean"],
                    "min": stats["min"],
                    "max": stats["max"],
                    "population_std": stats["population_std"],
                    "metadata_json": metadata_json,
                    "complete": complete,
                }
            )

    trial_data = _csv_bytes(_LAB_TRIAL_COLUMNS + ("metadata_json", "complete"), trial_rows)
    summary_data = _csv_bytes(_LAB_SUMMARY_COLUMNS + ("metadata_json", "complete"), summary_rows)
    staged: list[tuple[Path, Path]] = []
    try:
        directory.mkdir(parents=True, exist_ok=True)
        staged.append((_stage_file(trials_path, trial_data), trials_path))
        staged.append((_stage_file(summary_path, summary_data), summary_path))
        previous = {
            destination: (
                destination.read_bytes() if destination.exists() else None,
                (destination.stat().st_mode & 0o777) if destination.exists() else None,
            )
            for _, destination in staged
        }
        published: list[Path] = []
        try:
            for temporary, destination in staged:
                os.replace(temporary, destination)
                published.append(destination)
            _sync_parent_directory(directory)
        except Exception:
            for destination in reversed(published):
                old_bytes, old_mode = previous[destination]
                try:
                    _restore_destination(destination, old_bytes, old_mode)
                except OSError:
                    pass
            raise
        return trials_path, summary_path
    except (OSError, csv.Error, UnicodeError) as error:
        raise SparcError(
            "analysis_export_failed",
            f"Could not export sensitivity CSV files to {directory}; check that the directory is writable",
        ) from error
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _benchmark_rows(result: BenchmarkResult, metadata_json: str) -> list[dict]:
    complete = "true" if result.complete else "false"
    rows: list[dict] = []
    for sample in result.samples:
        row = {"row_type": "sample", "metadata_json": metadata_json, "complete": complete}
        for field in _BENCHMARK_SAMPLE_FIELDS:
            if field in sample:
                row[field] = sample[field]
        context = sample.get("context")
        if context is not None:
            _check_safe_tree(context)
            row["context_json"] = _metadata_json(context)
        elif "context_json" in sample:
            try:
                parsed_context = json.loads(sample["context_json"])
            except (TypeError, ValueError) as error:
                raise SparcError("analysis_export_failed", "Benchmark context is not valid JSON") from error
            _check_safe_tree(parsed_context)
            row["context_json"] = _metadata_json(parsed_context)
        rows.append(row)

    for summary in result.summary:
        row = {"row_type": "summary", "metadata_json": metadata_json, "complete": complete}
        for field in _BENCHMARK_SUMMARY_FIELDS:
            if field in summary:
                row[field] = summary[field]
        rows.append(row)

    if not result.samples:
        rows.insert(0, {"row_type": "metadata", "metadata_json": metadata_json, "complete": complete})
    return rows


def export_benchmark(result: BenchmarkResult, destination: Path) -> None:
    """Write one allowlisted CSV for local or network benchmark evidence."""
    if not isinstance(result.metadata, dict):
        raise SparcError("analysis_export_failed", "Benchmark metadata must be an object")
    _check_safe_tree(result.metadata)
    metadata_json = _metadata_json(result.metadata)
    rows = _benchmark_rows(result, metadata_json)
    data = _csv_bytes(_BENCHMARK_COLUMNS, rows)
    destination = Path(destination)
    try:
        atomic_write(destination, data, private=False, secure_parent=False)
    except (OSError, TypeError) as error:
        raise SparcError(
            "analysis_export_failed",
            f"Could not export benchmark CSV to {destination}; check that the destination directory is writable",
        ) from error
