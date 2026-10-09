import csv
from dataclasses import replace
from importlib import import_module
import json
import os
from math import ceil
from pathlib import Path
from statistics import mean, median, pstdev

import pytest

from sparc.analysis.benchmark import run_local_benchmarks
from sparc.analysis.sensitivity import run_sensitivity
from sparc.models import SparcError


def _export_module():
    try:
        exporter = import_module("sparc.analysis.export")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.export":
            raise
        pytest.fail("sparc.analysis.export must be implemented")
    assert callable(getattr(exporter, "export_lab", None)), "export_lab must be implemented"
    assert callable(getattr(exporter, "export_benchmark", None)), "export_benchmark must be implemented"
    return exporter


def _read_csv(path: Path):
    with path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames, list(reader)


def _metadata(rows):
    value = next(row["metadata_json"] for row in rows if row.get("metadata_json"))
    return json.loads(value)


def _assert_close(actual, expected):
    assert float(actual) == pytest.approx(expected)


def test_csv_reconstructs_lab_and_benchmark_summaries_without_live_secrets(tmp_path):
    exporter = _export_module()
    lab_result = run_sensitivity(seed=91, cases=1)
    trials_path, lab_summary_path = exporter.export_lab(lab_result, tmp_path)
    benchmark_result = run_local_benchmarks(sizes=(64,), warmups=0, repetitions=2)
    benchmark_path = tmp_path / "benchmark.csv"
    exporter.export_benchmark(benchmark_result, benchmark_path)

    trial_fields, trial_rows = _read_csv(trials_path)
    summary_fields, summary_rows = _read_csv(lab_summary_path)
    assert len(trial_rows) == 384
    assert len(summary_rows) == 6
    assert {"synthetic_key_hex", "synthetic_modified_key_hex"} <= set(trial_fields)
    assert {
        field for field in trial_fields if "key" in field.lower()
    } == {"synthetic_key_hex", "synthetic_modified_key_hex"}
    assert not {"private_key", "session_key", "aes_key"} & set(trial_fields)
    assert not {"private_key", "session_key", "aes_key"} & set(summary_fields)
    assert all(row["complete"] == "true" for row in trial_rows + summary_rows)

    lab_metadata = _metadata(trial_rows)
    assert lab_metadata["synthetic_operands"] is True
    assert lab_metadata["seed"] == "91"
    assert lab_metadata["units"]
    assert lab_metadata["definitions"]
    assert lab_metadata["evidence_mode"]
    assert all("private_key" not in key.lower() and "session_key" not in key.lower() for key in lab_metadata)

    for mode in ("plaintext", "key"):
        rows_for_mode = [row for row in trial_rows if row["mode"] == mode]
        for metric in ("bit_percent", "byte_percent", "hex_percent"):
            expected_values = [float(row[metric]) for row in rows_for_mode]
            summary = next(
                row for row in summary_rows if row["mode"] == mode and row["metric"] == metric
            )
            assert int(summary["count"]) == len(expected_values)
            _assert_close(summary["mean"], mean(expected_values))
            _assert_close(summary["min"], min(expected_values))
            _assert_close(summary["max"], max(expected_values))
            _assert_close(summary["population_std"], pstdev(expected_values))

    benchmark_fields, benchmark_rows = _read_csv(benchmark_path)
    assert {"row_type", "metadata_json", "complete", "operation", "payload_bytes", "elapsed_ns"} <= set(
        benchmark_fields
    )
    assert not any(
        "private_key" in field.lower() or "session_key" in field.lower() or "aes_key" in field.lower()
        for field in benchmark_fields
    )
    assert all(row["complete"] == "true" for row in benchmark_rows)
    benchmark_metadata = _metadata(benchmark_rows)
    assert benchmark_metadata["units"]
    assert benchmark_metadata["definitions"]
    sample_rows = [row for row in benchmark_rows if row["row_type"] == "sample"]
    benchmark_summaries = [row for row in benchmark_rows if row["row_type"] == "summary"]
    assert len(sample_rows) == 12
    assert len(benchmark_summaries) == 6

    for summary in benchmark_summaries:
        values = [
            int(row["elapsed_ns"])
            for row in sample_rows
            if row["operation"] == summary["operation"]
            and int(row["payload_bytes"]) == int(summary["payload_bytes"])
            and row["success"] == "true"
        ]
        assert int(summary["count"]) == len(values)
        _assert_close(summary["mean_ns"], mean(values))
        _assert_close(summary["median_ns"], median(values))
        assert int(summary["p95_ns"]) == sorted(values)[ceil(0.95 * len(values)) - 1]


def test_canceled_exports_are_marked_incomplete_and_keep_requested_seed(tmp_path):
    exporter = _export_module()

    def cancel_first_trial(current, total):
        if current == 1:
            cancel.set()

    from threading import Event

    cancel = Event()
    huge_seed = -(10**5000)
    lab_result = run_sensitivity(seed=huge_seed, cases=1, cancel=cancel, progress=cancel_first_trial)
    lab_trials, lab_summary = exporter.export_lab(lab_result, tmp_path)
    trial_rows = _read_csv(lab_trials)[1]
    summary_rows = _read_csv(lab_summary)[1]

    assert lab_result.complete is False
    assert lab_result.cases == 1
    assert trial_rows and all(row["complete"] == "false" for row in trial_rows)
    assert all(row["complete"] == "false" for row in summary_rows)
    expected_seed = "-1" + "0" * 5000
    assert _metadata(trial_rows)["seed"] == expected_seed

    benchmark_cancel = Event()
    benchmark_cancel.set()
    benchmark_result = run_local_benchmarks(
        sizes=(64,), warmups=0, repetitions=1, cancel=benchmark_cancel
    )
    benchmark_path = tmp_path / "canceled-benchmark.csv"
    exporter.export_benchmark(benchmark_result, benchmark_path)
    benchmark_rows = _read_csv(benchmark_path)[1]
    assert benchmark_result.complete is False
    summary_rows = [row for row in benchmark_rows if row["row_type"] == "summary"]
    metadata_rows = [row for row in benchmark_rows if row["row_type"] == "metadata"]
    assert len(summary_rows) == 6
    assert len(metadata_rows) == 1
    assert {row["operation"] for row in summary_rows} == {
        "hash",
        "sign",
        "encrypt",
        "decrypt",
        "recompute_hash",
        "verify",
    }
    for row in summary_rows:
        assert row["count"] == "0"
        assert row["mean_ns"] == ""
        assert row["median_ns"] == ""
        assert row["p95_ns"] == ""
        assert row["throughput_bytes_s"] == ""
    assert all(row["complete"] == "false" for row in benchmark_rows)
    assert all(row["metadata_json"] for row in benchmark_rows)


def test_failed_lab_staging_preserves_both_existing_files(tmp_path, monkeypatch):
    exporter = _export_module()
    lab_result = run_sensitivity(seed=7, cases=1)
    trials_path = tmp_path / "sensitivity_trials.csv"
    summary_path = tmp_path / "sensitivity_summary.csv"
    trials_path.write_bytes(b"old trials")
    summary_path.write_bytes(b"old summary")
    original_fsync = os.fsync
    sync_calls = 0

    def fail_second_stage_sync(descriptor):
        nonlocal sync_calls
        sync_calls += 1
        if sync_calls == 2:
            raise OSError("injected CSV staging failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_second_stage_sync)
    with pytest.raises((SparcError, OSError)):
        exporter.export_lab(lab_result, tmp_path)

    assert trials_path.read_bytes() == b"old trials"
    assert summary_path.read_bytes() == b"old summary"


def test_failed_benchmark_write_preserves_previous_file(tmp_path, monkeypatch):
    exporter = _export_module()
    benchmark_result = run_local_benchmarks(sizes=(64,), warmups=0, repetitions=1)
    destination = tmp_path / "benchmark.csv"
    destination.write_bytes(b"previous benchmark")

    def fail_sync(_descriptor):
        raise OSError("injected benchmark staging failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises((SparcError, OSError)):
        exporter.export_benchmark(benchmark_result, destination)

    assert destination.read_bytes() == b"previous benchmark"


def test_unsafe_benchmark_metadata_is_rejected_before_destination_changes(tmp_path):
    exporter = _export_module()
    benchmark_result = run_local_benchmarks(sizes=(64,), warmups=0, repetitions=1)
    unsafe_result = replace(
        benchmark_result,
        metadata={**benchmark_result.metadata, "session_key": "must never export"},
    )
    destination = tmp_path / "benchmark.csv"
    destination.write_bytes(b"previous benchmark")

    with pytest.raises(SparcError):
        exporter.export_benchmark(unsafe_result, destination)

    assert destination.read_bytes() == b"previous benchmark"


def test_selected_export_directory_permissions_are_preserved(tmp_path):
    exporter = _export_module()
    selected = tmp_path / "selected"
    selected.mkdir(mode=0o750)
    os.chmod(selected, 0o750)
    before = selected.stat().st_mode & 0o777

    exporter.export_lab(run_sensitivity(seed=12, cases=1), selected)
    exporter.export_benchmark(
        run_local_benchmarks(sizes=(64,), warmups=0, repetitions=1),
        selected / "benchmark.csv",
    )

    assert selected.stat().st_mode & 0o777 == before
