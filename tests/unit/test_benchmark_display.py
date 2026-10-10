"""Benchmark reporting behavior without requiring a Tk display."""

import csv

import pytest

from sparc.analysis.benchmark import run_local_benchmarks
from sparc.analysis.export import export_benchmark
from sparc.analysis.models import BenchmarkResult
from sparc.gui.analysis_view import AnalysisTab


def _render(result):
    # Replace only widget writes; exercise the actual reporting and formatting.
    tab = object.__new__(AnalysisTab)
    rows = []
    details = []
    tab._clear_results = lambda: None
    tab._add_row = lambda *values: rows.append(tuple(tab._display(value) for value in values))
    tab._details_text = details.append
    tab._render_benchmark(result)
    return rows, details[0]


def test_local_display_uses_median_and_primitive_rates_without_raw_samples():
    result = BenchmarkResult(
        metadata={"test_type": "local_cryptographic"},
        samples=[{
            "operation": "sign", "payload_bytes": 64,
            "elapsed_ns": duration, "success": True,
        } for duration in (1000, 2000, 9000)],
        summary=[{
            "operation": "sign", "payload_bytes": 64, "count": 3,
            "mean_ns": 4000, "median_ns": 2000, "p95_ns": 9000,
            "throughput_bytes_s": 16_000_000.0, "characters_s": 16_000_000.0,
        }],
        complete=True,
    )

    rows, details = _render(result)

    assert len(rows) == 1
    assert rows[0][1] == "Signature generation (µs)"
    assert rows[0][2] == "2"
    assert "median" in rows[0][3].lower()
    assert "p95 9 µs" in rows[0][3]
    assert "throughput 1.6e+07 B/s" in rows[0][3]
    assert "characters 1.6e+07/s" in rows[0][3]
    assert "goodput" not in rows[0][3]
    assert "3 measured samples" in details
    assert "CSV" in details


def test_full_local_run_displays_only_summaries_and_exports_all_samples(tmp_path):
    result = run_local_benchmarks()
    rows, details = _render(result)

    assert len(rows) == 18
    assert "18000 measured samples" in details
    assert all("unavailable" not in row[3] for row in rows)
    for summary in result.summary:
        assert summary["characters_s"] == summary["throughput_bytes_s"]

    destination = tmp_path / "full.csv"
    export_benchmark(result, destination)
    with destination.open(newline="", encoding="utf-8") as stream:
        exported = list(csv.DictReader(stream))
    assert sum(row["row_type"] == "sample" for row in exported) == 18000
    summaries = [row for row in exported if row["row_type"] == "summary"]
    assert len(summaries) == 18
    assert all(float(row["characters_s"]) > 0 for row in summaries)


@pytest.mark.parametrize("complete, rate", [(True, 1234.0), (False, None)])
def test_network_display_preserves_confirmed_goodput_and_incomplete_rates(complete, rate):
    result = BenchmarkResult(
        metadata={"test_type": "network_round_trip"}, samples=[],
        summary=[{
            "operation": "network_round_trip", "payload_bytes": 64, "count": 1,
            "mean_ns": 1000, "median_ns": 1000, "p95_ns": 1000,
            "throughput_bytes_s": None, "goodput_bytes_s": rate, "characters_s": rate,
        }], complete=complete,
    )
    rows, _ = _render(result)
    assert len(rows) == 1
    assert "throughput" not in rows[0][3]
    expected = "1,234" if complete else "unavailable"
    assert f"goodput {expected} B/s" in rows[0][3]
    assert f"characters {expected}/s" in rows[0][3]


def test_canceled_local_run_keeps_unmeasured_rates_unavailable():
    from threading import Event

    cancel = Event()
    cancel.set()
    result = run_local_benchmarks(sizes=(64,), cancel=cancel)
    rows, _ = _render(result)
    assert len(rows) == 6
    assert all(row[2] == "unavailable" for row in rows)
    assert all("throughput unavailable B/s" in row[3] for row in rows)
    assert all("characters unavailable/s" in row[3] for row in rows)


def test_operation_summary_does_not_display_unmeasured_payload_rates():
    result = BenchmarkResult(
        metadata={"test_type": "operation_metrics"}, samples=[],
        summary=[{
            "operation": "audit_verify", "count": 1,
            "mean_ns": 1000, "median_ns": 1000, "p95_ns": 1000,
            "throughput_bytes_s": None,
        }], complete=True,
    )
    rows, _ = _render(result)
    assert "goodput" not in rows[0][3]
    assert "throughput" not in rows[0][3]
    assert "characters" not in rows[0][3]
