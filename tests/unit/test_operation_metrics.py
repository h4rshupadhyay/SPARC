"""A3d bounded, reconstructable operation metric collection."""

import csv
import json
from importlib import import_module

import pytest

from sparc.analysis.models import BenchmarkResult
from sparc.models import ServiceEvent


def _operation_metrics(*args, **kwargs):
    try:
        module = import_module("sparc.analysis.operation_metrics")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.operation_metrics":
            raise
        pytest.fail("sparc.analysis.operation_metrics must be implemented")
    operation_metrics = getattr(module, "OperationMetrics", None)
    assert callable(operation_metrics), "OperationMetrics must be implemented"
    return module, operation_metrics(*args, **kwargs)


def _event(operation, elapsed_ns, *, success=True, context=None, **fields):
    data = {
        "operation": operation,
        "elapsed_ns": elapsed_ns,
        "success": success,
        "context": {} if context is None else context,
    }
    data.update(fields)
    return ServiceEvent("operation_metrics", data)


def _summary(result, operation):
    return next(row for row in result.summary if row["operation"] == operation)


def test_operation_spans_are_separate_bounded_and_failures_leave_aggregates():
    _, metrics = _operation_metrics(capacity=1000)
    original_context = {"stage": "payload", "public": {"sequence": 4}}
    first = _event(
        "encrypt", 100, encoded_bytes=48, frame_bytes=96, context=original_context
    )
    metrics.add(first)
    original_context["public"]["sequence"] = 99
    metrics.add(_event("encrypt", 300, encoded_bytes=52, frame_bytes=101))
    metrics.add(_event("encrypt", 9999, success=False, encoded_bytes=0, error_class="ValueError"))
    result = metrics.result()

    assert isinstance(result, BenchmarkResult)
    assert len(result.samples) == 3
    encrypt_rows = [row for row in result.samples if row["operation"] == "encrypt"]
    assert len(encrypt_rows) == 3
    assert encrypt_rows[0]["context"] == {"stage": "payload", "public": {"sequence": 4}}
    assert encrypt_rows[0]["context"] is not original_context
    assert encrypt_rows[0]["encoded_bytes"] == 48
    assert encrypt_rows[0]["frame_bytes"] == 96
    assert encrypt_rows[0]["frame_bytes"] != encrypt_rows[0]["encoded_bytes"]
    encrypt_summary = _summary(result, "encrypt")
    assert encrypt_summary["count"] == 2
    assert encrypt_summary["mean_ns"] == 200
    assert encrypt_summary["median_ns"] == 200
    assert encrypt_summary["p95_ns"] == 300
    assert encrypt_summary.get("throughput_bytes_s") is None

    _, bounded = _operation_metrics(capacity=1000)
    for elapsed in range(1002):
        bounded.add(_event("hash", elapsed, context={"sample": elapsed}))
    bounded_result = bounded.result()
    assert len(bounded_result.samples) == 1000
    hash_rows = bounded_result.samples
    assert len(hash_rows) == 1000
    assert hash_rows[0]["elapsed_ns"] == 2
    assert hash_rows[-1]["elapsed_ns"] == 1001
    assert _summary(bounded_result, "hash")["count"] == 1000


def test_handshake_approval_labels_and_audit_bytes_remain_separate():
    _, metrics = _operation_metrics()
    metrics.add(_event(
        "handshake", 1250, context={"approval_included": False, "outcome": "known"}
    ))
    metrics.add(_event(
        "handshake", 9250, context={"approval_included": True, "outcome": "approved"}
    ))
    metrics.add(_event(
        "audit", 400, encoded_bytes=312, frame_bytes=920,
        context={"event": "send_attempt", "frame_bytes": 920},
    ))

    result = metrics.result()
    handshake_rows = [row for row in result.samples if row["operation"] == "handshake"]
    assert [row["elapsed_ns"] for row in handshake_rows] == [1250, 9250]
    assert [row["context"]["approval_included"] for row in handshake_rows] == [False, True]
    audit = next(row for row in result.samples if row["operation"] == "audit")
    assert audit["elapsed_ns"] == 400
    assert audit["encoded_bytes"] == 312
    assert audit["frame_bytes"] == 920
    assert audit["context"]["frame_bytes"] == 920


def test_reconnect_recovery_uses_context_duration_and_preserves_wrapper_provenance(tmp_path):
    _, metrics = _operation_metrics()
    context = {"attempt": 2, "elapsed_ns": 123456}
    event = _event("reconnect_recovery", 0, context=context)
    metrics.add(event)

    result = metrics.result()
    recovery = result.samples[0]
    assert recovery["elapsed_ns"] == 123456
    assert recovery["success"] is True
    assert recovery["context"] == {
        "attempt": 2,
        "elapsed_ns": 123456,
        "source_elapsed_ns": 0,
    }
    assert context == {"attempt": 2, "elapsed_ns": 123456}
    assert recovery["context"] is not context
    summary = _summary(result, "reconnect_recovery")
    assert summary["count"] == 1
    assert summary["mean_ns"] == 123456
    assert summary["median_ns"] == 123456
    assert summary["p95_ns"] == 123456

    destination = tmp_path / "operation-metrics.csv"
    export = import_module("sparc.analysis.export")
    export.export_benchmark(result, destination)
    with destination.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    sample = next(row for row in rows if row["row_type"] == "sample")
    assert int(sample["elapsed_ns"]) == 123456
    assert json.loads(sample["context_json"]) == recovery["context"]
    exported_summary = next(
        row for row in rows
        if row["row_type"] == "summary" and row["operation"] == "reconnect_recovery"
    )
    assert float(exported_summary["mean_ns"]) == 123456
    assert float(exported_summary["median_ns"]) == 123456
    assert int(exported_summary["p95_ns"]) == 123456


def test_reconnect_attempt_wrapper_zero_is_labeled_diagnostic_not_measured():
    _, metrics = _operation_metrics()
    context = {"attempt": 2, "delay_seconds": 2.0}
    metrics.add(_event("reconnect_attempt", 0, context=context))

    result = metrics.result()
    attempt = result.samples[0]
    assert attempt["operation"] == "reconnect_attempt"
    assert attempt["success"] is True
    assert attempt["elapsed_ns"] is None
    assert attempt["context"]["attempt"] == 2
    assert attempt["context"]["delay_seconds"] == 2.0
    assert "diagnostic" in json.dumps(result.metadata).lower() or "diagnostic" in json.dumps(attempt["context"]).lower()


@pytest.mark.parametrize("bad_duration", [None, True, -1, "123456", 1.5])
def test_invalid_reconnect_duration_is_unavailable_without_zero_fallback(tmp_path, bad_duration):
    _, metrics = _operation_metrics()
    context = {"attempt": 1, "elapsed_ns": bad_duration}
    event = _event("reconnect_recovery", 0, context=context)
    metrics.add(event)

    result = metrics.result()
    sample = result.samples[0]
    assert sample["elapsed_ns"] is None
    assert sample["context"]["source_elapsed_ns"] == 0
    assert sample["context"]["elapsed_ns"] == bad_duration
    assert context == {"attempt": 1, "elapsed_ns": bad_duration}
    summary = _summary(result, "reconnect_recovery")
    assert summary["count"] == 0
    assert summary["mean_ns"] is None
    assert summary["median_ns"] is None
    assert summary["p95_ns"] is None

    destination = tmp_path / "unavailable.csv"
    import_module("sparc.analysis.export").export_benchmark(result, destination)
    with destination.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    exported_sample = next(row for row in rows if row["row_type"] == "sample")
    assert exported_sample["elapsed_ns"] == ""
    assert json.loads(exported_sample["context_json"]) == sample["context"]
    exported_summary = next(row for row in rows if row["row_type"] == "summary")
    assert exported_summary["count"] == "0"
    assert exported_summary["mean_ns"] == ""
    assert exported_summary["median_ns"] == ""
    assert exported_summary["p95_ns"] == ""


def test_export_can_reconstruct_each_operation_from_raw_rows(tmp_path):
    _, metrics = _operation_metrics(capacity=10)
    metrics.add(_event("handshake", 100, context={"approval_included": False}))
    metrics.add(_event("handshake", 300, context={"approval_included": True}))
    metrics.add(_event("audit", 250, encoded_bytes=40, context={"event": "append"}))
    metrics.add(_event("reconnect_recovery", 0, context={"attempt": 3, "elapsed_ns": 700}))
    result = metrics.result()

    destination = tmp_path / "reconstruct.csv"
    import_module("sparc.analysis.export").export_benchmark(result, destination)
    with destination.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    sample_rows = [row for row in rows if row["row_type"] == "sample"]
    for operation in ("handshake", "audit", "reconnect_recovery"):
        exported = [row for row in sample_rows if row["operation"] == operation]
        durations = [int(row["elapsed_ns"]) for row in exported if row["success"] == "true"]
        summary = next(
            row for row in rows
            if row["row_type"] == "summary" and row["operation"] == operation
        )
        assert int(summary["count"]) == len(durations)
        assert float(summary["mean_ns"]) == pytest.approx(sum(durations) / len(durations))
        assert float(summary["median_ns"]) == pytest.approx(
            sorted(durations)[len(durations) // 2]
            if len(durations) % 2
            else (sorted(durations)[len(durations) // 2 - 1] + sorted(durations)[len(durations) // 2]) / 2
        )
