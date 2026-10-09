"""Bounded collection and summaries for public peer-operation observations."""

from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone
import math
import platform
import sys
from statistics import median
from typing import Any
import uuid

import Crypto
import cryptography

from ..models import ServiceEvent
from .models import BenchmarkResult


_CAPACITY_MAX = 1000


class OperationMetrics:
    """Keep a fixed-size window of copied, public operation measurements."""

    def __init__(self, capacity: int = _CAPACITY_MAX) -> None:
        if type(capacity) is not int or not 1 <= capacity <= _CAPACITY_MAX:
            raise ValueError("capacity must be an integer from 1 through 1000")
        self.capacity = capacity
        self._samples: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._window_truncated = False

    def add(self, event: ServiceEvent) -> None:
        """Retain a safe copy of a public operation event, if well formed."""
        if not isinstance(event, ServiceEvent) or event.kind != "operation_metrics":
            return
        data = event.data
        if not isinstance(data, dict):
            return
        operation = data.get("operation")
        success = data.get("success")
        elapsed = data.get("elapsed_ns")
        if not isinstance(operation, str) or not operation or type(success) is not bool:
            return

        context = data.get("context", {})
        if not isinstance(context, dict):
            context = {}
        try:
            copied_context = deepcopy(context)
        except (TypeError, ValueError, RecursionError):
            copied_context = {}

        source_elapsed = elapsed if type(elapsed) is int and elapsed >= 0 else None
        sample: dict[str, Any] = {
            "operation": operation,
            "elapsed_ns": source_elapsed,
            "success": success,
            "context": copied_context,
        }
        for field in ("encoded_bytes", "frame_bytes"):
            value = data.get(field)
            sample[field] = value if type(value) is int and value >= 0 else None

        if operation == "reconnect_recovery":
            recovery_elapsed = context.get("elapsed_ns")
            sample["elapsed_ns"] = (
                recovery_elapsed
                if type(recovery_elapsed) is int and recovery_elapsed >= 0
                else None
            )
            copied_context["source_elapsed_ns"] = source_elapsed
        elif operation == "reconnect_attempt":
            # The service reports this wrapper zero as an outcome diagnostic.
            # It does not time an individual reconnect attempt.
            sample["elapsed_ns"] = None
            copied_context["source_elapsed_ns"] = source_elapsed

        if len(self._samples) == self.capacity:
            self._window_truncated = True
        self._samples.append(sample)

    def result(self) -> BenchmarkResult:
        samples = deepcopy(list(self._samples))
        durations: dict[str, list[int]] = defaultdict(list)
        for sample in samples:
            elapsed = sample["elapsed_ns"]
            if sample["success"] and type(elapsed) is int and elapsed >= 0:
                durations[sample["operation"]].append(elapsed)

        summaries = []
        for operation in sorted({sample["operation"] for sample in samples}):
            values = durations.get(operation, [])
            ordered = sorted(values)
            p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else None
            summaries.append({
                "operation": operation,
                "count": len(values),
                "mean_ns": sum(values) / len(values) if values else None,
                "median_ns": median(values) if values else None,
                "p95_ns": p95,
                "throughput_bytes_s": None,
            })

        metadata = {
            "run_id": uuid.uuid4().hex,
            "test_type": "operation_metrics",
            "evidence_mode": "retained_service_observations",
            "sample_count": len(samples),
            "utc": datetime.now(timezone.utc).isoformat(),
            "platform": sys.platform,
            "python": platform.python_version(),
            "library_versions": {
                "cryptography": cryptography.__version__,
                "pycryptodome": Crypto.__version__,
            },
            "window": {
                "capacity": self.capacity,
                "retained_samples": len(samples),
                "truncated": self._window_truncated,
                "policy": "latest operation events; successful available durations only in summaries",
            },
            "units": {
                "elapsed_ns": "nanoseconds",
                "encoded_bytes": "encoded audit/log bytes when supplied by the service",
                "frame_bytes": "complete protected frame bytes when supplied by the service",
            },
            "definitions": {
                "mean_ns": "arithmetic mean of successful retained samples with available durations",
                "median_ns": "median of successful retained samples with available durations",
                "p95_ns": "nearest-rank 95th percentile of successful retained durations",
                "reconnect_recovery": "duration from context.elapsed_ns; source_elapsed_ns retains the service wrapper duration",
                "reconnect_attempt": "outcome diagnostic; wrapper duration is not a measured attempt span",
                "audit_verify": "verifier duration over the captured committed prefix; excludes prior snapshot acquisition and GUI scheduling",
                "audit_append": "service-reported audit append duration; encoded bytes and frame bytes are separate fields",
                "window": "bounded best-effort observations; service event drops are not reconstructed",
            },
        }
        return BenchmarkResult(metadata=metadata, samples=samples, summary=summaries, complete=True)
