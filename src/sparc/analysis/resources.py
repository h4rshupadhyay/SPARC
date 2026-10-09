"""Bounded process CPU and memory sampling for analysis runs."""

from collections import deque
import math
import time
from typing import Protocol

import psutil

from ..models import SparcError
from .models import ResourceResult, ResourceSample


_MAX_SAMPLES = 3600
_MAX_PID = (1 << 31) - 1


class _Waiter(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...


def sample_resources(pid: int, stop: _Waiter, interval_s: float = 1) -> ResourceResult:
    """Sample process CPU and RSS until stopped, retaining at most one hour of data."""
    if type(pid) is not int or not 1 <= pid <= _MAX_PID:
        raise SparcError("invalid_analysis_input", "Process ID must be a positive bounded integer")
    if (
        isinstance(interval_s, bool)
        or not isinstance(interval_s, (int, float))
        or not math.isfinite(interval_s)
        or interval_s <= 0
    ):
        raise SparcError("invalid_analysis_input", "Sampling interval must be a finite positive number")
    if not callable(getattr(stop, "wait", None)):
        raise SparcError("invalid_analysis_input", "Stop signal must provide a wait method")

    interval = float(interval_s)
    retained: deque[ResourceSample] = deque(maxlen=_MAX_SAMPLES)
    window_truncated = False

    try:
        process = psutil.Process(pid)
        # The first psutil CPU reading only establishes the baseline. Discard it
        # before waiting for the first measured sampling interval.
        process.cpu_percent(interval=None)
        while not stop.wait(interval):
            try:
                monotonic_ns = time.monotonic_ns()
                cpu_percent = process.cpu_percent(interval=None)
                rss_bytes = process.memory_info().rss
            except (psutil.NoSuchProcess, ProcessLookupError):
                break

            if len(retained) == _MAX_SAMPLES:
                window_truncated = True
            retained.append(
                ResourceSample(
                    monotonic_ns=monotonic_ns,
                    cpu_percent=cpu_percent,
                    rss_bytes=rss_bytes,
                )
            )
    except (psutil.NoSuchProcess, ProcessLookupError):
        # A process that exits during setup produces a finite empty result.
        pass

    samples = list(retained)
    peak_observed_rss_bytes = max((sample.rss_bytes for sample in samples), default=0)
    return ResourceResult(
        samples=samples,
        interval_s=interval,
        peak_observed_rss_bytes=peak_observed_rss_bytes,
        window_truncated=window_truncated,
    )
