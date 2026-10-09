from importlib import import_module

import pytest

from sparc.analysis.models import SampleStats
from sparc.models import SparcError


def _summarize(*args, **kwargs):
    try:
        benchmark = import_module("sparc.analysis.benchmark")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.benchmark":
            raise
        pytest.fail("sparc.analysis.benchmark.summarize must be implemented")
    summarize = getattr(benchmark, "summarize", None)
    assert callable(summarize), "sparc.analysis.benchmark.summarize must be implemented"
    return summarize(*args, **kwargs)


def test_stats_use_nearest_rank_and_operation_time():
    stats = _summarize([1, 2, 3, 4], payload_bytes=16)

    assert isinstance(stats, SampleStats)
    assert stats.count == 4
    assert stats.mean_ns == 2.5
    assert stats.median_ns == 2.5
    assert stats.p95_ns == 4
    assert stats.throughput_bytes_s == 6_400_000_000


def test_empty_samples_have_unavailable_statistics():
    stats = _summarize([], payload_bytes=16)

    assert stats == SampleStats(
        count=0,
        mean_ns=None,
        median_ns=None,
        p95_ns=None,
        throughput_bytes_s=None,
    )


def test_zero_duration_has_zero_statistics_and_unavailable_throughput():
    stats = _summarize([0, 0], payload_bytes=16)

    assert stats.count == 2
    assert stats.mean_ns == 0
    assert stats.median_ns == 0
    assert stats.p95_ns == 0
    assert stats.throughput_bytes_s is None


def test_zero_payload_has_zero_throughput_for_positive_duration():
    stats = _summarize([5, 5], payload_bytes=0)

    assert stats.count == 2
    assert stats.throughput_bytes_s == 0


@pytest.mark.parametrize("samples_ns", [[-1], [1, -1], [1.5], [True], [False]])
def test_invalid_timings_are_domain_errors(samples_ns):
    with pytest.raises(SparcError):
        _summarize(samples_ns, payload_bytes=16)


@pytest.mark.parametrize("payload_bytes", [-1, 1.5, True, False, "16", None])
def test_invalid_payload_sizes_are_domain_errors(payload_bytes):
    with pytest.raises(SparcError):
        _summarize([1], payload_bytes=payload_bytes)
