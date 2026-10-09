from importlib import import_module
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from sparc.analysis.models import ResourceResult


def _resources():
    try:
        resources = import_module("sparc.analysis.resources")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.resources":
            raise
        pytest.fail("sparc.analysis.resources must be implemented")
    assert callable(getattr(resources, "sample_resources", None)), (
        "sample_resources must be implemented"
    )
    return resources


class _StopAfter(Event):
    def __init__(self, false_waits):
        super().__init__()
        self.false_waits = false_waits
        self.wait_count = 0
        self.calls = []

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        self.wait_count += 1
        return self.wait_count > self.false_waits


def test_resource_peak_is_observed_sample_peak(monkeypatch):
    resources = _resources()
    rss_values = iter((100, 900, 500))
    calls = []

    class FakeProcess:
        def cpu_percent(self, interval=None):
            calls.append(("cpu", interval))
            return 0.0 if len([call for call in calls if call[0] == "cpu"]) == 1 else 12.5

        def memory_info(self):
            return SimpleNamespace(rss=next(rss_values))

    stop = _StopAfter(false_waits=3)
    process = FakeProcess()
    monkeypatch.setattr(resources.psutil, "Process", lambda pid: process)
    original_wait = stop.wait

    def recording_wait(timeout=None):
        calls.append(("wait", timeout))
        return original_wait(timeout)

    monkeypatch.setattr(stop, "wait", recording_wait)

    result = resources.sample_resources(123, stop, interval_s=0.25)

    assert isinstance(result, ResourceResult)
    assert len(result.samples) == 3
    assert [sample.rss_bytes for sample in result.samples] == [100, 900, 500]
    assert result.peak_observed_rss_bytes == max(sample.rss_bytes for sample in result.samples)
    assert calls[0][0] == "cpu"
    assert calls[1] == ("wait", 0.25)
    assert result.interval_s == 0.25
    assert result.window_truncated is False


def test_stop_wakes_sampler(monkeypatch):
    resources = _resources()
    primed = Event()

    class FakeProcess:
        def cpu_percent(self, interval=None):
            primed.set()
            return 0.0

        def memory_info(self):
            return SimpleNamespace(rss=512)

    monkeypatch.setattr(resources.psutil, "Process", lambda pid: FakeProcess())
    stop = Event()
    result_box = []
    error_box = []

    def run_sampler():
        try:
            result_box.append(resources.sample_resources(456, stop, interval_s=30))
        except Exception as error:
            error_box.append(error)

    worker = Thread(target=run_sampler)
    worker.start()
    assert primed.wait(timeout=2)
    stop.set()
    worker.join(timeout=1)

    assert not worker.is_alive(), "sampler should wake promptly when stop is set"
    assert not error_box
    assert len(result_box) == 1
    assert isinstance(result_box[0], ResourceResult)


def test_samples_bound_3600_and_window_label(monkeypatch):
    resources = _resources()
    sample_index = 0

    class FakeProcess:
        def cpu_percent(self, interval=None):
            return 0.0

        def memory_info(self):
            nonlocal sample_index
            sample_index += 1
            rss = 10_000_000 if sample_index == 1 else sample_index - 1
            return SimpleNamespace(rss=rss)

    monkeypatch.setattr(resources.psutil, "Process", lambda pid: FakeProcess())
    stop = _StopAfter(false_waits=3601)

    result = resources.sample_resources(789, stop, interval_s=0.001)

    assert isinstance(result, ResourceResult)
    assert len(result.samples) <= 3600
    assert len(result.samples) == 3600
    assert result.window_truncated is True
    assert result.samples[0].rss_bytes == 1
    assert result.samples[-1].rss_bytes == 3600
    assert result.peak_observed_rss_bytes == max(sample.rss_bytes for sample in result.samples)
    assert result.peak_observed_rss_bytes == 3600


def test_process_exit_returns_finite_result_with_collected_samples(monkeypatch):
    resources = _resources()
    pid = 987
    cpu_calls = 0

    class FakeProcess:
        def cpu_percent(self, interval=None):
            nonlocal cpu_calls
            cpu_calls += 1
            if cpu_calls == 3:
                raise resources.psutil.NoSuchProcess(pid)
            return 0.0 if cpu_calls == 1 else 8.5

        def memory_info(self):
            return SimpleNamespace(rss=4096)

    monkeypatch.setattr(resources.psutil, "Process", lambda requested_pid: FakeProcess())
    stop = _StopAfter(false_waits=10)

    result = resources.sample_resources(pid, stop, interval_s=0.001)

    assert isinstance(result, ResourceResult)
    assert len(result.samples) == 1
    assert result.samples[0].rss_bytes == 4096
    assert result.peak_observed_rss_bytes == 4096
