from collections import Counter
from importlib import import_module
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from sparc.models import SparcError


OPERATIONS = ("hash", "sign", "encrypt", "decrypt", "recompute_hash", "verify")


def _benchmark_module():
    try:
        benchmark = import_module("sparc.analysis.benchmark")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.benchmark":
            raise
        pytest.fail("sparc.analysis.benchmark must be implemented")
    assert callable(getattr(benchmark, "run_local_benchmarks", None)), (
        "sparc.analysis.benchmark.run_local_benchmarks must be implemented"
    )
    return benchmark


def _run_local_benchmarks(*args, **kwargs):
    benchmark = _benchmark_module()
    return benchmark.run_local_benchmarks(*args, **kwargs)


def test_benchmark_measures_six_operations():
    result = _run_local_benchmarks(sizes=(64,), warmups=0, repetitions=2)

    assert result.complete is True
    assert Counter(sample["operation"] for sample in result.samples) == {
        operation: 2 for operation in OPERATIONS
    }
    assert all(sample["success"] is True for sample in result.samples)
    assert {sample["payload_bytes"] for sample in result.samples} == {64}

    summary_counts = {row["operation"]: row["count"] for row in result.summary}
    assert summary_counts == {operation: 2 for operation in OPERATIONS}


def test_encryption_nonces_are_unique_including_warmups(monkeypatch):
    original_encrypt = AESGCM.encrypt
    nonces = []

    def recording_encrypt(self, nonce, data, associated_data):
        nonces.append(bytes(nonce))
        return original_encrypt(self, nonce, data, associated_data)

    monkeypatch.setattr(AESGCM, "encrypt", recording_encrypt)
    result = _run_local_benchmarks(sizes=(64,), warmups=1, repetitions=2)

    assert result.complete is True
    assert len(nonces) == 1 + 1 + 2  # setup, warmup, and two measured encryptions
    assert all(len(nonce) == 12 for nonce in nonces)
    assert len(set(nonces)) == len(nonces)


def test_timers_exclude_keygen_encoding_and_io(monkeypatch):
    benchmark = _benchmark_module()
    from sparc import encoding

    timer_active = False
    clock_calls = 0
    clock_events = []
    primitive_events = []

    def record(name):
        primitive_events.append((name, timer_active))

    def fake_clock():
        nonlocal timer_active, clock_calls
        assert not timer_active, "timer calls must not nest"
        timer_active = True
        clock_calls += 1
        clock_events.append(clock_calls)
        return clock_calls * 100

    def end_clock():
        nonlocal timer_active, clock_calls
        assert timer_active
        clock_calls += 1
        clock_events.append(clock_calls)
        timer_active = False
        return clock_calls * 100

    # Each measured operation receives one start and one stop value; setup has no clock calls.
    def controlled_clock():
        if timer_active:
            return end_clock()
        return fake_clock()

    monkeypatch.setattr(benchmark.time, "perf_counter_ns", controlled_clock)

    original_generate = Ed25519PrivateKey.generate
    generated_keys = []

    class PublicKeyAdapter:
        def __init__(self, key):
            self._key = key

        def verify(self, signature, data):
            record("verify")
            return self._key.verify(signature, data)

        def __getattr__(self, name):
            return getattr(self._key, name)

    class PrivateKeyAdapter:
        def __init__(self, key):
            self._key = key

        def sign(self, data):
            record("sign")
            return self._key.sign(data)

        def public_key(self):
            return PublicKeyAdapter(self._key.public_key())

        def __getattr__(self, name):
            return getattr(self._key, name)

    def record_generate(cls, *args, **kwargs):
        record("keygen")
        key = PrivateKeyAdapter(original_generate(*args, **kwargs))
        generated_keys.append(key)
        return key

    monkeypatch.setattr(Ed25519PrivateKey, "generate", classmethod(record_generate))

    original_canonical = encoding.canonical

    def record_canonical(value):
        record("canonical")
        return original_canonical(value)

    monkeypatch.setattr(encoding, "canonical", record_canonical)
    if getattr(benchmark, "canonical", None) is original_canonical:
        monkeypatch.setattr(benchmark, "canonical", record_canonical)

    original_aesgcm = benchmark.AESGCM

    def record_aes_setup(key):
        record("aes_setup")
        return original_aesgcm(key)

    monkeypatch.setattr(benchmark, "AESGCM", record_aes_setup)

    original_hash = hashlib.sha256

    def record_hash(*args, **kwargs):
        record("hash")
        return original_hash(*args, **kwargs)

    monkeypatch.setattr(hashlib, "sha256", record_hash)

    original_encrypt = AESGCM.encrypt

    def record_encrypt(self, nonce, data, associated_data):
        record("encrypt")
        return original_encrypt(self, nonce, data, associated_data)

    monkeypatch.setattr(AESGCM, "encrypt", record_encrypt)

    original_decrypt = AESGCM.decrypt

    def record_decrypt(self, nonce, data, associated_data):
        record("decrypt")
        return original_decrypt(self, nonce, data, associated_data)

    monkeypatch.setattr(AESGCM, "decrypt", record_decrypt)

    result = benchmark.run_local_benchmarks(sizes=(64,), warmups=0, repetitions=1)

    assert result.complete is True
    assert clock_calls == 12
    assert clock_events == list(range(1, 13))
    assert all(sample["elapsed_ns"] == 100 for sample in result.samples)
    assert generated_keys
    assert all(not active for name, active in primitive_events if name == "keygen")
    assert all(not active for name, active in primitive_events if name == "canonical")
    assert all(not active for name, active in primitive_events if name == "aes_setup")
    assert Counter(name for name, active in primitive_events if active) == {
        "hash": 2,
        "sign": 1,
        "verify": 1,
        "encrypt": 1,
        "decrypt": 1,
    }
    assert not timer_active


def test_failed_primitive_keeps_raw_row_and_is_excluded_from_summary(monkeypatch):
    original_generate = Ed25519PrivateKey.generate
    sign_calls = 0

    class FailingPrivateKeyAdapter:
        def __init__(self, key):
            self._key = key

        def sign(self, data):
            nonlocal sign_calls
            sign_calls += 1
            if sign_calls == 3:  # setup signature, first measured call, then this failure
                raise RuntimeError("synthetic signing failure")
            return self._key.sign(data)

        def __getattr__(self, name):
            return getattr(self._key, name)

    def generate_with_adapter(cls, *args, **kwargs):
        return FailingPrivateKeyAdapter(original_generate(*args, **kwargs))

    monkeypatch.setattr(Ed25519PrivateKey, "generate", classmethod(generate_with_adapter))
    result = _run_local_benchmarks(sizes=(64,), warmups=0, repetitions=2)

    assert result.complete is False
    signing_rows = [row for row in result.samples if row["operation"] == "sign"]
    assert len(signing_rows) == 2
    assert Counter(row["success"] for row in signing_rows) == {True: 1, False: 1}
    failed_row = next(row for row in signing_rows if not row["success"])
    assert "RuntimeError" in failed_row.values()

    signing_summary = [row for row in result.summary if row["operation"] == "sign"]
    assert len(signing_summary) == 1
    assert signing_summary[0]["count"] == 1


def test_cancel_is_incomplete_before_work_and_at_final_boundary(monkeypatch):
    from threading import Event

    cancel = Event()
    cancel.set()
    pre_canceled = _run_local_benchmarks(sizes=(64,), warmups=0, repetitions=1, cancel=cancel)
    assert pre_canceled.complete is False
    assert pre_canceled.samples == []

    benchmark = _benchmark_module()
    cancel.clear()
    clock_calls = 0

    def cancel_after_last_clock():
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls == 12:
            cancel.set()
        return clock_calls * 100

    monkeypatch.setattr(benchmark.time, "perf_counter_ns", cancel_after_last_clock)
    final_boundary = benchmark.run_local_benchmarks(
        sizes=(64,), warmups=0, repetitions=1, cancel=cancel
    )
    assert len(final_boundary.samples) == len(OPERATIONS)
    assert final_boundary.complete is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"sizes": ()},
        {"sizes": (64, 64)},
        {"sizes": (32,)},
        {"sizes": (64, 1024, 16384, 64)},
        {"warmups": -1},
        {"warmups": 11},
        {"warmups": True},
        {"warmups": 1.5},
        {"repetitions": 0},
        {"repetitions": 1001},
        {"repetitions": False},
        {"repetitions": 1.5},
    ],
)
def test_invalid_workload_bounds_raise_domain_error(overrides):
    with pytest.raises(SparcError):
        _run_local_benchmarks(**overrides)
