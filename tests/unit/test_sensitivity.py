from collections import Counter
import hashlib
from statistics import mean, pstdev
from threading import Event

import pytest

from sparc.analysis import sensitivity
from sparc.models import SparcError


def _run_sensitivity(*args, **kwargs):
    runner = getattr(sensitivity, "run_sensitivity", None)
    assert callable(runner), "sensitivity.run_sensitivity must be implemented"
    return runner(*args, **kwargs)


def _population_stats(values):
    return {
        "count": len(values),
        "mean": mean(values),
        "min": min(values),
        "max": max(values),
        "population_std": pstdev(values),
    }


def test_batch_counts_and_recomputed_summary():
    result = _run_sensitivity(seed=91, cases=2)

    assert result.seed == 91
    assert result.cases == 2
    assert result.complete is True
    assert Counter(trial.mode for trial in result.trials) == {
        "plaintext": 256,
        "key": 512,
    }

    for mode in ("plaintext", "key"):
        mode_trials = [trial for trial in result.trials if trial.mode == mode]
        for metric in ("bit_percent", "byte_percent", "hex_percent"):
            values = [getattr(trial.difference, metric) for trial in mode_trials]
            actual = result.summary[mode][metric]
            expected = _population_stats(values)

            assert actual["count"] == expected["count"]
            assert actual["mean"] == pytest.approx(expected["mean"])
            assert actual["min"] == pytest.approx(expected["min"])
            assert actual["max"] == pytest.approx(expected["max"])
            assert actual["population_std"] == pytest.approx(expected["population_std"])


def test_default_counts():
    result = _run_sensitivity()

    assert result.cases == 50
    assert result.complete is True
    assert Counter(trial.mode for trial in result.trials) == {
        "plaintext": 6400,
        "key": 12800,
    }


def test_repeated_run_is_deterministic():
    first = _run_sensitivity(seed=1234, cases=2)
    second = _run_sensitivity(seed=1234, cases=2)

    assert second == first


@pytest.mark.parametrize("negative", [False, True])
def test_batch_preserves_extremely_large_seed_decimal_spelling(negative):
    magnitude = 10**5000
    seed = -magnitude if negative else magnitude
    seed_text = ("-" if negative else "") + "1" + "0" * 5000

    result = _run_sensitivity(seed=seed, cases=1)

    first_trial = result.trials[0]
    assert first_trial.key == hashlib.sha256(f"SPARC-LAB-v1:key:{seed_text}:0".encode("utf-8")).digest()
    assert first_trial.block == hashlib.sha256(f"SPARC-LAB-v1:block:{seed_text}:0".encode("utf-8")).digest()[:16]


def test_batch_encrypts_one_baseline_per_case(monkeypatch):
    original_new = sensitivity.AES.new
    encryptions = []

    class CountingCipher:
        def __init__(self, cipher):
            self._cipher = cipher

        def encrypt(self, block):
            encryptions.append(block)
            return self._cipher.encrypt(block)

    def counting_new(*args, **kwargs):
        return CountingCipher(original_new(*args, **kwargs))

    monkeypatch.setattr(sensitivity.AES, "new", counting_new)
    _run_sensitivity(seed=42, cases=2)

    assert len(encryptions) == 2 * (1 + 128 + 256)


@pytest.mark.parametrize("stop_at", [5, 128, 384])
def test_canceled_batch_is_partial_and_incomplete(stop_at):
    cancel = Event()
    progress_updates = []

    def cancel_after_first_update(current, total):
        progress_updates.append((current, total))
        if current == stop_at:
            cancel.set()

    result = _run_sensitivity(seed=9, cases=2, cancel=cancel, progress=cancel_after_first_update)

    assert progress_updates == [(current, 768) for current in range(stop_at + 1)]
    assert result.complete is False
    assert result.cases == 2
    assert len(result.trials) == stop_at
    assert {trial.case_index for trial in result.trials} == {0}
    assert Counter(trial.mode for trial in result.trials) == {
        mode: count for mode, count in (("plaintext", min(stop_at, 128)), ("key", max(0, stop_at - 128))) if count
    }

    for mode in ("plaintext", "key"):
        mode_trials = [trial for trial in result.trials if trial.mode == mode]
        for metric in ("bit_percent", "byte_percent", "hex_percent"):
            values = [getattr(trial.difference, metric) for trial in mode_trials]
            stats = result.summary[mode][metric]
            if values:
                expected = _population_stats(values)
                assert stats["count"] == expected["count"]
                assert stats["mean"] == pytest.approx(expected["mean"])
                assert stats["min"] == pytest.approx(expected["min"])
                assert stats["max"] == pytest.approx(expected["max"])
                assert stats["population_std"] == pytest.approx(expected["population_std"])
            else:
                assert stats == {"count": 0, "mean": None, "min": None, "max": None, "population_std": None}


def test_pre_canceled_batch_reports_empty_summary_without_encrypting(monkeypatch):
    cancel = Event()
    cancel.set()
    progress_updates = []
    original_new = sensitivity.AES.new
    encryptions = []

    class CountingCipher:
        def __init__(self, cipher):
            self._cipher = cipher

        def encrypt(self, block):
            encryptions.append(block)
            return self._cipher.encrypt(block)

    def counting_new(*args, **kwargs):
        return CountingCipher(original_new(*args, **kwargs))

    monkeypatch.setattr(sensitivity.AES, "new", counting_new)
    result = _run_sensitivity(seed=42, cases=3, cancel=cancel, progress=lambda *row: progress_updates.append(row))

    assert result.cases == 3
    assert result.trials == []
    assert result.complete is False
    assert progress_updates == [(0, 3 * 384)]
    assert encryptions == []
    assert set(result.summary) == {"plaintext", "key"}
    for mode_summary in result.summary.values():
        assert set(mode_summary) == {"bit_percent", "byte_percent", "hex_percent"}
        for stats in mode_summary.values():
            assert stats == {
                "count": 0,
                "mean": None,
                "min": None,
                "max": None,
                "population_std": None,
            }


def test_cancellation_at_final_progress_keeps_trials_but_marks_incomplete():
    cancel = Event()
    progress_updates = []

    def cancel_on_final_trial(current, total):
        progress_updates.append((current, total))
        if current == total:
            cancel.set()

    result = _run_sensitivity(seed=51, cases=1, cancel=cancel, progress=cancel_on_final_trial)

    assert len(result.trials) == 384
    assert progress_updates[0] == (0, 384)
    assert progress_updates[-1] == (384, 384)
    assert len(progress_updates) == 385
    assert result.complete is False


@pytest.mark.parametrize("cases", [0, 51, True, 1.5, None, "2"])
def test_invalid_case_counts_are_domain_errors(cases):
    with pytest.raises(SparcError):
        _run_sensitivity(seed=42, cases=cases)


@pytest.mark.parametrize("seed", [True, 1.5, "42", None])
def test_invalid_seed_is_domain_error(seed):
    with pytest.raises(SparcError):
        _run_sensitivity(seed=seed, cases=1)


@pytest.mark.parametrize("seed", [-23, 2**100])
def test_negative_and_large_integer_seeds_are_supported(seed):
    assert _run_sensitivity(seed=seed, cases=1) == _run_sensitivity(seed=seed, cases=1)
