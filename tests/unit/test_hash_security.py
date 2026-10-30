"""Full-digest checks for the bounded synthetic hashing laboratory."""

import csv
import hashlib
from importlib import import_module
from threading import Event

import pytest


def _lab():
    try:
        return import_module("sparc.analysis.hashing")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.hashing":
            raise
        pytest.fail("Hash security laboratory must be implemented")


@pytest.mark.parametrize("mode", ["collision", "preimage", "second_preimage"])
def test_default_search_uses_full_sha256_and_reports_no_prefix_matches(mode):
    result = _lab().run_hash_search(mode, max_attempts=4096, seed=7)
    assert result.digest_bits == 256
    assert result.outcome == "budget_exhausted"
    assert result.complete
    assert result.attempts == 4096
    assert result.elapsed_ns >= 0
    assert result.input_b is None
    if mode == "second_preimage":
        assert hashlib.sha256(result.input_a).hexdigest() == result.target_digest
    elif mode == "preimage":
        assert len(result.target_digest) == 64
        assert result.input_a is None
    else:
        assert result.target_digest is None
        assert result.input_a is None
    repeated = _lab().run_hash_search(mode, max_attempts=4096, seed=7)
    assert (repeated.attempts, repeated.target_digest, repeated.input_a, repeated.input_b) == (
        result.attempts, result.target_digest, result.input_a, result.input_b,
    )


@pytest.mark.parametrize("mode", ["collision", "preimage", "second_preimage"])
def test_full_sha256_search_reports_only_its_finite_budget(mode):
    result = _lab().run_hash_search(mode, digest_bits=256, max_attempts=10, seed=7)
    assert result.outcome == "budget_exhausted"
    assert result.attempts == 10
    assert result.complete
    assert result.input_b is None
    if mode == "second_preimage":
        assert hashlib.sha256(result.input_a).hexdigest() == result.target_digest
    elif mode == "preimage":
        assert len(result.target_digest) == 64
        assert result.input_a is None
    else:
        assert result.target_digest is None
        assert result.input_a is None


def test_cancel_preserves_partial_attempt_count_and_incomplete_label():
    cancel = Event()
    progress = []

    def progressed(completed, total):
        progress.append((completed, total))
        cancel.set()

    result = _lab().run_hash_search(
        "preimage", digest_bits=256, max_attempts=1000, seed=7,
        cancel=cancel, on_progress=progressed,
    )
    assert 0 < result.attempts < 1000
    assert result.outcome == "canceled"
    assert not result.complete
    assert progress[-1][0] == result.attempts
    before_start = _lab().run_hash_search("collision", cancel=cancel)
    assert before_start.attempts == 0
    assert before_start.outcome == "canceled"


@pytest.mark.parametrize("kwargs", [
    {"mode": "unknown"}, {"digest_bits": 0}, {"digest_bits": True},
    {"digest_bits": 8}, {"digest_bits": 12}, {"digest_bits": 16},
    {"max_attempts": 0}, {"max_attempts": 100001}, {"max_attempts": True},
    {"seed": -1}, {"seed": 2**64}, {"seed": True},
])
def test_invalid_or_unbounded_searches_are_rejected(kwargs):
    parameters = {"mode": "collision", **kwargs}
    with pytest.raises(ValueError):
        _lab().run_hash_search(**parameters)


def test_hash_csv_retains_full_target_units_and_bounded_scope(tmp_path):
    lab = _lab()
    result = lab.run_hash_search("second_preimage", max_attempts=4096)
    path = tmp_path / "hash.csv"
    lab.export_hash_search(result, path)
    with path.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["digest_bits"] == "256"
    assert row["scope"] == "full_sha256_bounded_search"
    assert row["outcome"] == "budget_exhausted"
    assert int(row["attempts"]) == result.attempts
    assert int(row["elapsed_ns"]) == result.elapsed_ns
    assert row["input_b_hex"] == ""
    assert hashlib.sha256(bytes.fromhex(row["input_a_hex"])).hexdigest() == row["target_digest"]
