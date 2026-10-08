from dataclasses import FrozenInstanceError, fields

import pytest

from sparc.analysis.models import (
    BenchmarkResult,
    Difference,
    LabResult,
    ResourceResult,
    ResourceSample,
    SampleStats,
    Trial,
)
from sparc.analysis.sensitivity import compare_ciphertexts
from sparc.models import SparcError


def test_one_bit_difference_has_distinct_units():
    difference = compare_ciphertexts(bytes(16), bytes(15) + b"\x01")

    assert difference == Difference(
        bit_percent=100 / 128,
        byte_percent=100 / 16,
        hex_percent=100 / 32,
    )


def test_all_bits_differ():
    difference = compare_ciphertexts(bytes(16), bytes([0xFF]) * 16)

    assert difference == Difference(bit_percent=100.0, byte_percent=100.0, hex_percent=100.0)


@pytest.mark.parametrize(
    "left,right",
    [
        (b"", bytes(16)),
        (bytes(15), bytes(16)),
        (bytes(17), bytes(17)),
        (bytes(16), bytes(15)),
    ],
)
def test_bad_block_lengths(left, right):
    with pytest.raises(SparcError):
        compare_ciphertexts(left, right)


@pytest.mark.parametrize(
    "left,right",
    [
        ("0" * 16, bytes(16)),
        (bytes(16), bytearray(16)),
        (None, bytes(16)),
        (bytes(16), [0] * 16),
    ],
)
def test_bad_ciphertext_types_are_domain_errors(left, right):
    with pytest.raises(SparcError):
        compare_ciphertexts(left, right)


def test_analysis_result_types_match_shared_schema():
    expected_fields = {
        Difference: ("bit_percent", "byte_percent", "hex_percent"),
        Trial: (
            "case_index",
            "mode",
            "bit_index",
            "key",
            "block",
            "modified_key",
            "modified_block",
            "baseline_ciphertext",
            "modified_ciphertext",
            "difference",
        ),
        LabResult: ("seed", "cases", "trials", "summary", "complete"),
        SampleStats: ("count", "mean_ns", "median_ns", "p95_ns", "throughput_bytes_s"),
        BenchmarkResult: ("metadata", "samples", "summary", "complete"),
        ResourceSample: ("monotonic_ns", "cpu_percent", "rss_bytes"),
        ResourceResult: ("samples", "interval_s", "peak_observed_rss_bytes", "window_truncated"),
    }

    for record_type, names in expected_fields.items():
        assert tuple(field.name for field in fields(record_type)) == names
        assert record_type.__dataclass_params__.frozen


def test_difference_is_immutable():
    difference = Difference(bit_percent=1.0, byte_percent=2.0, hex_percent=3.0)

    with pytest.raises(FrozenInstanceError):
        difference.bit_percent = 4.0
