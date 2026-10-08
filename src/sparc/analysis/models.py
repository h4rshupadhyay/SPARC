"""Result records shared by analysis modules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Difference:
    bit_percent: float
    byte_percent: float
    hex_percent: float


@dataclass(frozen=True)
class Trial:
    case_index: int
    mode: str
    bit_index: int
    key: bytes
    block: bytes
    modified_key: bytes
    modified_block: bytes
    baseline_ciphertext: bytes
    modified_ciphertext: bytes
    difference: Difference


@dataclass(frozen=True)
class LabResult:
    seed: int
    cases: int
    trials: list[Trial]
    summary: dict
    complete: bool


@dataclass(frozen=True)
class SampleStats:
    count: int
    mean_ns: float | None
    median_ns: float | None
    p95_ns: int | None
    throughput_bytes_s: float | None


@dataclass(frozen=True)
class BenchmarkResult:
    metadata: dict
    samples: list[dict]
    summary: list[dict]
    complete: bool


@dataclass(frozen=True)
class ResourceSample:
    monotonic_ns: int
    cpu_percent: float
    rss_bytes: int


@dataclass(frozen=True)
class ResourceResult:
    samples: list[ResourceSample]
    interval_s: float
    peak_observed_rss_bytes: int
    window_truncated: bool = False
