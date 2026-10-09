"""Verified, audited peer-to-peer message performance measurements."""

from dataclasses import asdict
from datetime import datetime, timezone
import platform
import sys
import time
from threading import Event
from typing import TYPE_CHECKING
import uuid

import Crypto
import cryptography

from ..models import SparcError
from .benchmark import _ALLOWED_SIZES, summarize
from .models import BenchmarkResult

if TYPE_CHECKING:
    from ..peer.service import PeerService


def _validate_inputs(
    sizes: tuple[int, ...], warmups: int, repetitions: int,
    cancel: Event | None, evidence_mode: str,
) -> None:
    if (
        not isinstance(sizes, tuple)
        or not 1 <= len(sizes) <= 3
        or any(type(size) is not int or size not in _ALLOWED_SIZES for size in sizes)
        or len(set(sizes)) != len(sizes)
    ):
        raise SparcError("invalid_analysis_input", "Sizes must be a tuple of one to three distinct allowed workloads")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or not 0 <= warmups <= 10:
        raise SparcError("invalid_analysis_input", "Warmups must be an integer from 0 through 10")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 100:
        raise SparcError("invalid_analysis_input", "Repetitions must be an integer from 1 through 100")
    if cancel is not None and not isinstance(cancel, Event):
        raise SparcError("invalid_analysis_input", "Cancellation event is invalid")
    if not isinstance(evidence_mode, str) or not evidence_mode:
        raise SparcError("invalid_analysis_input", "Evidence mode must be a nonempty string")


def run_network_benchmark(
    service: "PeerService",
    sizes: tuple[int, ...] = (64, 1024, 16384),
    warmups: int = 10,
    repetitions: int = 100,
    cancel: Event | None = None,
    evidence_mode: str = "unspecified",
) -> BenchmarkResult:
    """Measure sequential sends confirmed by the peer service's verified receipts."""
    _validate_inputs(sizes, warmups, repetitions, cancel, evidence_mode)

    if service.state != "connected":
        raise SparcError("invalid_state", "A connected peer session is required for a network benchmark")

    run_id = uuid.uuid4().hex
    metadata = {
        "run_id": run_id,
        "utc": datetime.now(timezone.utc).isoformat(),
        "test_type": "network_round_trip",
        "sizes": list(sizes),
        "warmups": warmups,
        "repetitions": repetitions,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "library_versions": {
            "cryptography": cryptography.__version__,
            "pycryptodome": Crypto.__version__,
        },
        "evidence_mode": evidence_mode,
        "units": {
            "payload_bytes": "bytes",
            "characters": "Unicode code points",
            "frame_bytes": "protected frame bytes",
            "elapsed_ns": "nanoseconds",
            "goodput_bytes_s": "confirmed plaintext bytes per second",
            "characters_s": "confirmed Unicode code points per second",
        },
        "definitions": {
            "timing_scope": "From the service-recorded send start through its verified receipt finish; includes encoding, cryptography, durable audit, network delivery, and pacing",
            "goodput": "Confirmed plaintext bytes divided by the interval from the first measured receipt start to the last measured receipt finish for each workload size",
            "characters_s": "Confirmed receipt code points divided by the same measured receipt interval",
            "frame_bytes": "Actual protected frame length reported by the verified delivery receipt; excludes inferred lower-layer overhead",
            "warmups": "Sequential benchmark messages confirmed before measured repetitions; excluded from samples and summaries",
            "confirmation": "A message is successful only when wait_for_receipt returns its verified delivery receipt",
        },
        "policy_limits": asdict(service.limits),
    }

    samples: list[dict] = []
    confirmed: dict[int, list[object]] = {size: [] for size in sizes}
    complete = True
    stop = False

    def canceled() -> bool:
        return cancel is not None and cancel.is_set()

    def exchange(size: int, *, measured: bool) -> bool:
        nonlocal complete, stop
        if canceled():
            complete = False
            stop = True
            if measured:
                samples.append({
                    "operation": "network_round_trip",
                    "payload_bytes": size,
                    "elapsed_ns": 0,
                    "success": False,
                    "error": "Benchmark canceled before send",
                    "error_class": "OperationCancelled",
                })
            return False
        if service.state != "connected":
            complete = False
            stop = True
            if measured:
                samples.append({
                    "operation": "network_round_trip",
                    "payload_bytes": size,
                    "elapsed_ns": 0,
                    "success": False,
                    "error": "Peer disconnected before send",
                    "error_class": "InvalidState",
                })
            return False

        text = "x" * size
        attempt_started = time.perf_counter_ns()
        message_id = None
        try:
            message_id = service.send_text(text, run_id=run_id)
            receipt = service.wait_for_receipt(message_id, cancel=cancel)
            elapsed_ns = receipt.finished_ns - receipt.started_ns
        except Exception as error:
            complete = False
            stop = True
            if measured:
                samples.append({
                    "operation": "network_round_trip",
                    "payload_bytes": size,
                    "elapsed_ns": max(0, time.perf_counter_ns() - attempt_started),
                    "success": False,
                    "message_id": message_id,
                    "characters": None,
                    "frame_bytes": None,
                    "started_ns": None,
                    "finished_ns": None,
                    "error": str(error),
                    "error_class": type(error).__name__,
                })
            return False

        if measured:
            row = {
                "operation": "network_round_trip",
                "payload_bytes": receipt.plaintext_bytes,
                "elapsed_ns": elapsed_ns,
                "success": True,
                "message_id": receipt.message_id,
                "characters": receipt.characters,
                "frame_bytes": receipt.frame_bytes,
                "started_ns": receipt.started_ns,
                "finished_ns": receipt.finished_ns,
            }
            samples.append(row)
            confirmed[size].append(receipt)
        return True

    for size in sizes:
        for _ in range(warmups):
            if stop or not exchange(size, measured=False):
                break
        if stop:
            break
        for _ in range(repetitions):
            if stop or not exchange(size, measured=True):
                break
        if stop:
            break

    summaries: list[dict] = []
    for size in sizes:
        receipts = confirmed[size]
        durations = [receipt.finished_ns - receipt.started_ns for receipt in receipts]
        stats = asdict(summarize(durations, size))
        stats["throughput_bytes_s"] = None
        elapsed_interval_ns = None
        goodput_bytes_s = None
        characters_s = None
        workload_complete = len(receipts) == repetitions and complete and not canceled()
        if receipts:
            elapsed_interval_ns = receipts[-1].finished_ns - receipts[0].started_ns
        if workload_complete and elapsed_interval_ns and elapsed_interval_ns > 0:
            goodput_bytes_s = (
                sum(receipt.plaintext_bytes for receipt in receipts) * 1_000_000_000
                / elapsed_interval_ns
            )
            characters_s = (
                sum(receipt.characters for receipt in receipts) * 1_000_000_000
                / elapsed_interval_ns
            )
        summaries.append({
            "operation": "network_round_trip",
            "payload_bytes": size,
            **stats,
            "confirmed_count": len(receipts),
            "elapsed_interval_ns": elapsed_interval_ns,
            "goodput_bytes_s": goodput_bytes_s,
            "characters_s": characters_s,
        })

    if canceled():
        complete = False
    if any(len(confirmed[size]) != repetitions for size in sizes):
        complete = False
    if not complete:
        for summary in summaries:
            summary["goodput_bytes_s"] = None
            summary["characters_s"] = None
    return BenchmarkResult(metadata=metadata, samples=samples, summary=summaries, complete=complete)
