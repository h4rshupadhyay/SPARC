"""Statistics for measured cryptographic operation durations."""

import base64
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from math import ceil
import os
import platform
from statistics import median
import sys
import time
from threading import Event
from typing import Callable
import uuid

import Crypto
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import message_context, record_aad
from ..models import Limits
from ..models import SparcError
from ..protocol.messages import signing_projection
from ..encoding import canonical
from .models import BenchmarkResult
from .models import SampleStats


def summarize(samples_ns: list[int], payload_bytes: int) -> SampleStats:
    """Summarize call durations using nearest-rank p95 and aggregate throughput."""
    if not isinstance(samples_ns, list):
        raise SparcError("invalid_analysis_input", "Timing samples must be a list")
    if any(isinstance(sample, bool) or not isinstance(sample, int) or sample < 0 for sample in samples_ns):
        raise SparcError("invalid_analysis_input", "Timing samples must be nonnegative integers")
    if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int) or payload_bytes < 0:
        raise SparcError("invalid_analysis_input", "Payload size must be a nonnegative integer")

    count = len(samples_ns)
    if count == 0:
        return SampleStats(
            count=0,
            mean_ns=None,
            median_ns=None,
            p95_ns=None,
            throughput_bytes_s=None,
        )

    ordered = sorted(samples_ns)
    total_ns = sum(samples_ns)
    mean_ns = total_ns / count
    p95_ns = ordered[ceil(0.95 * count) - 1]
    throughput = None if total_ns == 0 else payload_bytes * count * 1_000_000_000 / total_ns

    return SampleStats(
        count=count,
        mean_ns=mean_ns,
        median_ns=median(ordered),
        p95_ns=p95_ns,
        throughput_bytes_s=throughput,
    )


_ALLOWED_SIZES = (64, 1024, 16384)
_OPERATIONS = ("hash", "sign", "encrypt", "decrypt", "recompute_hash", "verify")


def _metadata(run_id: str, sizes: tuple[int, ...], warmups: int, repetitions: int) -> dict:
    return {
        "run_id": run_id,
        "utc": datetime.now(timezone.utc).isoformat(),
        "test_type": "local_cryptographic",
        "sizes": list(sizes),
        "warmups": warmups,
        "repetitions": repetitions,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "library_versions": {
            "cryptography": cryptography.__version__,
            "pycryptodome": Crypto.__version__,
        },
        "evidence_mode": "synthetic_local",
        "units": {
            "payload_bytes": "bytes",
            "elapsed_ns": "nanoseconds",
            "throughput_bytes_s": "bytes per second",
        },
        "definitions": {
            "hash": "SHA-256 digest of the ASCII plaintext; digest finalization is timed",
            "sign_verify": "Ed25519 over a fixed-length C2 message context and signing projection",
            "encrypt_decrypt": "AES-256-GCM over the serialized signed envelope, which grows with plaintext size",
            "throughput": "plaintext bytes multiplied by successful call count divided by summed primitive durations",
            "timing_scope": "Includes perf_counter_ns timer overhead; excludes key generation, encoding, nonce/AAD construction, and I/O",
            "audit": "Local primitive measurements do not include audit work",
        },
        "policy_limits": asdict(Limits()),
    }


def run_local_benchmarks(
    sizes: tuple[int, ...] = (64, 1024, 16384),
    warmups: int = 10,
    repetitions: int = 1000,
    cancel: Event | None = None,
) -> BenchmarkResult:
    """Measure six local cryptographic operations on synthetic operands."""
    if (
        not isinstance(sizes, tuple)
        or not 1 <= len(sizes) <= 3
        or any(type(size) is not int or size not in _ALLOWED_SIZES for size in sizes)
        or len(set(sizes)) != len(sizes)
    ):
        raise SparcError("invalid_analysis_input", "Sizes must be a tuple of one to three distinct allowed workloads")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or not 0 <= warmups <= 10:
        raise SparcError("invalid_analysis_input", "Warmups must be an integer from 0 through 10")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 1000:
        raise SparcError("invalid_analysis_input", "Repetitions must be an integer from 1 through 1000")

    run_id = uuid.uuid4().hex
    metadata = _metadata(run_id, sizes, warmups, repetitions)
    samples: list[dict] = []
    summaries: list[dict] = []
    success_durations: dict[tuple[str, int], list[int]] = {
        (operation, size): [] for size in sizes for operation in _OPERATIONS
    }
    complete = True
    nonce_counter = 0

    def next_nonce() -> bytes:
        nonlocal nonce_counter
        nonce = nonce_counter.to_bytes(12, "big")
        nonce_counter += 1
        return nonce

    def canceled() -> bool:
        return cancel is not None and cancel.is_set()

    def add_measured_sample(operation: str, size: int, call: Callable[[], object]) -> bool:
        nonlocal complete
        started = time.perf_counter_ns()
        try:
            call()
        except Exception as error:
            elapsed_ns = time.perf_counter_ns() - started
            samples.append(
                {
                    "operation": operation,
                    "payload_bytes": size,
                    "elapsed_ns": elapsed_ns,
                    "success": False,
                    "error_class": type(error).__name__,
                }
            )
            complete = False
            return False
        elapsed_ns = time.perf_counter_ns() - started
        samples.append(
            {
                "operation": operation,
                "payload_bytes": size,
                "elapsed_ns": elapsed_ns,
                "success": True,
            }
        )
        success_durations[(operation, size)].append(elapsed_ns)
        return True

    stop = canceled()
    if stop:
        complete = False

    for size in sizes:
        if stop or canceled():
            complete = False
            break

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        aesgcm = AESGCM(os.urandom(32))
        session_id = os.urandom(32)
        text_bytes = b"x" * size
        text = text_bytes.decode("ascii")
        run_message_id = uuid.uuid4().hex
        unsigned_payload = {
            "kind": "benchmark",
            "run_id": run_id,
            "message_id": run_message_id,
            "text": text,
            "byte_count": size,
            "sha256": hashlib.sha256(text_bytes).hexdigest(),
        }
        projection = signing_projection(unsigned_payload)
        context = message_context(session_id, 0, 0, projection)
        signature = private_key.sign(context)
        signed_payload = dict(unsigned_payload)
        signed_payload["signature"] = base64.b64encode(signature).decode("ascii")
        signed_envelope = canonical(signed_payload)
        frame_length = 1 + len(session_id) + 8 + len(signed_envelope) + 16
        associated_data = record_aad(6, session_id, 0, 0, frame_length)
        setup_nonce = next_nonce()
        setup_ciphertext = aesgcm.encrypt(setup_nonce, signed_envelope, associated_data)

        def make_call(operation: str) -> Callable[[], object]:
            if operation in ("hash", "recompute_hash"):
                return lambda: hashlib.sha256(text_bytes).digest()
            if operation == "sign":
                return lambda: private_key.sign(context)
            if operation == "encrypt":
                nonce = next_nonce()
                return lambda: aesgcm.encrypt(nonce, signed_envelope, associated_data)
            if operation == "decrypt":
                return lambda: aesgcm.decrypt(setup_nonce, setup_ciphertext, associated_data)
            if operation == "verify":
                return lambda: public_key.verify(signature, context)
            raise AssertionError(f"unknown operation: {operation}")

        for operation in _OPERATIONS:
            for _ in range(warmups):
                if canceled():
                    complete = False
                    stop = True
                    break
                try:
                    make_call(operation)()
                except Exception:
                    complete = False
                    stop = True
                    break
                if canceled():
                    complete = False
                    stop = True
                    break
            if stop:
                break

            for _ in range(repetitions):
                if canceled():
                    complete = False
                    stop = True
                    break
                add_measured_sample(operation, size, make_call(operation))
                if canceled():
                    complete = False
                    stop = True
                    break
            if stop:
                break
        if stop:
            break

    for size in sizes:
        for operation in _OPERATIONS:
            stats = summarize(success_durations[(operation, size)], size)
            summaries.append({"operation": operation, "payload_bytes": size, **asdict(stats)})

    if canceled():
        complete = False
    return BenchmarkResult(metadata=metadata, samples=samples, summary=summaries, complete=complete)
