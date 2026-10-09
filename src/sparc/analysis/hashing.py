"""Finite searches over synthetic inputs and complete SHA-256 digests."""

import csv
from dataclasses import asdict, dataclass
import hashlib
import io
from pathlib import Path
import random
from threading import Event
import time
from typing import Callable

from ..storage import atomic_write


HASH_SOURCE = "https://csrc.nist.gov/Projects/hash-functions"
HASH_PROPERTIES = {
    "collision": "Collision resistance: finding any pair of different inputs with equal hashes should be infeasible.",
    "preimage": "Preimage resistance: starting from a target digest, finding an input producing it should be infeasible.",
    "second_preimage": "Second-preimage resistance: starting from a specified input, finding a different input with its hash should be infeasible.",
}


@dataclass(frozen=True)
class HashSearchResult:
    mode: str
    digest_bits: int
    max_attempts: int
    seed: int
    outcome: str
    attempts: int
    elapsed_ns: int
    target_digest: str | None
    input_a: bytes | None
    input_b: bytes | None
    input_a_sha256: str | None
    input_b_sha256: str | None

    @property
    def complete(self) -> bool:
        return self.outcome != "canceled"

    @property
    def scope(self) -> str:
        return "full_sha256_bounded_search"

    @property
    def interpretation(self) -> str:
        return "Full SHA-256 bounded search. A bounded search does not establish cryptographic resistance."


def run_hash_search(
    mode: str,
    *,
    digest_bits: int = 256,
    max_attempts: int = 100000,
    seed: int = 42,
    cancel: Event | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> HashSearchResult:
    """Search distinct synthetic counter inputs, retaining at most one witness.

    Preimage targets are seeded random digest values. Second-preimage targets
    are hashes of a separate, specified synthetic input outside the candidate
    sequence. Attempts count candidate hashes, excluding target preparation.
    Elapsed time covers the search, including progress callbacks.
    """
    if mode not in HASH_PROPERTIES:
        raise ValueError("Choose collision, preimage, or second_preimage")
    if type(digest_bits) is not int or digest_bits != 256:
        raise ValueError("Hash searches require the full 256-bit SHA-256 digest")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 100000:
        raise ValueError("Attempt limit must be between 1 and 100000")
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("Seed must be an integer from 0 to 2^64 - 1")

    seed_bytes = seed.to_bytes(8, "big")
    target = None
    input_a = input_b = None
    hash_a = hash_b = None
    if mode == "preimage":
        target = f"{random.Random(seed).getrandbits(256):064x}"
    elif mode == "second_preimage":
        input_a = b"SPARC hash target\x00" + seed_bytes
        hash_a = hashlib.sha256(input_a).hexdigest()
        target = hash_a

    seen: dict[str, tuple[bytes, str]] = {}
    attempts = 0
    outcome = "budget_exhausted"
    started = time.perf_counter_ns()
    for index in range(max_attempts):
        if cancel is not None and cancel.is_set():
            outcome = "canceled"
            break
        candidate = b"SPARC hash candidate\x00" + seed_bytes + index.to_bytes(8, "big")
        full_digest = hashlib.sha256(candidate).hexdigest()
        attempts += 1
        if mode == "collision":
            previous = seen.get(full_digest)
            if previous is not None:
                input_a, hash_a = previous
                input_b, hash_b = candidate, full_digest
                target = full_digest
                outcome = "match"
                break
            seen[full_digest] = (candidate, full_digest)
        elif full_digest == target:
            if mode == "preimage":
                input_a, hash_a = candidate, full_digest
            else:
                input_b, hash_b = candidate, full_digest
            outcome = "match"
            break
        if on_progress is not None and attempts % 256 == 0:
            on_progress(attempts, max_attempts)

    if on_progress is not None:
        on_progress(attempts, max_attempts)
    elapsed = time.perf_counter_ns() - started
    return HashSearchResult(
        mode, digest_bits, max_attempts, seed, outcome, attempts, elapsed,
        target, input_a, input_b, hash_a, hash_b,
    )


def export_hash_search(result: HashSearchResult, destination: Path) -> None:
    """Export a synthetic witness and bounded-search provenance as one CSV row."""
    row = asdict(result)
    for field in ("input_a", "input_b"):
        value = row.pop(field)
        row[f"{field}_hex"] = value.hex() if value is not None else ""
    row.update(
        algorithm="SHA-256", method="synthetic_counter_v1", scope=result.scope,
        complete=result.complete, interpretation=result.interpretation,
        definitions_source=HASH_SOURCE,
        attempts_definition="candidate hashes; target preparation excluded",
        elapsed_definition="search including progress callbacks; target preparation excluded",
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(row))
    writer.writeheader()
    writer.writerow(row)
    atomic_write(Path(destination), output.getvalue().encode("utf-8"), private=False, secure_parent=False)
