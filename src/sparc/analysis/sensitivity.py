"""Formulas for comparing isolated AES block outputs."""

import hashlib
from math import fsum, sqrt
from threading import Event
from typing import Callable

from Crypto.Cipher import AES

from .models import Difference
from .models import LabResult
from .models import Trial
from ..models import SparcError


def compare_ciphertexts(left: bytes, right: bytes) -> Difference:
    """Return the percentages of changed bits, bytes, and lowercase hex positions."""
    if type(left) is not bytes or type(right) is not bytes:
        raise SparcError("invalid_analysis_input", "Ciphertexts must be bytes")
    if len(left) != 16 or len(right) != 16:
        raise SparcError("invalid_analysis_input", "Ciphertexts must each contain exactly 16 bytes")

    changed_bits = sum((a ^ b).bit_count() for a, b in zip(left, right))
    changed_bytes = sum(a != b for a, b in zip(left, right))
    left_hex = left.hex()
    right_hex = right.hex()
    changed_hex = sum(a != b for a, b in zip(left_hex, right_hex))

    return Difference(
        bit_percent=100 * changed_bits / 128,
        byte_percent=100 * changed_bytes / 16,
        hex_percent=100 * changed_hex / 32,
    )


def _validate_trial_inputs(seed: int, case_index: int, mode: str, bit_index: int) -> None:
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SparcError("invalid_analysis_input", "Seed must be an integer")
    if isinstance(case_index, bool) or not isinstance(case_index, int) or not 0 <= case_index < 50:
        raise SparcError("invalid_analysis_input", "Case index must be an integer from 0 through 49")
    if mode not in ("plaintext", "key"):
        raise SparcError("invalid_analysis_input", "Mode must be plaintext or key")
    bit_limit = 128 if mode == "plaintext" else 256
    if isinstance(bit_index, bool) or not isinstance(bit_index, int) or not 0 <= bit_index < bit_limit:
        raise SparcError("invalid_analysis_input", f"Bit index must be an integer from 0 through {bit_limit - 1}")


def _decimal_seed(seed: int) -> str:
    """Format an arbitrary-size integer without Python's decimal digit limit."""
    if seed == 0:
        return "0"

    negative = seed < 0
    magnitude = -seed if negative else seed
    chunks = []
    while magnitude:
        magnitude, chunk = divmod(magnitude, 1_000_000_000)
        chunks.append(chunk)

    decimal = str(chunks[-1]) + "".join(f"{chunk:09d}" for chunk in reversed(chunks[:-1]))
    return "-" + decimal if negative else decimal


def _synthetic_operands(seed: int, case_index: int) -> tuple[bytes, bytes]:
    seed_text = _decimal_seed(seed)
    key_material = f"SPARC-LAB-v1:key:{seed_text}:{case_index}".encode("utf-8")
    block_material = f"SPARC-LAB-v1:block:{seed_text}:{case_index}".encode("utf-8")
    key = hashlib.sha256(key_material).digest()
    block = hashlib.sha256(block_material).digest()[:16]
    return key, block


def _flip_bit(value: bytes, bit_index: int) -> bytes:
    modified = bytearray(value)
    modified[bit_index // 8] ^= 0x80 >> (bit_index % 8)
    return bytes(modified)


def sensitivity_trial(seed: int, case_index: int, mode: str, bit_index: int) -> Trial:
    """Run one reproducible synthetic AES-256 block sensitivity trial."""
    _validate_trial_inputs(seed, case_index, mode, bit_index)
    key, block = _synthetic_operands(seed, case_index)
    if mode == "plaintext":
        modified_key = key
        modified_block = _flip_bit(block, bit_index)
    else:
        modified_key = _flip_bit(key, bit_index)
        modified_block = block

    baseline_ciphertext = AES.new(key, AES.MODE_ECB).encrypt(block)
    modified_ciphertext = AES.new(modified_key, AES.MODE_ECB).encrypt(modified_block)
    return Trial(
        case_index=case_index,
        mode=mode,
        bit_index=bit_index,
        key=key,
        block=block,
        modified_key=modified_key,
        modified_block=modified_block,
        baseline_ciphertext=baseline_ciphertext,
        modified_ciphertext=modified_ciphertext,
        difference=compare_ciphertexts(baseline_ciphertext, modified_ciphertext),
    )


def run_sensitivity(
    seed: int = 42,
    cases: int = 50,
    cancel: Event | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> LabResult:
    """Run a bounded, reproducible batch of synthetic AES sensitivity trials."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SparcError("invalid_analysis_input", "Seed must be an integer")
    if isinstance(cases, bool) or not isinstance(cases, int) or not 1 <= cases <= 50:
        raise SparcError("invalid_analysis_input", "Cases must be an integer from 1 through 50")

    modes = ("plaintext", "key")
    metrics = ("bit_percent", "byte_percent", "hex_percent")
    total = cases * (128 + 256)
    trials: list[Trial] = []
    canceled = False

    def observe_cancellation() -> bool:
        nonlocal canceled
        if cancel is not None and cancel.is_set():
            canceled = True
        return canceled

    observe_cancellation()
    if progress is not None:
        progress(0, total)
    observe_cancellation()

    for case_index in range(cases):
        if observe_cancellation():
            break

        key, block = _synthetic_operands(seed, case_index)
        baseline_ciphertext = AES.new(key, AES.MODE_ECB).encrypt(block)
        for mode, bit_count in (("plaintext", 128), ("key", 256)):
            for bit_index in range(bit_count):
                if observe_cancellation():
                    break

                if mode == "plaintext":
                    modified_key = key
                    modified_block = _flip_bit(block, bit_index)
                else:
                    modified_key = _flip_bit(key, bit_index)
                    modified_block = block
                modified_ciphertext = AES.new(modified_key, AES.MODE_ECB).encrypt(modified_block)
                trials.append(
                    Trial(
                        case_index=case_index,
                        mode=mode,
                        bit_index=bit_index,
                        key=key,
                        block=block,
                        modified_key=modified_key,
                        modified_block=modified_block,
                        baseline_ciphertext=baseline_ciphertext,
                        modified_ciphertext=modified_ciphertext,
                        difference=compare_ciphertexts(baseline_ciphertext, modified_ciphertext),
                    )
                )
                if progress is not None:
                    progress(len(trials), total)
                observe_cancellation()
            if canceled:
                break
        if canceled:
            break

    summary: dict[str, dict[str, dict[str, int | float | None]]] = {}
    for mode in modes:
        mode_trials = [trial for trial in trials if trial.mode == mode]
        summary[mode] = {}
        for metric in metrics:
            values = [getattr(trial.difference, metric) for trial in mode_trials]
            if not values:
                summary[mode][metric] = {
                    "count": 0,
                    "mean": None,
                    "min": None,
                    "max": None,
                    "population_std": None,
                }
                continue
            mean = fsum(values) / len(values)
            variance = fsum((value - mean) ** 2 for value in values) / len(values)
            summary[mode][metric] = {
                "count": len(values),
                "mean": mean,
                "min": min(values),
                "max": max(values),
                "population_std": sqrt(variance),
            }

    observe_cancellation()
    complete = len(trials) == total and not canceled
    return LabResult(seed=seed, cases=cases, trials=trials, summary=summary, complete=complete)
