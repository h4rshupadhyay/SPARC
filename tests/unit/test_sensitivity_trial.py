import hashlib

from Crypto.Cipher import AES
import pytest

from sparc.analysis.models import Difference, Trial
from sparc.analysis.sensitivity import sensitivity_trial
from sparc.models import SparcError


def _expected_operands(seed, case_index):
    key_material = f"SPARC-LAB-v1:key:{seed}:{case_index}".encode("utf-8")
    block_material = f"SPARC-LAB-v1:block:{seed}:{case_index}".encode("utf-8")
    return hashlib.sha256(key_material).digest(), hashlib.sha256(block_material).digest()[:16]


def _encrypt(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)


@pytest.mark.parametrize("mode,bit_index", [("plaintext", 0), ("key", 0), ("plaintext", 127), ("key", 255)])
def test_deterministic_operands_and_msb_bit_zero(mode, bit_index):
    seed, case_index = -23, 7
    trial = sensitivity_trial(seed, case_index, mode, bit_index)
    expected_key, expected_block = _expected_operands(seed, case_index)
    expected_modified_key = bytearray(expected_key)
    expected_modified_block = bytearray(expected_block)
    target = expected_modified_block if mode == "plaintext" else expected_modified_key
    target[bit_index // 8] ^= 0x80 >> (bit_index % 8)

    assert isinstance(trial, Trial)
    assert trial.key == expected_key
    assert trial.block == expected_block
    assert trial.modified_key == bytes(expected_modified_key)
    assert trial.modified_block == bytes(expected_modified_block)
    assert trial.baseline_ciphertext == _encrypt(expected_key, expected_block)
    assert trial.modified_ciphertext == _encrypt(bytes(expected_modified_key), bytes(expected_modified_block))
    assert trial.difference == Difference(
        bit_percent=100 * sum((a ^ b).bit_count() for a, b in zip(trial.baseline_ciphertext, trial.modified_ciphertext)) / 128,
        byte_percent=100 * sum(a != b for a, b in zip(trial.baseline_ciphertext, trial.modified_ciphertext)) / 16,
        hex_percent=100 * sum(a != b for a, b in zip(trial.baseline_ciphertext.hex(), trial.modified_ciphertext.hex())) / 32,
    )


@pytest.mark.parametrize("negative", [False, True])
def test_extremely_large_seed_uses_exact_decimal_spelling(negative):
    magnitude = 10**5000
    seed = -magnitude if negative else magnitude
    seed_text = ("-" if negative else "") + "1" + "0" * 5000

    trial = sensitivity_trial(seed, 0, "plaintext", 0)

    expected_key = hashlib.sha256(f"SPARC-LAB-v1:key:{seed_text}:0".encode("utf-8")).digest()
    expected_block = hashlib.sha256(f"SPARC-LAB-v1:block:{seed_text}:0".encode("utf-8")).digest()[:16]
    assert trial.key == expected_key
    assert trial.block == expected_block


@pytest.mark.parametrize(
    "mode,bit_index",
    [("plaintext", 0), ("plaintext", 127), ("key", 0), ("key", 255)],
)
def test_trial_modes_and_bounds(mode, bit_index):
    trial = sensitivity_trial(42, 0, mode, bit_index)
    assert trial.mode == mode
    assert trial.bit_index == bit_index


def test_each_trial_starts_from_baseline_and_flips_one_bit():
    first = sensitivity_trial(42, 3, "plaintext", 0)
    another = sensitivity_trial(42, 3, "plaintext", 9)
    key_flip = sensitivity_trial(42, 3, "key", 4)

    for trial in (first, another, key_flip):
        assert trial.key == first.key
        assert trial.block == first.block
        assert trial.baseline_ciphertext == first.baseline_ciphertext
        assert sum(a != b for a, b in zip(trial.key, trial.modified_key)) + sum(
            a != b for a, b in zip(trial.block, trial.modified_block)
        ) == 1
        assert sum((a ^ b).bit_count() for a, b in zip(trial.key, trial.modified_key)) + sum(
            (a ^ b).bit_count() for a, b in zip(trial.block, trial.modified_block)
        ) == 1


@pytest.mark.parametrize(
    "seed,case_index,mode,bit_index",
    [
        (True, 0, "plaintext", 0),
        (1.5, 0, "plaintext", 0),
        (42, False, "plaintext", 0),
        (42, 1.5, "plaintext", 0),
        (42, 50, "plaintext", 0),
        (42, -1, "plaintext", 0),
        (42, 0, "unknown", 0),
        (42, 0, None, 0),
        (42, 0, "plaintext", -1),
        (42, 0, "plaintext", 128),
        (42, 0, "key", -1),
        (42, 0, "key", 256),
        (42, 0, "plaintext", True),
        (42, 0, "plaintext", 0.5),
        (42, 0, "key", False),
        ("42", 0, "plaintext", 0),
    ],
)
def test_invalid_trial_inputs_are_domain_errors(seed, case_index, mode, bit_index):
    with pytest.raises(SparcError):
        sensitivity_trial(seed, case_index, mode, bit_index)
