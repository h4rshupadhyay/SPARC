"""Independent chain and checkpoint oracles for C4b log verification."""

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


AUDIT_DOMAIN = b"SPARC-v1 audit\x00"
AUDIT_SIGNATURE_DOMAIN = b"SPARC-v1 audit-signature\x00"
CHECKPOINT_DOMAIN = b"SPARC-v1 checkpoint\x00"
LOG_ID = "0123456789abcdef0123456789abcdef"
ZERO_HASH = "0" * 64
IDENTITY_SEED = bytes(range(32))


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _key(seed=IDENTITY_SEED):
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, public_key, hashlib.sha256(public_key).hexdigest()


def _body(number, previous_hash, *, log_id=LOG_ID, owner=None):
    _, public_key, fingerprint = _key()
    return {
        "log_id": log_id,
        "record_number": number,
        "timestamp": f"2026-10-08T12:34:{number:02d}Z",
        "event": "send_attempt",
        "identity_fingerprint": fingerprint if owner is None else owner,
        "metadata": {
            "message_id": f"{number:032x}",
            "sha256": hashlib.sha256(f"message {number}".encode()).hexdigest(),
            "byte_count": 9,
        },
        "previous_hash": previous_hash,
    }


def _record(body, private_key=None):
    if private_key is None:
        private_key, _, _ = _key()
    digest = hashlib.sha256(AUDIT_DOMAIN + _canonical(body)).digest()
    return {
        "body": body,
        "record_hash": digest.hex(),
        "signature": base64.b64encode(
            private_key.sign(AUDIT_SIGNATURE_DOMAIN + digest)
        ).decode("ascii"),
    }


def _chain(count, *, start_previous=ZERO_HASH, start_number=1):
    result = []
    previous = start_previous
    for number in range(start_number, start_number + count):
        body = _body(number, previous)
        record = _record(body)
        result.append(record)
        previous = record["record_hash"]
    return result


def _write_log(path, records):
    path.write_bytes(b"".join(_canonical(record) + b"\n" for record in records))


def _checkpoint(number, record_hash, *, log_id=LOG_ID, owner=None, private_key=None):
    if private_key is None:
        private_key, _, fingerprint = _key()
    else:
        _, _, fingerprint = _key()
    body = {
        "log_id": log_id,
        "last_record_number": number,
        "last_record_hash": record_hash,
        "identity_fingerprint": fingerprint if owner is None else owner,
    }
    signature = private_key.sign(CHECKPOINT_DOMAIN + _canonical(body))
    return {"body": body, "signature": base64.b64encode(signature).decode("ascii")}


def _write_checkpoint(path, checkpoint):
    path.write_bytes(_canonical(checkpoint))


def _assert_report(report, *, valid, records, first_failed, checkpoint_checked=None):
    assert report.valid is valid
    assert report.verified_records == records
    assert report.first_failed_record == first_failed
    assert type(report.elapsed_ns) is int and report.elapsed_ns >= 0
    if checkpoint_checked is not None:
        assert report.checkpoint_checked is checkpoint_checked


def test_intact_chain_and_empty_chain_report(tmp_path):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    log_path = tmp_path / "audit-intact.jsonl"
    records = _chain(3)
    _write_log(log_path, records)
    report = verify_log(log_path, public_key)
    _assert_report(report, valid=True, records=3, first_failed=None, checkpoint_checked=False)
    assert "available" in report.reason.lower()

    empty_path = tmp_path / "audit-empty.jsonl"
    empty_path.write_bytes(b"")
    empty_report = verify_log(empty_path, public_key)
    _assert_report(empty_report, valid=True, records=0, first_failed=None, checkpoint_checked=False)
    assert "available" in empty_report.reason.lower() and "empty" in empty_report.reason.lower()


@pytest.mark.parametrize(
    "damage,expected_code",
    [
        ("body", "audit_hash_mismatch"),
        ("link", "audit_chain_mismatch"),
        ("hash", "audit_hash_mismatch"),
        ("signature", "audit_signature_failed"),
        ("owner", "audit_chain_mismatch"),
        ("log_id", "audit_chain_mismatch"),
        ("number", "audit_chain_mismatch"),
    ],
)
def test_intact_chain_and_first_failure_index(tmp_path, damage, expected_code):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    records = _chain(3)
    damaged = copy.deepcopy(records[1])
    if damage == "body":
        damaged["body"]["metadata"]["byte_count"] += 1
    elif damage == "link":
        damaged["body"]["previous_hash"] = "f" * 64
    elif damage == "hash":
        damaged["record_hash"] = "f" * 64
    elif damage == "signature":
        damaged["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    elif damage == "owner":
        damaged["body"]["identity_fingerprint"] = "b" * 64
    elif damage == "log_id":
        damaged["body"]["log_id"] = "f" * 32
    else:
        damaged["body"]["record_number"] = 3
    records[1] = damaged
    path = tmp_path / "audit.jsonl"
    _write_log(path, records)

    report = verify_log(path, public_key)
    _assert_report(report, valid=False, records=1, first_failed=2, checkpoint_checked=False)
    assert expected_code in report.reason
    assert len(report.reason) < 512


@pytest.mark.parametrize(
    "malformed,failed_line",
    [
        (b"{\"body\":", 1),
        (b"\n", 1),
        (b"\n", 2),
        (b"{\"x\":{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":\"x\"}}}}}}}\n", 1),
        (b"x" * 131072 + b"\n", 1),
    ],
    ids=["partial-json", "blank-first-line", "blank-after-record", "deep-object", "overlong-line"],
)
def test_blank_partial_overlong_and_deep_lines_fail_safely(tmp_path, malformed, failed_line):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    path = tmp_path / "audit.jsonl"
    if failed_line == 2:
        _write_log(path, _chain(1))
        path.write_bytes(path.read_bytes() + malformed)
    else:
        path.write_bytes(malformed)
    report = verify_log(path, public_key)
    _assert_report(report, valid=False, records=failed_line - 1, first_failed=failed_line, checkpoint_checked=False)
    assert len(report.reason) < 512


def test_unterminated_final_line_is_rejected(tmp_path):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    path = tmp_path / "audit.jsonl"
    path.write_bytes(_canonical(_chain(1)[0]))
    report = verify_log(path, public_key)
    _assert_report(report, valid=False, records=0, first_failed=1, checkpoint_checked=False)


def test_missing_log_with_or_without_checkpoint_fails(tmp_path):
    from sparc.audit import verify_log

    _, public_key, fingerprint = _key()
    missing = tmp_path / "missing.jsonl"
    without = verify_log(missing, public_key)
    _assert_report(without, valid=False, records=0, first_failed=None, checkpoint_checked=False)

    checkpoint_path = tmp_path / "checkpoint.json"
    _write_checkpoint(checkpoint_path, _checkpoint(0, ZERO_HASH, owner=fingerprint))
    with_checkpoint = verify_log(missing, public_key, checkpoint_path)
    _assert_report(with_checkpoint, valid=False, records=0, first_failed=None, checkpoint_checked=False)


def test_chain_only_cannot_assert_tail_absence(tmp_path):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    path = tmp_path / "audit.jsonl"
    _write_log(path, _chain(3)[:2])
    report = verify_log(path, public_key)
    _assert_report(report, valid=True, records=2, first_failed=None, checkpoint_checked=False)
    assert "available" in report.reason.lower()


def test_current_older_prefix_and_zero_head_checkpoints(tmp_path):
    from sparc.audit import verify_log

    _, public_key, fingerprint = _key()
    records = _chain(3)
    log_path = tmp_path / "audit.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    _write_log(log_path, records)

    _write_checkpoint(
        checkpoint_path,
        _checkpoint(3, records[2]["record_hash"], owner=fingerprint),
    )
    current = verify_log(log_path, public_key, checkpoint_path)
    _assert_report(current, valid=True, records=3, first_failed=None, checkpoint_checked=True)

    _write_checkpoint(
        checkpoint_path,
        _checkpoint(1, records[0]["record_hash"], owner=fingerprint),
    )
    earlier = verify_log(log_path, public_key, checkpoint_path)
    _assert_report(earlier, valid=True, records=3, first_failed=None, checkpoint_checked=True)

    empty_path = tmp_path / "empty.jsonl"
    empty_path.write_bytes(b"")
    _write_checkpoint(checkpoint_path, _checkpoint(0, ZERO_HASH, owner=fingerprint))
    zero_head = verify_log(empty_path, public_key, checkpoint_path)
    _assert_report(zero_head, valid=True, records=0, first_failed=None, checkpoint_checked=True)


@pytest.mark.parametrize(
    "checkpoint,expected_code,verified_records",
    [
        ("bad_signature", "audit_signature_failed", 0),
        ("owner", "audit_chain_mismatch", 0),
        ("hash", "audit_chain_mismatch", 0),
        ("log_id", "audit_chain_mismatch", 0),
        ("too_new", "audit_chain_mismatch", 2),
        ("wrong_prefix", "audit_chain_mismatch", 0),
    ],
)
def test_invalid_checkpoint_reports_accepted_prefix_without_record_failure(
    tmp_path, checkpoint, expected_code, verified_records
):
    from sparc.audit import verify_log

    _, public_key, fingerprint = _key()
    records = _chain(2)
    path = tmp_path / "audit.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    _write_log(path, records)
    if checkpoint == "bad_signature":
        value = _checkpoint(1, records[0]["record_hash"], owner=fingerprint)
        value["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    elif checkpoint == "owner":
        value = _checkpoint(1, records[0]["record_hash"], owner="b" * 64)
    elif checkpoint == "hash":
        value = _checkpoint(1, "f" * 64, owner=fingerprint)
    elif checkpoint == "log_id":
        value = _checkpoint(1, records[0]["record_hash"], owner=fingerprint, log_id="f" * 32)
    elif checkpoint == "too_new":
        value = _checkpoint(3, "f" * 64, owner=fingerprint)
    else:
        value = _checkpoint(1, records[1]["record_hash"], owner=fingerprint)
    _write_checkpoint(checkpoint_path, value)

    report = verify_log(path, public_key, checkpoint_path)
    _assert_report(
        report,
        valid=False,
        records=verified_records,
        first_failed=None,
        checkpoint_checked=False,
    )
    assert expected_code in report.reason


def test_wrong_hash_at_later_checkpoint_prefix_keeps_prior_accepted_count(tmp_path):
    from sparc.audit import verify_log

    _, public_key, fingerprint = _key()
    records = _chain(3)
    path = tmp_path / "audit.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    _write_log(path, records)
    _write_checkpoint(
        checkpoint_path,
        _checkpoint(2, "f" * 64, owner=fingerprint),
    )

    report = verify_log(path, public_key, checkpoint_path)
    _assert_report(report, valid=False, records=1, first_failed=None, checkpoint_checked=False)
    assert "audit_chain_mismatch" in report.reason


def test_checkpoint_prefix_can_be_checked_before_later_record_failure(tmp_path):
    from sparc.audit import verify_log

    _, public_key, fingerprint = _key()
    records = _chain(3)
    records[2]["body"]["metadata"]["byte_count"] = 10
    path = tmp_path / "audit.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    _write_log(path, records)
    _write_checkpoint(
        checkpoint_path,
        _checkpoint(2, _chain(2)[1]["record_hash"], owner=fingerprint),
    )

    report = verify_log(path, public_key, checkpoint_path)
    _assert_report(report, valid=False, records=2, first_failed=3, checkpoint_checked=True)


def test_missing_checkpoint_is_an_invalid_requested_anchor(tmp_path):
    from sparc.audit import verify_log

    _, public_key, _ = _key()
    path = tmp_path / "audit.jsonl"
    _write_log(path, _chain(1))
    report = verify_log(path, public_key, tmp_path / "missing-checkpoint.json")
    _assert_report(report, valid=False, records=0, first_failed=None, checkpoint_checked=False)
