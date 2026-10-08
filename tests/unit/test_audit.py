"""Durable append and fail-closed startup tests for C4c."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


AUDIT_DOMAIN = b"SPARC-v1 audit\x00"
AUDIT_SIGNATURE_DOMAIN = b"SPARC-v1 audit-signature\x00"
CHECKPOINT_DOMAIN = b"SPARC-v1 checkpoint\x00"
LOG_ID = "0123456789abcdef0123456789abcdef"
ZERO_HASH = "0" * 64


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _identity(seed=bytes(range(32))):
    from sparc.models import Identity

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())


def _record(identity, number, previous_hash, *, log_id=LOG_ID):
    body = {
        "log_id": log_id,
        "record_number": number,
        "timestamp": f"2026-10-08T12:34:{number:02d}Z",
        "event": "send_attempt",
        "identity_fingerprint": identity.fingerprint,
        "metadata": {
            "message_id": f"{number:032x}",
            "sha256": hashlib.sha256(f"fixture {number}".encode()).hexdigest(),
            "byte_count": 9,
        },
        "previous_hash": previous_hash,
    }
    digest = hashlib.sha256(AUDIT_DOMAIN + _canonical(body)).digest()
    return {
        "body": body,
        "record_hash": digest.hex(),
        "signature": base64.b64encode(
            identity.private_key.sign(AUDIT_SIGNATURE_DOMAIN + digest)
        ).decode("ascii"),
    }


def _write_chain(path, identity, count):
    records = []
    previous = ZERO_HASH
    for number in range(1, count + 1):
        record = _record(identity, number, previous)
        records.append(record)
        previous = record["record_hash"]
    path.write_bytes(b"".join(_canonical(record) + b"\n" for record in records))
    return records


def _write_checkpoint(path, identity, number, record_hash, *, log_id=LOG_ID):
    body = {
        "log_id": log_id,
        "last_record_number": number,
        "last_record_hash": record_hash,
        "identity_fingerprint": identity.fingerprint,
    }
    signature = identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(body))
    checkpoint = {"body": body, "signature": base64.b64encode(signature).decode("ascii")}
    path.write_bytes(_canonical(checkpoint))
    return checkpoint


def _send_metadata(number, *, message_id=None):
    return {
        "message_id": message_id or f"{number:032x}",
        "sha256": hashlib.sha256(f"message {number}".encode()).hexdigest(),
        "byte_count": 9,
    }


def test_fresh_log_gets_durable_empty_file_and_appends_first_record(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    path = tmp_path / "audit.jsonl"
    assert path.is_file()
    assert path.read_bytes() == b""

    result = audit.append("send_attempt", _send_metadata(1))
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert result.encoded_bytes == len(raw)
    assert result.elapsed_ns >= 0
    assert type(result.elapsed_ns) is int
    assert result.record["body"]["record_number"] == 1
    assert result.record["body"]["previous_hash"] == ZERO_HASH
    assert len(result.record["body"]["log_id"]) == 32


def test_existing_chain_and_retained_checkpoint_are_verified_before_append(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    log_path = tmp_path / "audit.jsonl"
    records = _write_chain(log_path, identity, 2)
    _write_checkpoint(
        tmp_path / "audit-checkpoint.json", identity, 2, records[-1]["record_hash"]
    )

    audit = AuditLog(tmp_path, identity)
    result = audit.append("send_attempt", _send_metadata(3))
    assert result.record["body"]["record_number"] == 3
    assert result.record["body"]["log_id"] == LOG_ID
    assert result.record["body"]["previous_hash"] == records[-1]["record_hash"]


def test_existing_empty_log_without_zero_head_checkpoint_blocks_restart(tmp_path):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    identity = _identity()
    log_path = tmp_path / "audit.jsonl"
    log_path.write_bytes(b"")
    before = log_path.read_bytes()
    with pytest.raises(SparcError) as raised:
        AuditLog(tmp_path, identity)
    assert raised.value.code == "audit_verification_failed"
    assert log_path.read_bytes() == before


def test_corrupt_startup_preserves_bytes_and_blocks_append(tmp_path):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    identity = _identity()
    path = tmp_path / "audit.jsonl"
    _write_chain(path, identity, 1)
    with path.open("ab") as stream:
        stream.write(b'{"corrupt":true}\n')
    before = path.read_bytes()
    with pytest.raises(SparcError) as raised:
        AuditLog(tmp_path, identity)
    assert raised.value.code == "audit_verification_failed"
    assert path.read_bytes() == before


@pytest.mark.parametrize("failure_point", ["write", "flush", "fsync"])
def test_append_durability_failure_never_succeeds_or_allows_retry(tmp_path, monkeypatch, failure_point):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    path = tmp_path / "audit.jsonl"
    original_open = Path.open
    attempts = []
    real_fsync = audit_module.os.fsync

    class FaultyStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.stream.close()

        def write(self, data):
            attempts.append("write")
            if failure_point == "write":
                raise OSError("injected write failure")
            return self.stream.write(data)

        def flush(self):
            attempts.append("flush")
            if failure_point == "flush":
                raise OSError("injected flush failure")
            return self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def open_with_fault(self, *args, **kwargs):
        stream = original_open(self, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if self == path and mode == "ab":
            return FaultyStream(stream)
        return stream

    monkeypatch.setattr(Path, "open", open_with_fault)
    if failure_point == "fsync":
        def failing_fsync(fd):
            attempts.append("fsync")
            raise OSError("injected fsync failure")

        monkeypatch.setattr(audit_module.os, "fsync", failing_fsync)

    with pytest.raises(SparcError) as raised:
        audit.append("send_attempt", _send_metadata(1))
    assert raised.value.code == "audit_storage_failed"
    first_attempt_count = len(attempts)
    with pytest.raises(SparcError) as retried:
        audit.append("send_attempt", _send_metadata(2))
    assert retried.value.code == "audit_storage_failed"
    assert len(attempts) == first_attempt_count
    assert path.exists()


def test_append_flush_and_fsync_happen_before_successful_return(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    path = tmp_path / "audit.jsonl"
    events = []
    original_open = Path.open
    original_fsync = audit_module.os.fsync

    class TrackedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.stream.close()

        def write(self, data):
            events.append("write")
            return self.stream.write(data)

        def flush(self):
            events.append("flush")
            return self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def tracked_open(self, *args, **kwargs):
        stream = original_open(self, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if self == path and mode == "ab":
            return TrackedStream(stream)
        return stream

    def tracked_fsync(fd):
        events.append("fsync")
        return original_fsync(fd)

    monkeypatch.setattr(Path, "open", tracked_open)
    monkeypatch.setattr(audit_module.os, "fsync", tracked_fsync)
    result = audit.append("send_attempt", _send_metadata(1))
    assert events.index("write") < events.index("flush") < events.index("fsync")
    assert result.encoded_bytes == len(path.read_bytes())


def test_log_contains_no_plaintext_private_keys_or_timing_fields(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    plaintext = "sensitive test phrase must never be persisted"
    private_bytes = identity.private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    audit = AuditLog(tmp_path, identity)
    result = audit.append("send_attempt", _send_metadata(1))
    stored = (tmp_path / "audit.jsonl").read_bytes()
    assert plaintext.encode() not in stored
    assert private_bytes not in stored
    assert base64.b64encode(private_bytes) not in stored
    assert set(result.record) == {"body", "record_hash", "signature"}
    assert "elapsed_ns" not in result.record["body"]
    assert "sign_ns" not in result.record["body"]
    assert "encrypt_ns" not in result.record["body"]
    assert result.encoded_bytes == len(stored)


def test_concurrent_appends_form_one_valid_serial_chain(tmp_path):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    count = 12
    barrier = threading.Barrier(count)

    def append_one(number):
        barrier.wait()
        return audit.append("send_attempt", _send_metadata(number))

    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(append_one, range(1, count + 1)))
    assert len({result.record["body"]["record_number"] for result in results}) == count
    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes)
    assert report.valid
    assert report.verified_records == count
    assert report.first_failed_record is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner modes are platform-specific")
def test_audit_store_restricts_existing_directory_and_log_modes(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    log_path = tmp_path / "audit.jsonl"
    records = _write_chain(log_path, identity, 1)
    _write_checkpoint(
        tmp_path / "audit-checkpoint.json", identity, 1, records[0]["record_hash"]
    )
    os.chmod(tmp_path, 0o755)
    os.chmod(log_path, 0o644)

    AuditLog(tmp_path, identity)

    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert log_path.stat().st_mode & 0o777 == 0o600
