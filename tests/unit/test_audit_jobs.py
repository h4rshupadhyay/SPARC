"""Focused snapshot and cancellation seams for C7d audit jobs."""

from __future__ import annotations

import hashlib
import base64
import json
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _identity():
    from sparc.models import Identity

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())


def _metadata(number):
    return {
        "message_id": f"{number:032x}",
        "sha256": hashlib.sha256(f"message {number}".encode()).hexdigest(),
        "byte_count": 9,
    }


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def test_head_snapshot_is_exact_copy_of_committed_public_head(tmp_path):
    from sparc.audit import AuditLog

    audit = AuditLog(tmp_path, _identity())
    first = audit.append("send_attempt", _metadata(1))
    snapshot = audit.head_snapshot()
    assert set(snapshot) == {
        "log_id", "last_record_number", "last_record_hash", "identity_fingerprint",
    }
    assert snapshot == {
        "log_id": first.record["body"]["log_id"],
        "last_record_number": 1,
        "last_record_hash": first.record["record_hash"],
        "identity_fingerprint": audit.identity.fingerprint,
    }
    snapshot["last_record_hash"] = "0" * 64
    assert audit.head_snapshot()["last_record_hash"] == first.record["record_hash"]


def test_verify_scans_captured_prefix_without_blocking_append(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    entered_record = threading.Event()
    continue_scan = threading.Event()
    original_verify = audit_module.verify_audit_record

    def gated_verify(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        if not entered_record.is_set():
            entered_record.set()
            assert continue_scan.wait(2), "test did not release prefix verifier"
        return result

    monkeypatch.setattr(audit_module, "verify_audit_record", gated_verify)
    result = {}

    def verify():
        result["report"] = audit.verify()

    worker = threading.Thread(target=verify)
    worker.start()
    assert entered_record.wait(1), "verification did not reach record scan"
    appended = threading.Event()

    def append_during_scan():
        audit.append("send_attempt", _metadata(2))
        appended.set()

    appender = threading.Thread(target=append_during_scan)
    appender.start()
    try:
        assert appended.wait(1), "verification held the append lock for its scan"
    finally:
        continue_scan.set()
        worker.join(2)
        appender.join(2)
    report = result["report"]
    assert report.valid
    assert report.verified_records == 1
    assert audit.head_snapshot()["last_record_number"] == 2


def test_verify_cancellation_after_a_record_is_not_reported_as_corruption(
    tmp_path, monkeypatch
):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    cancelled = threading.Event()
    original_verify = audit_module.verify_audit_record

    def cancel_after_record(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        cancelled.set()
        return result

    monkeypatch.setattr(audit_module, "verify_audit_record", cancel_after_record)
    with pytest.raises(SparcError) as raised:
        audit.verify(cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"


def test_verify_log_honors_cancellation_before_file_work_and_after_record(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog, verify_log
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    audit.append("send_attempt", _metadata(1))
    with pytest.raises(SparcError) as before:
        verify_log(audit.path, identity.public_bytes, cancelled=lambda: True)
    assert before.value.code == "operation_cancelled"

    cancelled = threading.Event()
    original_verify = audit_module.verify_audit_record

    def cancel_after_record(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        cancelled.set()
        return result

    monkeypatch.setattr(audit_module, "verify_audit_record", cancel_after_record)
    with pytest.raises(SparcError) as after:
        verify_log(audit.path, identity.public_bytes, cancelled=cancelled.is_set)
    assert after.value.code == "operation_cancelled"


def test_empty_prefix_without_checkpoint_reports_available_empty_chain_only(tmp_path):
    from sparc.audit import AuditLog

    audit = AuditLog(tmp_path, _identity())
    report = audit.verify()
    assert report.valid
    assert report.verified_records == 0
    assert not report.checkpoint_checked
    assert "available empty chain only" in report.reason


def test_empty_captured_prefix_rejects_other_log_zero_head_checkpoint(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    first = AuditLog(tmp_path / "first", identity)
    second = AuditLog(tmp_path / "second", identity)
    foreign_checkpoint = tmp_path / "second-zero-head.json"
    second.export_checkpoint(foreign_checkpoint)

    report = first.verify(foreign_checkpoint)
    assert not report.valid
    assert not report.checkpoint_checked
    assert "audit_chain_mismatch" in report.reason

    own_checkpoint = tmp_path / "first-zero-head.json"
    first.export_checkpoint(own_checkpoint)
    own_report = first.verify(own_checkpoint)
    assert own_report.valid
    assert own_report.checkpoint_checked
    available = first.verify()
    assert available.valid and not available.checkpoint_checked
    assert "available empty chain only" in available.reason


def test_checkpoint_failure_after_cancellation_propagates_cancelled(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog, verify_log
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    cancelled = threading.Event()

    def invalid_checkpoint_after_cancel(_path, _public_key):
        cancelled.set()
        raise SparcError("invalid_schema", "injected checkpoint read failure")

    monkeypatch.setattr(audit_module, "_validate_checkpoint", invalid_checkpoint_after_cancel)
    with pytest.raises(SparcError) as raised:
        verify_log(audit.path, identity.public_bytes, tmp_path / "broken.json", cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"


def test_malformed_read_after_cancellation_propagates_without_record_check(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import verify_log
    from sparc.models import SparcError

    path = tmp_path / "malformed.jsonl"
    cancelled = threading.Event()
    verified_records = []

    class MalformedRead:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def readline(self, _size=-1):
            cancelled.set()
            return b"unterminated"

    monkeypatch.setattr(audit_module.Path, "open", lambda *_args, **_kwargs: MalformedRead())
    monkeypatch.setattr(
        audit_module, "verify_audit_record",
        lambda *args, **kwargs: verified_records.append(args),
    )
    with pytest.raises(SparcError) as raised:
        verify_log(path, _identity().public_bytes, cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"
    assert verified_records == []


def test_unreadable_file_error_after_cancellation_propagates_cancelled(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import verify_log
    from sparc.models import SparcError

    cancelled = threading.Event()

    def fail_open(*_args, **_kwargs):
        cancelled.set()
        raise OSError("injected unreadable file")

    monkeypatch.setattr(audit_module.Path, "open", fail_open)
    with pytest.raises(SparcError) as raised:
        verify_log(tmp_path / "unreadable.jsonl", _identity().public_bytes,
                   cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"


@pytest.mark.parametrize("same_retained", [False, True])
def test_cancel_during_final_checkpoint_publication_reports_cancelled_without_poisoning(
    tmp_path, monkeypatch, same_retained,
):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    selected = audit.checkpoint_path if same_retained else tmp_path / "selected-final.json"
    cancelled = threading.Event()
    original_write = audit_module.atomic_write
    def cancel_after_final_write(path, *args, **kwargs):
        result = original_write(path, *args, **kwargs)
        if Path(path).resolve() == Path(selected).resolve():
            cancelled.set()
        return result

    monkeypatch.setattr(audit_module, "atomic_write", cancel_after_final_write)
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(selected, cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"
    assert audit.checkpoint_path.exists()
    if not same_retained:
        assert selected.exists()
    assert not audit._poisoned
    audit.append("send_attempt", _metadata(2))


def test_empty_captured_prefix_rejects_other_log_zero_head_checkpoint(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    first = AuditLog(tmp_path / "first", identity)
    second = AuditLog(tmp_path / "second", identity)
    foreign_checkpoint = tmp_path / "second-zero-head.json"
    second.export_checkpoint(foreign_checkpoint)

    report = first.verify(foreign_checkpoint)
    assert not report.valid
    assert not report.checkpoint_checked
    assert "audit_chain_mismatch" in report.reason

    own_checkpoint = tmp_path / "first-zero-head.json"
    first.export_checkpoint(own_checkpoint)
    own_report = first.verify(own_checkpoint)
    assert own_report.valid
    assert own_report.checkpoint_checked
    available = first.verify()
    assert available.valid and not available.checkpoint_checked
    assert "available empty chain only" in available.reason


def test_checkpoint_failure_after_cancellation_propagates_cancelled(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog, verify_log
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    cancelled = threading.Event()

    def invalid_checkpoint_after_cancel(_path, _public_key):
        cancelled.set()
        raise SparcError("invalid_schema", "injected checkpoint read failure")

    monkeypatch.setattr(audit_module, "_validate_checkpoint", invalid_checkpoint_after_cancel)
    with pytest.raises(SparcError) as raised:
        verify_log(audit.path, identity.public_bytes, tmp_path / "broken.json", cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"


def test_malformed_read_after_cancellation_propagates_without_record_check(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import verify_log
    from sparc.models import SparcError

    path = tmp_path / "malformed.jsonl"
    cancelled = threading.Event()
    verified_records = []

    class MalformedRead:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def readline(self, _size=-1):
            cancelled.set()
            return b"unterminated"

    monkeypatch.setattr(audit_module.Path, "open", lambda *_args, **_kwargs: MalformedRead())
    monkeypatch.setattr(
        audit_module, "verify_audit_record",
        lambda *args, **kwargs: verified_records.append(args),
    )
    with pytest.raises(SparcError) as raised:
        verify_log(path, _identity().public_bytes, cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"
    assert verified_records == []


def test_unreadable_file_error_after_cancellation_propagates_cancelled(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import verify_log
    from sparc.models import SparcError

    cancelled = threading.Event()

    def fail_open(*_args, **_kwargs):
        cancelled.set()
        raise OSError("injected unreadable file")

    monkeypatch.setattr(audit_module.Path, "open", fail_open)
    with pytest.raises(SparcError) as raised:
        verify_log(tmp_path / "unreadable.jsonl", _identity().public_bytes,
                   cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"


@pytest.mark.parametrize("same_retained", [False, True])
def test_cancel_during_final_checkpoint_publication_reports_cancelled_without_poisoning(
    tmp_path, monkeypatch, same_retained,
):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    selected = audit.checkpoint_path if same_retained else tmp_path / "selected-final.json"
    cancelled = threading.Event()
    original_write = audit_module.atomic_write
    published = []

    def cancel_after_final_write(path, *args, **kwargs):
        result = original_write(path, *args, **kwargs)
        published.append(Path(path))
        if Path(path).resolve() == Path(selected).resolve():
            cancelled.set()
        return result

    monkeypatch.setattr(audit_module, "atomic_write", cancel_after_final_write)
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(selected, cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"
    assert audit.checkpoint_path.exists()
    if not same_retained:
        assert selected.exists()
    assert not audit._poisoned
    audit.append("send_attempt", _metadata(2))


def test_head_snapshot_cancellation_while_waiting_for_append_lock(tmp_path):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    checking = threading.Event()
    cancelled = threading.Event()
    result = {}

    def cancellation_requested():
        checking.set()
        return cancelled.is_set()

    def snapshot():
        try:
            audit.head_snapshot(cancelled=cancellation_requested)
        except SparcError as exc:
            result["error"] = exc

    audit._lock.acquire()
    worker = threading.Thread(target=snapshot)
    worker.start()
    try:
        assert checking.wait(1)
        cancelled.set()
        worker.join(1)
    finally:
        audit._lock.release()
        worker.join(1)
    assert result["error"].code == "operation_cancelled"


def test_checkpoint_cancel_between_copies_keeps_retained_copy_without_poisoning(
    tmp_path, monkeypatch
):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    selected = tmp_path / "selected-checkpoint.json"
    cancelled = threading.Event()
    original_write = audit_module.atomic_write
    writes = []

    def cancel_after_first_copy(*args, **kwargs):
        result = original_write(*args, **kwargs)
        writes.append(args[0])
        if len(writes) == 1:
            cancelled.set()
        return result

    monkeypatch.setattr(audit_module, "atomic_write", cancel_after_first_copy)
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(selected, cancelled=cancelled.is_set)
    assert raised.value.code == "operation_cancelled"
    assert audit.checkpoint_path.exists()
    assert not selected.exists()
    assert not audit._poisoned
    audit.append("send_attempt", _metadata(2))


def test_checkpoint_cancel_before_publication_writes_nothing_and_does_not_poison(tmp_path):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    selected = tmp_path / "selected-checkpoint.json"
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(selected, cancelled=lambda: True)
    assert raised.value.code == "operation_cancelled"
    assert not audit.checkpoint_path.exists()
    assert not selected.exists()
    assert not audit._poisoned
    audit.append("send_attempt", _metadata(2))


def test_verify_detects_truncation_after_capturing_committed_prefix(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    audit.append("send_attempt", _metadata(2))
    entered_record = threading.Event()
    continue_scan = threading.Event()
    original_verify = audit_module.verify_audit_record

    def gated_verify(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        if not entered_record.is_set():
            entered_record.set()
            assert continue_scan.wait(2), "test did not release prefix verifier"
        return result

    monkeypatch.setattr(audit_module, "verify_audit_record", gated_verify)
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("report", audit.verify()))
    worker.start()
    try:
        assert entered_record.wait(1), "verification did not reach record scan"
        first_line = audit.path.read_bytes().splitlines(keepends=True)[0]
        audit.path.write_bytes(first_line)
    finally:
        continue_scan.set()
        worker.join(2)
    report = result["report"]
    assert not report.valid
    assert report.reason


def test_verify_detects_replacement_with_different_valid_signed_chain(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog

    identity = _identity()
    audit = AuditLog(tmp_path / "primary", identity)
    audit.append("send_attempt", _metadata(1))
    other = AuditLog(tmp_path / "alternate", identity)
    other.append("send_attempt", _metadata(1))
    opened = threading.Event()
    continue_scan = threading.Event()
    original_open = audit_module.Path.open
    opened_streams = []

    def gate_scan_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == audit.path and mode == "rb" and not opened.is_set():
            opened_streams.append(stream)
            opened.set()
            assert continue_scan.wait(2), "test did not release replacement scan"
        return stream

    monkeypatch.setattr(audit_module.Path, "open", gate_scan_open)
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("report", audit.verify()))
    worker.start()
    try:
        assert opened.wait(1), "verification did not open captured prefix"
        audit.path.write_bytes(other.path.read_bytes())
    finally:
        continue_scan.set()
        worker.join(2)
    assert not result["report"].valid
    assert "captured committed head" in result["report"].reason


def test_checkpoint_beyond_captured_prefix_fails_despite_newer_append(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog, CHECKPOINT_DOMAIN

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    first = audit.append("send_attempt", _metadata(1))
    checkpoint_body = {
        "log_id": first.record["body"]["log_id"],
        "last_record_number": 2,
        "last_record_hash": "f" * 64,
        "identity_fingerprint": identity.fingerprint,
    }
    signature = identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(checkpoint_body))
    checkpoint = tmp_path / "future-checkpoint.json"
    checkpoint.write_bytes(_canonical({
        "body": checkpoint_body,
        "signature": base64.b64encode(signature).decode("ascii"),
    }))

    entered_record = threading.Event()
    continue_scan = threading.Event()
    original_verify = audit_module.verify_audit_record
    result = {}

    def gated_verify(*args, **kwargs):
        verified = original_verify(*args, **kwargs)
        if not entered_record.is_set():
            entered_record.set()
            assert continue_scan.wait(2), "test did not release checkpoint verifier"
        return verified

    monkeypatch.setattr(audit_module, "verify_audit_record", gated_verify)
    worker = threading.Thread(target=lambda: result.setdefault(
        "report", audit.verify(checkpoint)
    ))
    worker.start()
    try:
        assert entered_record.wait(1), "verification did not reach checkpoint prefix"
        audit.append("send_attempt", _metadata(2))
    finally:
        continue_scan.set()
        worker.join(2)
    report = result["report"]
    assert not report.valid
    assert "beyond the available audit tail" in report.reason
    assert audit.head_snapshot()["last_record_number"] == 2


def test_verify_uses_durable_length_after_failed_partial_append(tmp_path, monkeypatch):
    import sparc.audit as audit_module
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    audit = AuditLog(tmp_path, _identity())
    audit.append("send_attempt", _metadata(1))
    committed_bytes = audit.path.stat().st_size
    original_open = audit_module.Path.open

    class PartialFailure:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, data):
            self.stream.write(data[: max(1, len(data) // 2)])
            raise OSError("injected partial append")

        def flush(self):
            return self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def open_with_partial_failure(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == audit.path and mode == "ab":
            return PartialFailure(stream)
        return stream

    monkeypatch.setattr(audit_module.Path, "open", open_with_partial_failure)
    with pytest.raises(SparcError) as raised:
        audit.append("send_attempt", _metadata(2))
    assert raised.value.code == "audit_storage_failed"
    assert audit.path.stat().st_size > committed_bytes
    report = audit.verify()
    assert report.valid
    assert report.verified_records == 1
