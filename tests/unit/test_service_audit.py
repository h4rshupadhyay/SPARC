"""C7d public audit wrapper contracts for PeerService."""

from __future__ import annotations

import queue
import threading

import pytest

from sparc.audit_format import AuditReport
from sparc.models import ServiceEvent, SparcError
from sparc.peer.service import PeerService


def _report(*, valid=True):
    return AuditReport(
        valid=valid,
        verified_records=3,
        first_failed_record=None if valid else 3,
        reason="available chain only" if valid else "audit signature failed",
        checkpoint_checked=False,
        elapsed_ns=100,
    )


def test_audit_head_is_fresh_exact_public_snapshot(tmp_path):
    service = PeerService(tmp_path)
    try:
        first = service.audit_head()
        assert set(first) == {
            "log_id", "last_record_number", "last_record_hash", "identity_fingerprint",
        }
        assert first["last_record_number"] == 0
        assert first["last_record_hash"] == "0" * 64
        first["last_record_hash"] = "f" * 64
        second = service.audit_head()
        assert second["last_record_hash"] == "0" * 64
        assert second is not first
    finally:
        service.close()


def test_verify_forwards_composed_service_and_caller_cancellation(tmp_path, monkeypatch):
    service = PeerService(tmp_path)
    caller_cancel = threading.Event()
    predicates = []

    def verify(checkpoint=None, *, cancelled=None):
        predicates.append(cancelled)
        assert checkpoint is None
        assert cancelled is not None
        assert not cancelled()
        return _report()

    monkeypatch.setattr(service._audit, "verify", verify)
    try:
        assert service.verify_audit(cancel=caller_cancel).valid
        assert len(predicates) == 1
        predicate = predicates[0]
        caller_cancel.set()
        assert predicate()
        caller_cancel.clear()
        service._cancel.set()
        assert predicate()
    finally:
        service.close()


def test_audit_read_works_after_sticky_failure_but_export_refuses(tmp_path, monkeypatch):
    service = PeerService(tmp_path)
    monkeypatch.setattr(service._audit, "head_snapshot", lambda *, cancelled=None: {
        "log_id": "1" * 32,
        "last_record_number": 0,
        "last_record_hash": "0" * 64,
        "identity_fingerprint": service.own_fingerprint,
    })
    monkeypatch.setattr(service._audit, "verify", lambda checkpoint=None, *, cancelled=None: _report())
    service._audit_failed = True
    try:
        assert service.audit_head()["log_id"] == "1" * 32
        assert service.verify_audit().valid
        with pytest.raises(SparcError) as raised:
            service.export_audit_checkpoint(tmp_path / "selected.json")
        assert raised.value.code == "audit_storage_failed"
    finally:
        service.close()


def test_verify_caller_cancellation_raises_operation_cancelled(tmp_path):
    service = PeerService(tmp_path)
    caller_cancel = threading.Event()
    caller_cancel.set()
    try:
        with pytest.raises(SparcError) as raised:
            service.verify_audit(cancel=caller_cancel)
        assert raised.value.code == "operation_cancelled"
    finally:
        service.close()


def test_checkpoint_storage_failure_latches_without_event_queue_capacity(tmp_path, monkeypatch):
    service = PeerService(tmp_path)

    def fail_export(_path, *, cancelled=None):
        raise SparcError("audit_storage_failed", "injected checkpoint fsync failure")

    monkeypatch.setattr(service._audit, "export_checkpoint", fail_export)
    while True:
        try:
            service.events.put_nowait(ServiceEvent("filler", {}))
        except queue.Full:
            break
    try:
        with pytest.raises(SparcError) as raised:
            service.export_audit_checkpoint(tmp_path / "selected.json")
        assert raised.value.code == "audit_storage_failed"
        assert service._audit_failed
    finally:
        service.close()


def test_checkpoint_cancellation_does_not_latch_audit_failure(tmp_path, monkeypatch):
    service = PeerService(tmp_path)
    caller_cancel = threading.Event()

    def cancel_export(_path, *, cancelled=None):
        assert cancelled is not None
        caller_cancel.set()
        assert cancelled()
        raise SparcError("operation_cancelled", "canceled by caller")

    monkeypatch.setattr(service._audit, "export_checkpoint", cancel_export)
    try:
        with pytest.raises(SparcError) as raised:
            service.export_audit_checkpoint(tmp_path / "selected.json", cancel=caller_cancel)
        assert raised.value.code == "operation_cancelled"
        assert not service._audit_failed
    finally:
        service.close()


def test_service_closed_cancellation_reaches_audit_wrapper(tmp_path):
    service = PeerService(tmp_path)
    service.close()
    with pytest.raises(SparcError) as raised:
        service.verify_audit()
    assert raised.value.code == "operation_cancelled"
