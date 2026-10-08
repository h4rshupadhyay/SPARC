"""Authenticated application delivery and receipt behavior over real peers."""

import json
import queue
import time
import copy
import threading

import pytest

from sparc.audit import verify_log
from sparc.audit_format import verify_peer_evidence
from sparc.models import Limits, OpenedRecord, ProtectedRecord, SparcError

from conftest import wait_event


def _records(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


def _wait_state(service, expected, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == expected:
            return
        time.sleep(0.005)
    assert service.state == expected


def test_bidirectional_unicode_delivery_is_audited(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    for sender, receiver, text in (
        (alice, bob, "Cafe\u0301 → 雪🧪"),
        (bob, alice, "reply: 🛰️ Καλημέρα"),
    ):
        message_id = sender.send_text(text)
        event = wait_event(receiver, "message", message_id)
        assert event.data["text"] == text
        receipt = sender.wait_for_receipt(message_id, timeout=6)
        assert receipt.message_id == message_id
        assert receipt.plaintext_bytes == len(text.encode("utf-8"))
        assert receipt.characters == len(text)
        assert receipt.frame_bytes > receipt.plaintext_bytes

    for service in (alice, bob):
        events = _records(service)
        verified = [row for row in events if row["event"] == "verified_receipt"]
        delivered = [row for row in events if row["event"] == "verified_delivery"]
        assert verified and delivered
        for row in [*verified, *delivered]:
            verify_peer_evidence(row["metadata"])
        report = verify_log(
            service.data_dir / "audit.jsonl",
            service._identity.public_bytes,
            service._audit.checkpoint_path,
        )
        assert report.valid


def test_message_events_include_local_origin(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    message_id = sender.send_text("origin contract")
    sent = wait_event(sender, "message", message_id)
    received = wait_event(receiver, "message", message_id)
    assert sent.data["origin"] == "outgoing"
    assert received.data["origin"] == "incoming"


def test_failed_receive_audit_prevents_ack_and_display(peer_pair, monkeypatch):
    sender, receiver = peer_pair.alice, peer_pair.bob
    original_append = receiver._audit.append

    def fail_receipt(kind, metadata):
        if kind == "verified_receipt":
            raise SparcError("audit_storage_failed", "injected receive audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(receiver._audit, "append", fail_receipt)
    message_id = sender.send_text("must not be displayed or acknowledged")
    _wait_state(receiver, "error")
    with pytest.raises(SparcError):
        sender.wait_for_receipt(message_id, timeout=2)
    assert not any(
        event.kind == "message" and event.data.get("message_id") == message_id
        for event in list(receiver.events.queue)
    )
    assert not any(
        row["event"] == "verified_delivery" and row["metadata"].get("message_id") == message_id
        for row in _records(sender)
    )


def test_ack_is_not_recursively_acknowledged(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    message_id = sender.send_text("one application record")
    wait_event(receiver, "message", message_id)
    sender.wait_for_receipt(message_id, timeout=6)
    sender_rows = _records(sender)
    receiver_rows = _records(receiver)
    assert sum(row["event"] == "verified_receipt" for row in receiver_rows) == 1
    assert not any(row["event"] == "verified_receipt" for row in sender_rows)
    assert not any(row["event"] == "verified_delivery" for row in receiver_rows)


def test_stale_payload_handler_cannot_audit_or_confirm_replacement_receipt(peer_pair):
    sender = peer_pair.alice
    session = sender._slot.session
    queued = []
    session.enqueue = lambda payload, control=False: queued.append(payload)
    message_id = sender.send_text("pending on replacement")
    pending = sender._receipts.validate_ack(message_id, queued[0]["sha256"])
    stale_attempt = copy.copy(sender._slot)
    opened = OpenedRecord({
        "kind": "ack",
        "message_id": message_id,
        "sha256": pending.sha256,
        "status": "verified",
    }, None, sequence=4, direction=1)
    before = len(_records(sender))

    sender._handle_payload(stale_attempt, session, None, opened)

    assert len(_records(sender)) == before
    assert sender._receipts.validate_ack(message_id, pending.sha256) == pending


def test_delivery_audit_failure_prevents_successful_receipt(peer_pair, monkeypatch):
    sender, receiver = peer_pair.alice, peer_pair.bob
    receiver_session = receiver._slot.session
    original_enqueue = receiver_session.enqueue
    captured_acks = []

    def hold_ack(payload, control=False):
        if control and payload.get("kind") == "ack":
            captured_acks.append(payload)
            return
        original_enqueue(payload, control=control)

    receiver_session.enqueue = hold_ack
    message_id = sender.send_text("delivery audit failure")
    wait_event(receiver, "message", message_id)
    assert captured_acks
    original_append = sender._audit.append

    def fail_delivery(kind, metadata):
        if kind == "verified_delivery":
            raise SparcError("audit_storage_failed", "injected delivery audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(sender._audit, "append", fail_delivery)
    original_enqueue(captured_acks[0], control=True)
    with pytest.raises(SparcError):
        sender.wait_for_receipt(message_id, timeout=5)
    assert not any(
        row["event"] == "verified_delivery" and row["metadata"].get("message_id") == message_id
        for row in _records(sender)
    )


def test_cancel_during_successful_delivery_audit_never_publishes_receipt(
    peer_pair, monkeypatch
):
    sender, receiver = peer_pair.alice, peer_pair.bob
    receiver_session = receiver._slot.session
    original_enqueue = receiver_session.enqueue
    captured_acks = []

    def hold_ack(payload, control=False):
        if control and payload.get("kind") == "ack":
            captured_acks.append(payload)
            return
        original_enqueue(payload, control=control)

    receiver_session.enqueue = hold_ack
    message_id = sender.send_text("cancel during delivery audit")
    wait_event(receiver, "message", message_id)
    assert captured_acks

    entered_audit = threading.Event()
    release_audit = threading.Event()
    original_append = sender._audit.append

    def pause_successful_delivery(kind, metadata):
        if kind == "verified_delivery":
            entered_audit.set()
            assert release_audit.wait(timeout=15), "delivery audit was not released"
        return original_append(kind, metadata)

    monkeypatch.setattr(sender._audit, "append", pause_successful_delivery)
    original_enqueue(captured_acks[0], control=True)
    attempt = sender._slot
    session = attempt.session
    closer = threading.Thread(target=session.close)
    try:
        assert entered_audit.wait(timeout=3)
        closer.start()
        assert attempt.cancel.wait(timeout=1)
        release_audit.set()
        closer.join(timeout=3)
        assert not closer.is_alive()
        with pytest.raises(SparcError) as raised:
            sender.wait_for_receipt(message_id, timeout=0.5)
        assert raised.value.code == "delivery_unconfirmed"
        assert any(row["event"] == "verified_delivery" for row in _records(sender))
        assert not any(
            event.kind == "delivery" and event.data.get("message_id") == message_id
            for event in list(sender.events.queue)
        )
    finally:
        release_audit.set()
        if closer.ident is not None:
            closer.join(timeout=2)


def test_receiver_benchmark_record_cap_rejects_excess(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    receiver.limits = Limits(benchmark_records=1, benchmark_bytes=1024)
    run_id = "d" * 32
    first_id = sender.send_text("one", run_id=run_id)
    sender.wait_for_receipt(first_id, timeout=6)
    second_id = sender.send_text("two", run_id=run_id)
    with pytest.raises(SparcError):
        sender.wait_for_receipt(second_id, timeout=6)
    _wait_state(receiver, "error")
    received = [
        row for row in _records(receiver)
        if row["event"] == "verified_receipt" and row["metadata"].get("run_id") == run_id
    ]
    assert len(received) == 1


def test_benchmark_delivery_uses_progress_events_not_chat_bubbles(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    run_id = "c" * 32
    message_ids = [
        sender.send_text("benchmark sample", run_id=run_id),
        sender.send_text("benchmark sample two", run_id=run_id),
    ]
    for message_id in message_ids:
        sender.wait_for_receipt(message_id, timeout=6)

    deadline = time.monotonic() + 3
    progress_events = []
    while time.monotonic() < deadline:
        try:
            event = receiver.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if event.data.get("run_id") == run_id:
            progress_events.append(event)
            if len(progress_events) >= 2:
                break
    assert progress_events
    assert all(event.kind != "message" for event in progress_events)


def test_bad_authenticated_record_closes_without_plaintext_event(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    session = sender._slot.session
    original_protect = session._codec.protect

    def corrupt_frame(payload):
        protected = original_protect(payload)
        damaged = bytearray(protected.frame)
        damaged[-1] ^= 1
        return ProtectedRecord(bytes(damaged), protected.inspection)

    session._codec.protect = corrupt_frame
    message_id = sender.send_text("unauthenticated data")
    _wait_state(receiver, "error")
    assert not any(event.kind == "message" for event in list(receiver.events.queue))
    with pytest.raises(SparcError):
        sender.wait_for_receipt(message_id, timeout=3)
