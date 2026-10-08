"""C5e outbound reservation and accountable send ordering."""

import json
import copy
import queue
import threading
import time

import pytest

from sparc.models import Endpoint, Limits, ProtectedRecord, SparcError
from sparc.peer.service import PeerService


def _wait_pairing(service, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if "request_id" in event.data:
            return event
    raise AssertionError("timed out waiting for a test pairing request")


def _wait_connected(service, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == "connected":
            return
        time.sleep(0.005)
    assert service.state == "connected"


def _connected_pair(tmp_path, limits=Limits()):
    receiver = PeerService(tmp_path / "receiver", limits)
    sender = None
    try:
        endpoint = receiver.start_listener("127.0.0.1", 0)
        sender = PeerService(tmp_path / "sender", limits)
        sender.connect(endpoint)
        sender_request = _wait_pairing(sender)
        sender.respond_to_pairing(sender_request.data["request_id"], True)
        receiver_request = _wait_pairing(receiver)
        receiver.respond_to_pairing(receiver_request.data["request_id"], True)
        _wait_connected(sender)
        _wait_connected(receiver)
        return sender, receiver
    except Exception:
        if sender is not None:
            sender.close()
        receiver.close()
        raise


def _session(service):
    return service._slot.session


def _replace_enqueue(service, callback):
    session = _session(service)
    session.enqueue = callback
    return session


def test_send_requires_connected(tmp_path):
    service = PeerService(tmp_path)
    try:
        with pytest.raises(SparcError):
            service.send_text("hello")
    finally:
        service.close()


def test_send_attempt_audited_before_enqueue_and_storage_failure_sends_nothing(
    tmp_path, monkeypatch
):
    sender, receiver = _connected_pair(tmp_path)
    wire_queue = []

    def capture(payload, *, control=False):
        wire_queue.append((payload, control))

    _replace_enqueue(sender, capture)

    def fail_audit(_kind, _metadata):
        raise SparcError("audit_storage_failed", "injected send-attempt fsync failure")

    monkeypatch.setattr(sender._audit, "append", fail_audit)
    try:
        with pytest.raises(SparcError) as raised:
            sender.send_text("must not go to wire")
        assert raised.value.code == "audit_storage_failed"
        assert wire_queue == []
    finally:
        sender.close()
        receiver.close()


def test_timer_starts_before_hash_preparation(tmp_path, monkeypatch):
    import sparc.peer.service as service_module
    from sparc.protocol.messages import prepare_text as real_prepare_text

    sender, receiver = _connected_pair(tmp_path)
    queue_payloads = []
    _replace_enqueue(sender, lambda payload, *, control=False: queue_payloads.append(payload))
    order = []
    clock_value = [1_000]

    def controlled_clock():
        order.append("clock")
        clock_value[0] += 10
        return clock_value[0]

    def observe_prepare(*args, **kwargs):
        order.append("prepare")
        return real_prepare_text(*args, **kwargs)

    monkeypatch.setattr(service_module.time, "perf_counter_ns", controlled_clock)
    monkeypatch.setattr(service_module, "prepare_text", observe_prepare, raising=False)
    try:
        message_id = sender.send_text("timer ordering")
        assert message_id == queue_payloads[0]["message_id"]
        assert order[0] == "clock"
        assert order.index("clock") < order.index("prepare")
        pending = sender._receipts.validate_ack(message_id, queue_payloads[0]["sha256"])
        assert pending.started_ns == 1_010
    finally:
        sender.close()
        receiver.close()


def test_pending_is_reserved_and_send_attempt_is_durable_before_enqueue(tmp_path):
    sender, receiver = _connected_pair(tmp_path)
    observations = []

    def acknowledge_immediately(payload, *, control=False):
        pending = sender._receipts.validate_ack(payload["message_id"], payload["sha256"])
        audit_events = [
            json.loads(line)["body"]["event"]
            for line in (sender.data_dir / "audit.jsonl").read_text("utf-8").splitlines()
        ]
        assert "send_attempt" in audit_events
        observations.append((pending, control))

    _replace_enqueue(sender, acknowledge_immediately)
    try:
        message_id = sender.send_text("reservation ordering")
        assert len(observations) == 1
        pending, control = observations[0]
        assert not control
        assert pending.message_id == message_id
        assert pending.sha256
        assert pending.frame_bytes == 0
        receipt = sender._receipts.confirm(message_id, pending.sha256, pending.started_ns + 1)
        assert receipt.message_id == message_id
    finally:
        sender.close()
        receiver.close()


def test_frame_bytes_are_the_actual_protected_frame_length(tmp_path):
    sender, receiver = _connected_pair(tmp_path)
    queued = []
    _replace_enqueue(sender, lambda payload, *, control=False: queued.append(payload))
    try:
        message_id = sender.send_text("frame accounting")
        payload = queued[0]
        hook = _session(sender)._hooks.on_written
        assert hook is not None
        encoded = b"frame-prefix-and-protected-record"
        protected = ProtectedRecord(frame=encoded)
        hook(payload, protected)
        pending = sender._receipts.validate_ack(message_id, payload["sha256"])
        assert pending.frame_bytes == len(encoded)
        receipt = sender._receipts.confirm(message_id, payload["sha256"], pending.started_ns + 1)
        assert receipt.frame_bytes == len(encoded)
    finally:
        sender.close()
        receiver.close()


def test_benchmark_record_limit_is_per_connection(tmp_path, monkeypatch):
    sender, receiver = _connected_pair(tmp_path)
    session = _session(sender)
    receipt_ledger = sender._receipts

    def complete_in_queue(payload, *, control=False):
        pending = receipt_ledger.validate_ack(payload["message_id"], payload["sha256"])
        receipt_ledger.confirm(
            pending.message_id,
            pending.sha256,
            pending.started_ns + 1,
        )

    session.enqueue = complete_in_queue
    monkeypatch.setattr(sender._audit, "append", lambda _kind, _metadata: None)
    try:
        for _ in range(1000):
            sender.send_text("x", run_id="a" * 32)
        with pytest.raises(SparcError) as raised:
            sender.send_text("x", run_id="a" * 32)
        assert raised.value.code in {"busy", "benchmark_limit"}
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("callback_name", ["_session_closed", "_finish_attempt"])
def test_stale_attempt_terminal_callback_preserves_current_pending_receipt(
    tmp_path, callback_name
):
    sender, receiver = _connected_pair(tmp_path)
    queued = []
    session = _replace_enqueue(sender, lambda payload, *, control=False: queued.append(payload))
    try:
        message_id = sender.send_text("current session message")
        pending = sender._receipts.validate_ack(message_id, queued[0]["sha256"])
        stale_attempt = copy.copy(sender._slot)
        error = SparcError("tcp_loss", "stale owner callback")

        if callback_name == "_session_closed":
            sender._session_closed(stale_attempt, error)
        else:
            sender._finish_attempt(stale_attempt, error)

        retained = sender._receipts.validate_ack(message_id, pending.sha256)
        assert retained == pending
        assert sender._slot.session is session
        assert sender.state == "connected"
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("failure", ["domain", "unexpected"])
def test_old_send_audit_failure_preserves_replacement_pending_and_hash(
    tmp_path, failure
):
    sender, receiver = _connected_pair(tmp_path)
    old_attempt = sender._slot
    old_session = old_attempt.session
    entered_audit = threading.Event()
    release_audit = threading.Event()
    original_append = sender._audit.append
    old_thread_id = []

    def pause_old_send(kind, metadata):
        if kind == "send_attempt" and threading.get_ident() == old_thread_id[0]:
            entered_audit.set()
            assert release_audit.wait(timeout=15), "old send audit was not released"
            if failure == "domain":
                raise SparcError("audit_storage_failed", "injected old audit failure")
            raise RuntimeError("injected unexpected audit failure")
        return original_append(kind, metadata)

    sender._audit.append = pause_old_send
    old_errors = []

    def old_send():
        old_thread_id.append(threading.get_ident())
        try:
            sender.send_text("old attempt")
        except SparcError as error:
            old_errors.append(error)

    worker = threading.Thread(target=old_send)
    try:
        worker.start()
        assert entered_audit.wait(timeout=3)
        old_session.close()
        sender_deadline = time.monotonic() + 3
        while sender._slot is not None and time.monotonic() < sender_deadline:
            time.sleep(0.005)
        assert sender._slot is None
        receiver_deadline = time.monotonic() + 3
        while (receiver._slot is not None or receiver._listener is None) and time.monotonic() < receiver_deadline:
            time.sleep(0.005)
        assert receiver._slot is None
        assert receiver._listener is not None
        sender.connect(old_attempt.endpoint)
        _wait_connected(sender)
        _wait_connected(receiver)

        queued = []
        replacement = sender._slot
        replacement.session.enqueue = lambda payload, *, control=False: queued.append(payload)
        replacement_id = sender.send_text("replacement pending")
        pending = sender._receipts.validate_ack(replacement_id, queued[0]["sha256"])
        replacement_hash = sender._hash_ns_by_id[replacement_id]

        release_audit.set()
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert old_errors and old_errors[0].code == "audit_storage_failed"
        assert sender._slot is replacement
        assert sender._receipts.validate_ack(replacement_id, pending.sha256) == pending
        assert sender._hash_ns_by_id[replacement_id] == replacement_hash
    finally:
        release_audit.set()
        worker.join(timeout=2)
        sender.close()
        receiver.close()


def test_failed_enqueue_fails_only_its_message(tmp_path):
    sender, receiver = _connected_pair(tmp_path)
    queued = []

    def enqueue(payload, *, control=False):
        queued.append(payload)
        if len(queued) == 2:
            raise SparcError("busy", "Outbound session queue is full")

    _replace_enqueue(sender, enqueue)
    try:
        first_id = sender.send_text("first pending")
        first = sender._receipts.validate_ack(first_id, queued[0]["sha256"])
        with pytest.raises(SparcError) as raised:
            sender.send_text("second fails")
        assert raised.value.code == "busy"
        with pytest.raises(SparcError) as failed:
            sender._receipts.wait(queued[1]["message_id"], timeout=0)
        assert failed.value.code == "delivery_unconfirmed"
        assert sender._receipts.validate_ack(first_id, first.sha256) == first
    finally:
        sender.close()
        receiver.close()


def test_benchmark_byte_limit_is_per_connection(tmp_path):
    limits = Limits(benchmark_records=100, benchmark_bytes=2)
    sender, receiver = _connected_pair(tmp_path, limits)
    session = _session(sender)

    def complete_in_queue(payload, *, control=False):
        pending = sender._receipts.validate_ack(payload["message_id"], payload["sha256"])
        sender._receipts.confirm(pending.message_id, pending.sha256, pending.started_ns + 1)

    session.enqueue = complete_in_queue
    try:
        sender.send_text("xx", run_id="b" * 32)
        with pytest.raises(SparcError) as raised:
            sender.send_text("x", run_id="b" * 32)
        assert raised.value.code == "benchmark_limit"
    finally:
        sender.close()
        receiver.close()
