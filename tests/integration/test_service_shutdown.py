"""Finite cancellation, loss, metrics and late-owner service behavior."""

import json
import queue
import socket
import threading
import time

import pytest

import sparc.peer.service as service_module
from conftest import _connected, _pairing_request, wait_event
from sparc.audit import verify_log
from sparc.models import Endpoint, Limits, ServiceEvent, SparcError
from sparc.peer.service import PeerService
from sparc.protocol.framing import pack_frame


def _wait_state(service, expected, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == expected:
            return
        time.sleep(0.005)
    assert service.state == expected


def _audit_records(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


def _terminal_state(service, expected_reason=None, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if (
            event.kind == "state"
            and event.data.get("state") in {"listening", "stopped", "error"}
            and (expected_reason is None or event.data.get("reason") == expected_reason)
        ):
            return event
    raise AssertionError("terminal state event was not delivered")


def test_disconnect_during_pairing_cancels_workers(tmp_path):
    bob = PeerService(tmp_path / "bob")
    endpoint = bob.start_listener("127.0.0.1", 0)
    alice = PeerService(tmp_path / "alice")
    try:
        alice.connect(endpoint)
        _pairing_request(alice)
        workers = list(alice._workers)
        alice.disconnect()
        _wait_state(alice, "stopped")
        assert alice._slot is None
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and bob._slot is not None:
            time.sleep(0.005)
        assert bob._slot is None
        assert bob._listener is not None
    finally:
        alice.close()
        bob.close()


@pytest.mark.parametrize("trigger", ["direct_close", "writer_failure"])
@pytest.mark.parametrize(
    "peer_pair", [Limits(cancel_poll_seconds=0.01)], indirect=True
)
def test_session_close_unblocks_reader_and_full_event_queue(peer_pair, trigger):
    sender, receiver = peer_pair.alice, peer_pair.bob
    session = receiver._slot.session
    original_emit = receiver._emit
    emitting = threading.Event()
    sendall_entered = threading.Event()
    release_sendall = threading.Event()

    reader_thread = session._reader_worker

    def observe_emit(event, cancel=None):
        if threading.current_thread() is reader_thread:
            emitting.set()
        return original_emit(event, cancel)

    receiver._emit = observe_emit
    if trigger == "writer_failure":
        def fail_after_event(frame):
            sendall_entered.set()
            if not release_sendall.wait(1):
                raise OSError("bounded test send delay expired")
            raise OSError("injected writer loss")

        class SendallProxy:
            def __init__(self, inner):
                self.inner = inner

            def sendall(self, frame):
                fail_after_event(frame)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        session._sock = SendallProxy(session._sock)

    while True:
        try:
            receiver.events.put_nowait(ServiceEvent("occupied", {}))
        except queue.Full:
            break

    if trigger == "writer_failure":
        session.enqueue({"kind": "ping", "ping_id": "f" * 32}, control=True)

    closer = None
    try:
        sender.send_text("reader will block on the full event queue")
        assert emitting.wait(timeout=3)
        if trigger == "direct_close":
            closer = threading.Thread(target=session.close)
            closer.start()
        else:
            assert sendall_entered.wait(timeout=2)
            release_sendall.set()
            closer = session._reader_worker

        if trigger == "direct_close":
            closer.join(timeout=0.5)
            assert not closer.is_alive(), "session close must finish its on_closed callback"
        else:
            _wait_state(receiver, "error", timeout=2)
            assert session.join(timeout=1)
        assert receiver.state != "connected"
        terminal = _terminal_state(
            receiver,
            "operation_cancelled" if trigger == "direct_close" else "tcp_loss",
        )
        assert terminal.data["state"] == ("listening" if trigger == "direct_close" else "error")
    finally:
        release_sendall.set()
        receiver.close()
        if closer is not None and closer is not threading.current_thread():
            closer.join(timeout=2)


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(delivery_timeout_seconds=0.12, cancel_poll_seconds=0.01,
            reconnect_delays=())],
    indirect=True,
)
def test_delivery_timeout_is_unconfirmed_without_a_waiter(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    receiver_session = receiver._slot.session
    original_enqueue = receiver_session.enqueue

    def hold_ack(payload, control=False):
        if control and payload.get("kind") == "ack":
            return
        original_enqueue(payload, control=control)

    receiver_session.enqueue = hold_ack
    message_id = sender.send_text("ack intentionally withheld")
    wait_event(receiver, "message", message_id)
    _wait_state(sender, "error", timeout=4)
    with pytest.raises(SparcError) as raised:
        sender.wait_for_receipt(message_id, timeout=0.1)
    assert raised.value.code == "delivery_timeout"


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(delivery_timeout_seconds=0.2, cancel_poll_seconds=0.01,
            reconnect_delays=())],
    indirect=True,
)
def test_delivery_expiry_runs_while_valid_frames_continue(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    bob_session = bob._slot.session
    original_enqueue = bob_session.enqueue
    held = []

    def hold_first_ack(payload, control=False):
        if control and payload.get("kind") == "ack" and not held:
            held.append(payload)
            return
        original_enqueue(payload, control=control)

    bob_session.enqueue = hold_first_ack
    pending_id = alice.send_text("expire during inbound traffic")
    wait_event(bob, "message", pending_id)

    end = time.monotonic() + 1.5
    sent = 0
    while time.monotonic() < end and alice.state == "connected" and bob.state == "connected":
        try:
            message_id = bob.send_text(f"pulse {sent}")
            bob.wait_for_receipt(message_id, timeout=0.5)
            sent += 1
        except SparcError:
            break
    assert sent > 0
    _wait_state(alice, "error", timeout=2)
    with pytest.raises(SparcError) as raised:
        alice.wait_for_receipt(pending_id, timeout=0.1)
    assert raised.value.code == "delivery_timeout"


def test_session_generation_discards_late_completion(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    stale_attempt = alice._slot
    stale_session = stale_attempt.session
    stale_session.close()
    _wait_state(alice, "listening")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and bob._slot is not None:
        time.sleep(0.005)
    assert bob._slot is None
    assert bob._listener is not None

    alice.connect(peer_pair.bob_endpoint)
    _connected(alice)
    _connected(bob)
    current_attempt = alice._slot
    alice._session_closed(stale_attempt, SparcError("tcp_loss", "late old-session completion"))
    assert alice._slot is current_attempt
    assert alice.state == "connected"


def test_listener_lifecycle_preserves_connected_session_state(peer_pair):
    alice = peer_pair.alice
    alice.stop_listener()
    assert alice.state == "connected"
    before_start = alice.send_text("listener stopped while connected")
    alice.wait_for_receipt(before_start, timeout=6)

    endpoint = alice.start_listener("127.0.0.1", 0)
    assert isinstance(endpoint, Endpoint)
    assert alice.state == "connected"
    first = alice.send_text("listener added while connected")
    alice.wait_for_receipt(first, timeout=6)

    alice.stop_listener()
    assert alice.state == "connected"
    second = alice.send_text("listener stopped while connected")
    alice.wait_for_receipt(second, timeout=6)


def test_session_close_is_accountably_audited(peer_pair):
    alice = peer_pair.alice
    alice.disconnect()
    _wait_state(alice, "listening")
    close_rows = [row for row in _audit_records(alice) if row["event"] == "session_closed"]
    assert close_rows
    metadata = close_rows[-1]["metadata"]
    assert metadata["endpoint"] == f"{peer_pair.bob_endpoint.ip}:{peer_pair.bob_endpoint.port}"
    assert metadata["state"] == "listening"
    assert metadata["code"] == "operation_cancelled"
    assert isinstance(metadata["reason"], str) and 0 < len(metadata["reason"]) <= 120
    assert verify_log(
        alice.data_dir / "audit.jsonl",
        alice._identity.public_bytes,
        alice._audit.checkpoint_path,
    ).valid


def test_terminal_state_is_retained_when_ordinary_queue_is_full(peer_pair):
    alice, _bob = peer_pair.alice, peer_pair.bob
    session = alice._slot.session
    while True:
        try:
            alice.events.get_nowait()
        except queue.Empty:
            break
    occupied = 0
    while True:
        try:
            alice.events.put_nowait(ServiceEvent("occupied", {"index": occupied}))
            occupied += 1
        except queue.Full:
            break
    assert occupied == alice.limits.event_queue

    closer = threading.Thread(target=session.close)
    closer.start()
    closer.join(timeout=2)
    assert not closer.is_alive()
    assert alice.state == "listening"
    for index in range(occupied):
        assert alice.events.get_nowait() == ServiceEvent("occupied", {"index": index})
    terminal = _terminal_state(alice, "operation_cancelled")
    assert terminal.data["state"] == "listening"
    assert terminal.data["reason"] == "operation_cancelled"


def test_closure_audit_failure_publishes_error_terminal_state(peer_pair, monkeypatch):
    alice = peer_pair.alice
    session = alice._slot.session
    original_append = alice._audit.append

    def fail_closure(kind, metadata):
        if kind == "session_closed":
            raise SparcError("audit_storage_failed", "injected closure audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(alice._audit, "append", fail_closure)
    session.close()
    terminal = _terminal_state(alice, "audit_storage_failed")
    assert terminal.data["state"] == "error"
    assert terminal.data["reason"] == "audit_storage_failed"


def test_handshake_security_rejection_is_audited_with_safe_reason(tmp_path):
    service = PeerService(tmp_path)
    endpoint = service.start_listener("127.0.0.1", 0)
    peer = socket.create_connection((endpoint.ip, endpoint.port), timeout=2)
    try:
        peer.sendall(pack_frame(1, b"{}"))
        _wait_state(service, "error")
        rejected = [
            row for row in _audit_records(service)
            if row["event"] == "security_rejected"
        ]
        assert rejected
        metadata = rejected[-1]["metadata"]
        assert metadata["code"] == "invalid_schema"
        assert isinstance(metadata["reason"], str) and 0 < len(metadata["reason"]) <= 120
        assert "{}" not in metadata["reason"]
        terminal = _terminal_state(service, "invalid_schema")
        assert terminal.data["state"] == "error"
        assert terminal.data["reason"] == "invalid_schema"
        assert verify_log(
            service.data_dir / "audit.jsonl",
            service._identity.public_bytes,
            service._audit.checkpoint_path,
        ).valid
    finally:
        peer.close()
        service.close()


def test_private_event_queue_preserves_fifo_and_one_generation_current_terminal():
    from sparc.peer.service import _ServiceEventQueue

    events = _ServiceEventQueue(maxsize=1)
    first = ServiceEvent("verification", {"index": 1})
    second = ServiceEvent("verification", {"index": 2})
    events.put_nowait(first)
    with pytest.raises(queue.Full):
        events.put_nowait(second)
    events.advance_generation(4)
    events.publish_terminal(ServiceEvent("state", {"state": "error", "reason": "tcp_loss"}), 4)
    events.publish_terminal(ServiceEvent("state", {"state": "listening", "reason": "closed"}), 3)
    assert events.get_nowait() == first
    assert events.get_nowait() == ServiceEvent(
        "state", {"state": "error", "reason": "tcp_loss", "endpoint": None}
    )
    with pytest.raises(queue.Empty):
        events.get_nowait()

    events.publish_terminal(ServiceEvent("state", {"state": "error", "reason": "old"}), 4)
    events.advance_generation(5)
    with pytest.raises(queue.Empty):
        events.get_nowait()


def test_private_event_queue_terminal_wakes_waiter_and_empty_timeout_is_bounded():
    from sparc.peer.service import _ServiceEventQueue

    events = _ServiceEventQueue(maxsize=1)
    ordinary = ServiceEvent("verification", {"index": 1})
    events.put_nowait(ordinary)
    assert events.get(block=False, timeout=0.1) == ordinary

    events.advance_generation(2)
    terminal = ServiceEvent(
        "state", {"state": "error", "reason": "tcp_loss", "endpoint": None}
    )
    events.publish_terminal(terminal, 2)
    assert events.get(block=False, timeout=0.1) == terminal

    received = []
    waiter = threading.Thread(target=lambda: received.append(events.get(timeout=1)))
    waiter.start()
    events.publish_terminal(terminal, 2)
    waiter.join(timeout=1)
    assert not waiter.is_alive()
    assert received == [ServiceEvent(
        "state", {"state": "error", "reason": "tcp_loss", "endpoint": None}
    )]
    started = time.monotonic()
    with pytest.raises(queue.Empty):
        events.get(timeout=0.05)
    assert time.monotonic() - started < 0.5


def test_operation_events_have_units_success_and_public_context(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    metrics = []
    for service in (alice, bob):
        while True:
            try:
                event = service.events.get_nowait()
            except queue.Empty:
                break
            if event.kind == "operation_metrics":
                metrics.append(event.data)

    message_id = alice.send_text("metrics context")
    wait_event(bob, "message", message_id)
    alice.wait_for_receipt(message_id, timeout=6)

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        for service in (alice, bob):
            try:
                event = service.events.get_nowait()
            except queue.Empty:
                continue
            if event.kind == "operation_metrics":
                metrics.append(event.data)
        if any(row.get("operation") == "handshake" for row in metrics) and any(
            row.get("operation") == "audit" for row in metrics
        ):
            break
        time.sleep(0.01)

    handshake = [row for row in metrics if row.get("operation") == "handshake"]
    audit = [row for row in metrics if row.get("operation") == "audit"]
    assert handshake and audit
    assert all(type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0 for row in metrics)
    assert all(type(row["success"]) is bool for row in metrics)
    assert any(row["context"].get("approval_included") is True for row in handshake)
    assert any(type(row.get("encoded_bytes")) is int and row["encoded_bytes"] > 0 for row in audit)
    for row in metrics:
        assert not {"private_key", "public_key", "session_id", "traffic_key"}.intersection(row["context"])


def test_stop_listener_cancels_a_bind_in_progress_and_allows_restart(tmp_path, monkeypatch):
    service = PeerService(tmp_path)
    original_socket = socket.socket
    entered_bind = threading.Event()
    release_bind = threading.Event()
    created = []

    class BlockingBindSocket:
        def __init__(self, *args, **kwargs):
            self.inner = original_socket(*args, **kwargs)
            created.append(self)

        def bind(self, address):
            if len(created) == 1:
                entered_bind.set()
                release_bind.wait(2)
            return self.inner.bind(address)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    monkeypatch.setattr(service_module.socket, "socket", BlockingBindSocket)
    result = []

    def start():
        try:
            result.append(service.start_listener("127.0.0.1", 0))
        except SparcError as error:
            result.append(error)

    worker = threading.Thread(target=start)
    worker.start()
    try:
        assert entered_bind.wait(timeout=2)
        service.stop_listener()
        release_bind.set()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert isinstance(result[0], SparcError)
        assert result[0].code == "operation_cancelled"
        assert service.state == "stopped"
        assert service._listener is None

        monkeypatch.setattr(service_module.socket, "socket", original_socket)
        service.start_listener("127.0.0.1", 0)
        assert service.state == "listening"
        service.stop_listener()
    finally:
        release_bind.set()
        service.close()
        worker.join(timeout=2)
