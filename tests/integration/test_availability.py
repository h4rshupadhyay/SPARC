"""Authenticated reconnect behavior stays finite and never replays text."""

import json
import queue
import socket
import threading
import time

import pytest

from sparc.audit import verify_log
from sparc.models import Endpoint, Limits, Role, ServiceEvent, SparcError
import sparc.peer.service as service_module
from sparc.peer.service import PeerService
from conftest import _connected, _pairing_request, wait_event


def _wait_until(predicate, timeout=6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    assert predicate()


def _drain(service):
    while True:
        try:
            service.events.get_nowait()
        except queue.Empty:
            return


def _audit_bodies(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


def _assert_sticky_audit_failure_blocks_networking(service, endpoint, monkeypatch):
    entered_responder_c3 = []
    original_handshake = service_module.perform_handshake

    def observe_handshake(sock, role, *args, **kwargs):
        if role is Role.RESPONDER:
            entered_responder_c3.append(role)
            sock.close()
            raise SparcError("tcp_loss", "probe stopped before handshake")
        return original_handshake(sock, role, *args, **kwargs)

    monkeypatch.setattr(service_module, "perform_handshake", observe_handshake)
    try:
        probe = socket.create_connection(
            (endpoint.ip, endpoint.port), timeout=0.2
        )
    except OSError:
        probe = None
    if probe is not None:
        probe.close()
    time.sleep(0.1)
    _wait_until(lambda: service._slot is None, timeout=2.0)

    assert service._audit_failed
    assert entered_responder_c3 == []
    with pytest.raises(SparcError) as connect_error:
        service.connect(endpoint)
    assert connect_error.value.code == "audit_storage_failed"
    with pytest.raises(SparcError) as listener_error:
        service.start_listener("127.0.0.1", 0)
    assert listener_error.value.code == "audit_storage_failed"


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.05, 0.1, 0.2))], indirect=True
)
def test_reconnect_fresh_keys_and_no_resend(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    old_session = alice._slot.session
    bob_session = bob._slot.session
    old_ids = (old_session._codec.session_id, bob_session._codec.session_id)
    connected_audit_snapshots = []
    bob_roles = []
    original_publish_terminal = alice.events.publish_terminal
    original_bob_start = bob._start_coordinator

    def observe_connected(event, generation):
        if (event.kind == "state" and event.data.get("state") == "connected"
                and event.data.get("reason") == "session_established"):
            connected_audit_snapshots.append(_audit_bodies(alice))
        return original_publish_terminal(event, generation)

    def observe_bob_coordinator(attempt):
        bob_roles.append(attempt.role)
        return original_bob_start(attempt)

    alice.events.publish_terminal = observe_connected
    bob._start_coordinator = observe_bob_coordinator

    # Leave one application request unconfirmed when the established socket
    # disappears. The peer has received it, but its ACK is held locally.
    original_enqueue = bob_session.enqueue
    held_acks = []

    def hold_ack(payload, control=False):
        if control and payload.get("kind") == "ack":
            held_acks.append(payload)
            return
        original_enqueue(payload, control=control)

    bob_session.enqueue = hold_ack
    _drain(alice)
    _drain(bob)
    message_id = alice.send_text("one deliberate submission")
    wait_event(bob, "message", message_id)
    assert held_acks

    bob_session.close()
    _wait_until(lambda: bob._slot is None)
    _wait_until(
        lambda: alice._slot is not None and alice._slot.session is not old_session,
        timeout=4.0,
    )
    _connected(alice, timeout=4.0)
    _connected(bob, timeout=4.0)

    assert alice._slot.session is not old_session
    assert alice._slot.session._codec.session_id != old_ids[0]
    assert bob._slot.session._codec.session_id != old_ids[1]
    assert connected_audit_snapshots
    outcomes_at_publication = [
        row for row in connected_audit_snapshots[-1]
        if row["event"] == "reconnect_outcome"
    ]
    assert outcomes_at_publication[-1]["metadata"] == {
        "endpoint": f"{peer_pair.bob_endpoint.ip}:{peer_pair.bob_endpoint.port}",
        "state": "connected",
        "attempt": 1,
    }
    assert all(role is Role.RESPONDER for role in bob_roles)
    assert verify_log(
        alice.data_dir / "audit.jsonl",
        alice._identity.public_bytes,
        alice._audit.checkpoint_path,
    ).valid
    with pytest.raises(SparcError) as raised:
        alice.wait_for_receipt(message_id, timeout=0.1)
    assert raised.value.code == "delivery_unconfirmed"

    # Drain connection/state diagnostics, then ensure the new session does
    # not deliver the old application payload a second time.
    _drain(bob)
    time.sleep(0.3)
    received = [
        event for event in list(bob.events.queue)
        if event.kind == "message" and event.data.get("message_id") == message_id
    ]
    assert received == []
    send_attempts = [
        row for row in _audit_bodies(alice)
        if row["event"] == "send_attempt" and row["metadata"].get("message_id") == message_id
    ]
    assert len(send_attempts) == 1


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.05, 0.1, 0.2))], indirect=True
)
def test_forgotten_authenticated_key_does_not_prompt_or_repin_on_retry(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    fingerprint = bob.own_fingerprint
    assert any(peer["fingerprint"] == fingerprint for peer in alice.trusted_peers())
    alice._trust.forget(fingerprint)
    _drain(alice)
    established_before = sum(
        row["event"] == "session_established" for row in _audit_bodies(alice)
    )

    bob._slot.session.close()
    _wait_until(lambda: alice._slot is None, timeout=4.0)

    assert alice.state == "error"
    assert not any(peer["fingerprint"] == fingerprint for peer in alice.trusted_peers())
    events = []
    while True:
        try:
            events.append(alice.events.get_nowait())
        except queue.Empty:
            break
    assert not any(
        event.kind == "pairing_required"
        or event.data.get("reason") == "pairing_required"
        or "request_id" in event.data
        for event in events
    )
    assert sum(
        row["event"] == "session_established" for row in _audit_bodies(alice)
    ) == established_before


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.02, 0.04, 0.08))], indirect=True
)
def test_repeated_tcp_handshake_failures_consume_exactly_three_retries(
    peer_pair, monkeypatch
):
    alice, bob = peer_pair.alice, peer_pair.bob
    original_coordinate = bob._coordinate
    retry_accepts = []
    outcomes_seen_at_accept = []

    def reject_reconnect(attempt):
        if attempt.role is Role.RESPONDER:
            retry_accepts.append(attempt)
            outcomes_seen_at_accept.append([
                row for row in _audit_bodies(alice)
                if row["event"] == "reconnect_outcome"
            ])
            if attempt.sock is not None:
                bob._close_socket(attempt.sock)
            bob._finish_attempt(attempt, SparcError("tcp_loss", "test rejects retry handshake"))
            return
        original_coordinate(attempt)

    monkeypatch.setattr(bob, "_coordinate", reject_reconnect)
    bob._slot.session.close()
    _wait_until(lambda: alice._slot is None, timeout=4.0)

    assert len(retry_accepts) == 3
    outcomes = [
        row for row in _audit_bodies(alice)
        if row["event"] == "reconnect_outcome"
    ]
    assert [row["metadata"]["attempt"] for row in outcomes] == [1, 2, 3]
    assert [row["metadata"]["state"] for row in outcomes] == [
        "tcp_loss", "tcp_loss", "tcp_loss"
    ]
    assert [len(rows) for rows in outcomes_seen_at_accept] == [0, 1, 2]
    assert alice.state == "error"
    assert bob._listener is not None


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.5, 1.0))], indirect=True
)
@pytest.mark.parametrize("action", ["disconnect", "stop_listener", "close"])
def test_explicit_stop_wakes_pending_reconnect_delay(peer_pair, action):
    alice, bob = peer_pair.alice, peer_pair.bob
    accepted = []
    original_coordinate = bob._coordinate

    def count_retry(attempt):
        if attempt.role is Role.RESPONDER:
            accepted.append(attempt)
        original_coordinate(attempt)

    bob._coordinate = count_retry
    if action == "stop_listener":
        alice.stop_listener()
        # A fresh explicit connection starts a new intent while leaving Alice
        # without a listener. The later Stop call therefore tests revocation
        # of a chain when no listener exists.
        alice.disconnect()
        _wait_until(lambda: bob._slot is None)
        alice.connect(peer_pair.bob_endpoint)
        _connected(alice)
        _connected(bob)
        accepted.clear()

    bob._slot.session.close()
    _wait_until(
        lambda: alice._slot is not None and alice._slot.session is None,
        timeout=2.0,
    )
    time.sleep(0.05)
    started = time.monotonic()
    if action == "disconnect":
        alice.disconnect()
    elif action == "stop_listener":
        # This call is made while no listener exists; it must still revoke the
        # retry chain and wake its delay.
        alice.stop_listener()
    else:
        alice.close()
    _wait_until(lambda: alice._slot is None, timeout=2.0)
    assert time.monotonic() - started < 1.0
    time.sleep(1.1)
    assert accepted == []


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.05, 0.1, 0.2))], indirect=True
)
def test_closure_audit_failure_prevents_retry_scheduling(peer_pair, monkeypatch):
    alice, bob = peer_pair.alice, peer_pair.bob
    accepted = []
    original_coordinate = bob._coordinate

    def count_retry(attempt):
        if attempt.role is Role.RESPONDER:
            accepted.append(attempt)
        original_coordinate(attempt)

    bob._coordinate = count_retry
    original_append = alice._audit.append

    def fail_closure(kind, metadata):
        if kind == "session_closed":
            raise OSError("injected closure audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(alice._audit, "append", fail_closure)
    bob._slot.session.close()
    _wait_until(lambda: alice._slot is None, timeout=2.0)
    time.sleep(0.1)

    assert alice.state == "error"
    assert alice._audit_failed
    assert accepted == []
    _assert_sticky_audit_failure_blocks_networking(
        alice, peer_pair.alice_endpoint, monkeypatch
    )


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.02, 0.04))], indirect=True
)
def test_retry_outcome_audit_failure_stops_remaining_chain(peer_pair, monkeypatch):
    alice, bob = peer_pair.alice, peer_pair.bob
    accepted = []
    original_coordinate = bob._coordinate

    def reject_retry_handshake(attempt):
        if attempt.role is Role.RESPONDER:
            accepted.append(attempt)
            if attempt.sock is not None:
                bob._close_socket(attempt.sock)
            bob._finish_attempt(attempt, SparcError("tcp_loss", "injected retry failure"))
            return
        original_coordinate(attempt)

    monkeypatch.setattr(bob, "_coordinate", reject_retry_handshake)
    original_append = alice._audit.append

    def fail_retry_outcome(kind, metadata):
        if kind == "reconnect_outcome":
            raise OSError("injected retry outcome audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(alice._audit, "append", fail_retry_outcome)
    established_before = sum(
        row["event"] == "session_established" for row in _audit_bodies(alice)
    )
    bob._slot.session.close()
    _wait_until(lambda: alice._slot is None, timeout=3.0)
    time.sleep(0.25)

    assert len(accepted) == 1
    assert alice._audit_failed
    assert alice.state == "error"
    assert sum(
        row["event"] == "session_established" for row in _audit_bodies(alice)
    ) == established_before
    _assert_sticky_audit_failure_blocks_networking(
        alice, peer_pair.alice_endpoint, monkeypatch
    )


def test_initial_manual_tcp_failure_does_not_start_reconnect_chain(tmp_path):
    service = PeerService(tmp_path / "initial-failure", Limits(reconnect_delays=(0.01, 0.02)))
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    endpoint = Endpoint(*probe.getsockname())
    probe.close()
    try:
        service.connect(endpoint)
        _wait_until(lambda: service._slot is None, timeout=2.0)
        time.sleep(0.1)
        assert service.state == "error"
        assert not any(
            row["event"] == "reconnect_outcome"
            for row in _audit_bodies(service)
        )
    finally:
        service.close()


def test_captured_responder_coordinator_is_cancelled_when_rate_audit_fails(
    tmp_path, monkeypatch
):
    service = PeerService(tmp_path / "captured-coordinator")
    endpoint = service.start_listener("127.0.0.1", 0)
    coordinator_entered = threading.Event()
    release_coordinator = threading.Event()
    c3_entered = []
    captured = []
    original_start = service._start_coordinator
    original_handshake = service_module.perform_handshake
    original_append = service._audit.append
    probe = socket.create_connection((endpoint.ip, endpoint.port), timeout=1)

    def hold_start(attempt):
        if attempt.role is Role.RESPONDER:
            captured.append(attempt)
            coordinator_entered.set()
            release_coordinator.wait(timeout=10)
        return original_start(attempt)

    def observe_c3(sock, role, *args, **kwargs):
        c3_entered.append(role)
        return original_handshake(sock, role, *args, **kwargs)

    def fail_rate_audit(kind, metadata):
        if kind == "rate_limit_rejected":
            raise OSError("injected connection rejection audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(service, "_start_coordinator", hold_start)
    monkeypatch.setattr(service_module, "perform_handshake", observe_c3)
    monkeypatch.setattr(service._audit, "append", fail_rate_audit)
    actor_result = []
    actor = None
    try:
        assert coordinator_entered.wait(timeout=2)
        owner = captured[0]

        # This invokes the real bounded rejection/audit/fail-closed path from
        # another thread while the accept loop owns a captured socket.
        actor = threading.Thread(
            target=lambda: actor_result.append(
                service._record_rate_limit_rejection("connection")
            ),
            daemon=True,
        )
        actor.start()
        assert owner.cancel.wait(timeout=2)
        release_coordinator.set()
        actor.join(timeout=3)
        assert not actor.is_alive()
        _wait_until(lambda: service._slot is None, timeout=2.0)

        assert actor_result == [False]
        assert service._audit_failed
        assert owner.cancel.is_set()
        assert c3_entered == []
        with pytest.raises(SparcError) as connect_error:
            service.connect(endpoint)
        assert connect_error.value.code == "audit_storage_failed"
        with pytest.raises(SparcError) as listener_error:
            service.start_listener("127.0.0.1", 0)
        assert listener_error.value.code == "audit_storage_failed"
    finally:
        release_coordinator.set()
        probe.close()
        if actor is not None:
            actor.join(timeout=3)
        service.close()


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.05,))], indirect=True
)
def test_audit_failure_survives_cancel_after_failure_diagnostic(
    peer_pair, monkeypatch
):
    alice, bob = peer_pair.alice, peer_pair.bob
    retry_worker_entered = threading.Event()
    release_retry = threading.Event()
    outcome_append_entered = threading.Event()
    failure_diagnostic_waiting = threading.Event()
    finish_entered = threading.Event()
    release_finish = threading.Event()
    original_coordinate = alice._coordinate
    original_finish_attempt = alice._finish_attempt
    original_event_put = alice.events.put
    original_append = alice._audit.append

    def gate_retry(attempt):
        if attempt.retry_chain is not None:
            retry_worker_entered.set()
            while not release_retry.is_set() and not attempt.cancel.wait(0.1):
                pass
        return original_coordinate(attempt)

    observed_audit_latch = []

    def observe_failure_diagnostic(event, block=True, timeout=None):
        data = event.data if isinstance(event, ServiceEvent) else {}
        context = data.get("context", {})
        if (isinstance(event, ServiceEvent) and event.kind == "operation_metrics"
                and data.get("operation") == "audit"
                and data.get("success") is False
                and context.get("event") == "reconnect_outcome"):
            with alice._state_lock:
                observed_audit_latch.append(alice._audit_failed)
            failure_diagnostic_waiting.set()
        if timeout is None:
            return original_event_put(event, block=block)
        return original_event_put(event, block=block, timeout=timeout)

    def hold_failed_attempt(attempt, error):
        if error.code == "audit_storage_failed":
            finish_entered.set()
            release_finish.wait(timeout=3)
        return original_finish_attempt(attempt, error)

    def fail_reconnect_outcome(kind, metadata):
        if kind == "reconnect_outcome":
            outcome_append_entered.set()
            raise OSError("injected retry outcome audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(alice, "_coordinate", gate_retry)
    monkeypatch.setattr(alice, "_finish_attempt", hold_failed_attempt)
    monkeypatch.setattr(alice.events, "put", observe_failure_diagnostic)
    monkeypatch.setattr(alice._audit, "append", fail_reconnect_outcome)
    _drain(alice)
    old_session = alice._slot.session
    bob._slot.session.close()
    assert retry_worker_entered.wait(timeout=2)
    assert old_session.join(timeout=2)
    _drain(alice)

    for index in range(alice.events.maxsize):
        alice.events.put_nowait(ServiceEvent("held", {"index": index}))
    release_retry.set()
    assert outcome_append_entered.wait(timeout=3)
    assert failure_diagnostic_waiting.wait(timeout=2)
    assert observed_audit_latch == [True]
    assert finish_entered.wait(timeout=2)

    closer = threading.Thread(target=alice.disconnect)
    closer.start()
    attempt = alice._slot
    assert attempt is not None and attempt.cancel.wait(timeout=1)
    release_finish.set()
    closer.join(timeout=2)
    assert not closer.is_alive()
    _wait_until(lambda: alice._slot is None, timeout=2.0)

    assert alice._audit_failed
    pending = alice.events._pending_terminal
    assert pending is not None
    assert pending[0].data["state"] == "error"
    assert pending[0].data["reason"] == "audit_storage_failed"
    held = [alice.events.get_nowait().data["index"] for _ in range(alice.events.maxsize)]
    assert held == list(range(alice.events.maxsize))
    with pytest.raises(SparcError) as raised:
        alice.connect(peer_pair.bob_endpoint)
    assert raised.value.code == "audit_storage_failed"
    with pytest.raises(SparcError) as listener_error:
        alice.start_listener("127.0.0.1", 0)
    assert listener_error.value.code == "audit_storage_failed"


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.02, 0.04))], indirect=True
)
def test_audit_failure_preserves_assigned_retry_session_owner(peer_pair, monkeypatch):
    alice, bob = peer_pair.alice, peer_pair.bob
    session_start_entered = threading.Event()
    release_session_start = threading.Event()
    original_make_session = alice._make_session
    original_append = alice._audit.append
    original_emit_state = alice._emit_state
    connected_publications = []

    def gate_retry_session_start(attempt, sock, established):
        session = original_make_session(attempt, sock, established)
        if attempt.retry_chain is not None:
            original_start = session.start

            def held_start():
                session_start_entered.set()
                release_session_start.wait(timeout=10)
                return original_start()

            session.start = held_start
        return session

    def observe_state(state, reason, endpoint, cancel=None):
        if state == "connected" and reason == "session_established":
            connected_publications.append(endpoint)
        return original_emit_state(state, reason, endpoint, cancel)

    def fail_rate_audit(kind, metadata):
        if kind == "rate_limit_rejected":
            raise OSError("injected audit failure during retry adoption")
        return original_append(kind, metadata)

    monkeypatch.setattr(alice, "_make_session", gate_retry_session_start)
    monkeypatch.setattr(alice, "_emit_state", observe_state)
    monkeypatch.setattr(alice._audit, "append", fail_rate_audit)
    bob._slot.session.close()

    actor_result = []
    actor = None
    try:
        assert session_start_entered.wait(timeout=4)
        attempt = alice._slot
        assert attempt is not None
        session = attempt.session
        assert session is not None
        assert attempt.retry_chain is not None

        actor = threading.Thread(
            target=lambda: actor_result.append(
                alice._record_rate_limit_rejection("connection")
            ),
            daemon=True,
        )
        actor.start()
        _wait_until(lambda: alice._audit_failed, timeout=2.0)

        # The assigned session owns the shared cancellation event. The audit
        # helper must only revoke its chain and close captured transport; the
        # session's own terminal callback wins cancellation and slot cleanup.
        assert alice._slot is attempt
        assert attempt.retry_chain is not None
        assert not attempt.cancel.is_set()
        release_session_start.set()
        actor.join(timeout=3)
        assert not actor.is_alive()
        _wait_until(lambda: alice._slot is None, timeout=3.0)

        assert actor_result == [False]
        assert alice.state == "error"
        assert not connected_publications
        assert alice._audit_failed
    finally:
        release_session_start.set()
        if actor is not None:
            actor.join(timeout=3)


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(event_queue=64, reconnect_delays=(0.02, 0.04, 0.08))],
    indirect=True,
)
def test_full_event_queue_keeps_retry_handoff_and_finite_budget_moving(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    old_session = alice._slot.session
    retry_started = []
    retry_starts = threading.Event()
    accepted = []
    original_start = alice._start_coordinator
    original_coordinate = bob._coordinate

    def observe_start(attempt):
        if attempt.retry_chain is not None:
            retry_started.append(attempt.generation)
            retry_starts.set()
        return original_start(attempt)

    def reject_retry(attempt):
        if attempt.role is Role.RESPONDER:
            accepted.append(attempt)
            if attempt.sock is not None:
                bob._close_socket(attempt.sock)
            bob._finish_attempt(attempt, SparcError("tcp_loss", "queue-full retry rejection"))
            return
        original_coordinate(attempt)

    alice._start_coordinator = observe_start
    bob._coordinate = reject_retry
    _drain(alice)
    for index in range(alice.events.maxsize):
        alice.events.put_nowait(ServiceEvent("held", {"index": index}))

    bob._slot.session.close()
    assert retry_starts.wait(timeout=2)
    _wait_until(lambda: alice._slot is None, timeout=3.0)
    assert old_session.join(timeout=0.5)
    assert len(retry_started) == 3
    assert len(accepted) == 3
    assert any(
        row["event"] == "session_closed"
        and row["metadata"]["code"] == "tcp_loss"
        for row in _audit_bodies(alice)
    )
    outcomes = [
        row for row in _audit_bodies(alice)
        if row["event"] == "reconnect_outcome"
    ]
    assert [row["metadata"]["attempt"] for row in outcomes] == [1, 2, 3]

    assert alice.events.qsize() == alice.events.maxsize
    held = [alice.events.get_nowait() for _ in range(alice.events.maxsize)]
    assert [event.data["index"] for event in held] == list(range(alice.events.maxsize))
    terminal = alice.events.get_nowait()
    assert terminal.kind == "state"
    assert terminal.data["state"] == "error"
    pending = alice.events._pending_terminal
    assert pending is None


@pytest.mark.parametrize(
    "peer_pair", [Limits(event_queue=64, reconnect_delays=(5.0,))], indirect=True
)
def test_stop_cancels_retry_with_full_queue_and_preserves_latest_terminal(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    old_session = alice._slot.session
    retry_started = threading.Event()
    accepted = []
    original_start = alice._start_coordinator
    original_coordinate = bob._coordinate

    def observe_start(attempt):
        if attempt.retry_chain is not None:
            retry_started.set()
        return original_start(attempt)

    def count_accept(attempt):
        if attempt.role is Role.RESPONDER:
            accepted.append(attempt)
        return original_coordinate(attempt)

    alice._start_coordinator = observe_start
    bob._coordinate = count_accept
    _drain(alice)
    for index in range(alice.events.maxsize):
        alice.events.put_nowait(ServiceEvent("held", {"index": index}))

    bob._slot.session.close()
    assert retry_started.wait(timeout=2)
    stopper = threading.Thread(target=alice.stop_listener, daemon=True)
    stopper.start()
    stopper.join(timeout=1.5)
    assert not stopper.is_alive()
    _wait_until(lambda: alice._slot is None, timeout=2.0)
    assert old_session.join(timeout=0.5)
    assert accepted == []
    assert alice.events.qsize() == alice.events.maxsize
    pending = alice.events._pending_terminal
    assert pending is not None
    latest_generation = pending[1]
    assert latest_generation == alice._generation
    assert pending[0].data["state"] == "stopped"
    assert pending[0].data["reason"] == "operation_cancelled"

    time.sleep(0.1)
    assert alice._slot is None
    assert alice.events._pending_terminal == pending
    held = [alice.events.get_nowait() for _ in range(alice.events.maxsize)]
    assert [event.data["index"] for event in held] == list(range(alice.events.maxsize))
    terminal = alice.events.get_nowait()
    assert terminal.data["state"] == "stopped"
    assert alice.events._pending_terminal is None


@pytest.mark.parametrize(
    "peer_pair", [Limits(reconnect_delays=(0.3, 0.3, 0.3))], indirect=True
)
@pytest.mark.parametrize("forget_old_pin", [False, True])
def test_changed_but_separately_trusted_key_is_never_adopted(
    peer_pair, tmp_path, forget_old_pin
):
    alice, bob = peer_pair.alice, peer_pair.bob
    rogue = PeerService(tmp_path / "rogue", Limits(reconnect_delays=(0.05, 0.1, 0.2)))
    rogue_endpoint = rogue.start_listener("127.0.0.1", 0)
    old_bob_endpoint = peer_pair.bob_endpoint
    try:
        # Pin the rogue identity at a different endpoint first.
        alice.disconnect()
        _wait_until(lambda: bob._slot is None)
        alice.connect(rogue_endpoint)
        request = _pairing_request(alice)
        alice.respond_to_pairing(request.data["request_id"], True)
        rogue_request = _pairing_request(rogue)
        rogue.respond_to_pairing(rogue_request.data["request_id"], True)
        _connected(alice)
        _connected(rogue)
        rogue_fingerprint = rogue.own_fingerprint
        assert any(
            peer["fingerprint"] == rogue_fingerprint
            for peer in alice.trusted_peers()
        )

        # Re-establish the old authenticated target, then move the separately
        # trusted rogue key onto that endpoint before the automatic retry.
        alice.disconnect()
        _wait_until(lambda: rogue._slot is None)
        alice.connect(old_bob_endpoint)
        _connected(alice)
        _connected(bob)
        established_before = sum(
            row["event"] == "session_established" for row in _audit_bodies(alice)
        )
        _drain(alice)
        bob.stop_listener()
        rogue.stop_listener()
        rogue.start_listener(old_bob_endpoint.ip, old_bob_endpoint.port)
        bob._slot.session.close()
        _wait_until(lambda: bob._slot is None)
        _wait_until(
            lambda: alice._slot is not None and alice._slot.session is None,
            timeout=2.0,
        )
        if forget_old_pin:
            alice._trust.forget(bob.own_fingerprint)

        _wait_until(lambda: alice._slot is None, timeout=4.0)
        assert alice.state == "error"
        assert not any(
            event.data.get("reason") == "pairing_required"
            or "request_id" in event.data
            for event in list(alice.events.queue)
        )
        assert sum(
            row["event"] == "session_established" for row in _audit_bodies(alice)
        ) == established_before
        peers = alice.trusted_peers()
        assert any(peer["fingerprint"] == rogue_fingerprint for peer in peers)
        assert any(peer["fingerprint"] == bob.own_fingerprint for peer in peers) is (
            not forget_old_pin
        )
    finally:
        alice.close()
        bob.close()
        rogue.close()
