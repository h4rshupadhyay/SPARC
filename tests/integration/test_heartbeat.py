"""C6c liveness behavior over authenticated peer sessions."""

import json
import queue
import threading
import time

import pytest

from sparc.models import Limits, ServiceEvent, SparcError
from sparc.peer.policy import RecordBucket


def _wait_state(service, expected, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == expected:
            return
        time.sleep(0.005)
    assert service.state == expected


def _drain_events(service):
    while True:
        try:
            service.events.get_nowait()
        except queue.Empty:
            return


def _audit_bodies(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


class _BlockedWriterBucket:
    def __init__(self):
        self.waiting = threading.Event()

    def wait(self, cancel, *, maintenance=None):
        self.waiting.set()
        cancel.wait()
        return False


class _GateBucket:
    def __init__(self, delegate):
        self.delegate = delegate
        self.waiting = threading.Event()
        self.release = threading.Event()

    def wait(self, cancel, *, maintenance=None):
        self.waiting.set()
        while not self.release.wait(0.01):
            if cancel.is_set():
                return False
        if cancel.is_set():
            return False
        return self.delegate.wait(cancel, maintenance=maintenance)


def _silence_outgoing(service):
    blocker = _BlockedWriterBucket()
    service._slot.session._outbound_bucket = blocker
    return blocker


def _collect_inactivity_metric(service, timeout=2.0):
    deadline = time.monotonic() + timeout
    matching = []
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if (event.kind == "operation_metrics"
                and event.data.get("operation") == "peer_inactivity_detection"):
            matching.append(event.data)
        if service.state == "error" and matching:
            break
    return matching


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(heartbeat_seconds=0.05, peer_timeout_seconds=0.25,
            cancel_poll_seconds=0.01)],
    indirect=True,
)
def test_idle_healthy_session_survives_and_ping_pong_are_not_acknowledged(peer_pair):
    sent = {peer_pair.alice: [], peer_pair.bob: []}
    for service in (peer_pair.alice, peer_pair.bob):
        hooks = service._slot.session._hooks
        original = hooks.on_written

        def observe(payload, protected, *, service=service, original=original):
            if original is not None:
                original(payload, protected)
            sent[service].append(payload.get("kind"))

        object.__setattr__(hooks, "on_written", observe)

    _drain_events(peer_pair.alice)
    _drain_events(peer_pair.bob)
    time.sleep(0.6)

    for service in (peer_pair.alice, peer_pair.bob):
        assert service.state == "connected"
        assert "ping" in sent[service]
        assert "pong" in sent[service]
        assert "ack" not in sent[service]
        assert not any(row["event"] in {"verified_receipt", "verified_delivery"}
                       for row in _audit_bodies(service))


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(heartbeat_seconds=0.05, peer_timeout_seconds=0.25,
            cancel_poll_seconds=0.01, reconnect_delays=())],
    indirect=True,
)
def test_inactivity_closes_once_with_last_activity_duration(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    alice_session = alice._slot.session
    _drain_events(alice)
    _drain_events(bob)
    blocker = _silence_outgoing(bob)

    assert blocker.waiting.wait(timeout=1)
    _wait_state(alice, "error", timeout=2)
    metrics = _collect_inactivity_metric(alice, timeout=1)
    assert len(metrics) == 1
    metric = metrics[0]
    assert set(metric) == {"operation", "elapsed_ns", "success", "context"}
    assert metric["operation"] == "peer_inactivity_detection"
    assert metric["success"] is False
    assert metric["context"] == {"reason": "peer_inactivity"}
    assert type(metric["elapsed_ns"]) is int
    assert 250_000_000 <= metric["elapsed_ns"] <= 1_000_000_000
    assert metric["elapsed_ns"] == alice_session._liveness.loss_elapsed_ns

    closed = [row for row in _audit_bodies(alice)
              if row["event"] == "session_closed"]
    assert closed[-1]["metadata"]["code"] == "peer_inactivity"
    assert sum(row["metadata"]["code"] == "peer_inactivity" for row in closed) == 1


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(event_queue=64, heartbeat_seconds=0.05, peer_timeout_seconds=0.25,
            cancel_poll_seconds=0.01, reconnect_delays=())],
    indirect=True,
)
def test_inactivity_cleanup_is_finite_when_ordinary_event_queue_is_full(peer_pair):
    alice, bob = peer_pair.alice, peer_pair.bob
    _drain_events(alice)
    for index in range(alice.events.maxsize):
        alice.events.put_nowait(ServiceEvent("held", {"index": index}))
    blocker = _silence_outgoing(bob)

    assert blocker.waiting.wait(timeout=1)
    _wait_state(alice, "error", timeout=2)
    assert alice.events.qsize() == alice.events.maxsize
    assert all(event.kind == "held" for event in alice.events.queue)
    terminal = alice.events._pending_terminal
    assert terminal is not None
    assert terminal[0].kind == "state"
    closed = [row for row in _audit_bodies(alice)
              if row["event"] == "session_closed"]
    assert closed[-1]["metadata"]["code"] == "peer_inactivity"


def test_stale_session_diagnostic_cannot_publish_for_replacement(peer_pair):
    alice = peer_pair.alice
    old_session = alice._slot.session
    stale_emit = old_session._hooks.emit

    alice.disconnect()
    _wait_state(alice, "listening")
    deadline = time.monotonic() + 2.0
    while peer_pair.bob._slot is not None and time.monotonic() < deadline:
        time.sleep(0.005)
    assert peer_pair.bob._slot is None
    alice.connect(peer_pair.bob_endpoint)
    _wait_state(alice, "connected")
    assert alice._slot.session is not old_session
    _drain_events(alice)

    stale_emit(ServiceEvent("operation_metrics", {
        "operation": "peer_inactivity_detection",
        "elapsed_ns": 250_000_000,
        "success": False,
        "context": {"reason": "peer_inactivity"},
    }))

    assert alice.events.qsize() == 0
    with pytest.raises(queue.Empty):
        alice.events.get_nowait()


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(heartbeat_seconds=0.05, peer_timeout_seconds=0.25,
            cancel_poll_seconds=0.01, control_queue=1, reconnect_delays=())],
    indirect=True,
)
def test_slow_paced_writer_runs_loss_maintenance_with_full_control_queue(
    peer_pair, monkeypatch
):
    alice, bob = peer_pair.alice, peer_pair.bob
    session = alice._slot.session
    _drain_events(alice)
    blocker = _silence_outgoing(bob)
    slow_bucket = RecordBucket(
        time.monotonic, limits=Limits(record_rate=0.01, record_burst=1)
    )
    assert slow_bucket.allow()
    gate = _GateBucket(slow_bucket)
    session._outbound_bucket = gate

    poll_calls = []
    original_poll = session._hooks.on_poll

    def observe_poll():
        poll_calls.append(time.monotonic())
        if original_poll is not None:
            original_poll()

    object.__setattr__(session._hooks, "on_poll", observe_poll)

    session.enqueue({"kind": "held-control"}, control=True)
    assert gate.waiting.wait(timeout=1)
    session.enqueue({"kind": "queued-control"}, control=True)
    message_id = alice.send_text("queued while the first frame is paced")
    assert len(session._control) == 1
    assert len(session._outbound) == 1

    original_enqueue = session.enqueue
    ping_enqueue_attempts = []

    def observe_enqueue(payload, control=False):
        if payload.get("kind") == "ping":
            ping_enqueue_attempts.append(payload)
        return original_enqueue(payload, control=control)

    monkeypatch.setattr(session, "enqueue", observe_enqueue)
    started = time.monotonic()
    gate.release.set()
    _wait_state(alice, "error", timeout=1.8)

    assert time.monotonic() - started < 2.0
    assert len(poll_calls) >= 2
    assert not ping_enqueue_attempts
    assert blocker.waiting.is_set()
    with pytest.raises(SparcError):
        alice.wait_for_receipt(message_id, timeout=0.1)
