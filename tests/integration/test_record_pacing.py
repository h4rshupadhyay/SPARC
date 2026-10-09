"""C6 sender pacing and bounded rejection over authenticated peers."""

import json
import socket
import threading
import time
from datetime import datetime

import pytest

from sparc.audit import verify_log
from sparc.models import Limits, SparcError
from sparc.peer.policy import RecordBucket
from sparc.peer.service import PeerService

from conftest import wait_event


def _audit_bodies(service):
    path = service.data_dir / "audit.jsonl"
    return [json.loads(line)["body"] for line in path.read_text("utf-8").splitlines()]


def _wait_for_state(service, state, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == state:
            return
        time.sleep(0.005)
    assert service.state == state


def _wait_for_rate_limit_audit(service, expected_count, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = [row for row in _audit_bodies(service)
                if row["event"] == "rate_limit_rejected"]
        if sum(row["metadata"].get("count", 0) for row in rows) >= expected_count:
            return rows
        time.sleep(0.01)
    assert sum(row["metadata"].get("count", 0) for row in rows) >= expected_count
    return rows


def test_sender_paces_data_and_control_records(peer_pair):
    sender, receiver = peer_pair.alice, peer_pair.bob
    sent_at = {sender: [], receiver: []}

    for service in (sender, receiver):
        session = service._slot.session
        # Isolate sender pacing: leave the production receive bucket generous
        # so socket delivery jitter cannot turn valid output into a microburst.
        session._outbound_bucket = RecordBucket(
            time.monotonic, limits=Limits(record_rate=100.0, record_burst=1)
        )
        hook = session._hooks.on_written

        def observe(payload, protected, *, service=service, hook=hook):
            if hook is not None:
                hook(payload, protected)
            sent_at[service].append((payload.get("kind"), time.monotonic()))

        # Observe the production writer's completed protection step, immediately
        # before its sole sendall call.
        object.__setattr__(service._slot.session._hooks, "on_written", observe)

    ids = [sender.send_text(f"paced {index}") for index in range(3)]
    for message_id in ids:
        wait_event(receiver, "message", message_id)
        sender.wait_for_receipt(message_id, timeout=5)

    for service, expected_kind in ((sender, "chat"), (receiver, "ack")):
        times = [stamp for kind, stamp in sent_at[service] if kind == expected_kind]
        assert len(times) == 3
        assert times[-1] - times[0] >= 0.015


@pytest.mark.parametrize(
    "peer_pair",
    [Limits(record_rate=0.01, record_burst=2)],
    indirect=True,
)
def test_authenticated_peer_exceeding_receive_burst_is_rejected(peer_pair, monkeypatch):
    sender, receiver = peer_pair.alice, peer_pair.bob
    sender_session = sender._slot.session
    captured = []
    monkeypatch.setattr(
        sender_session,
        "enqueue",
        lambda payload, control=False: captured.append(payload),
    )

    message_ids = [sender.send_text(f"flood {index}") for index in range(3)]
    assert len(captured) == 3

    # This test peer creates valid encrypted records but deliberately bypasses
    # its own normal writer pacing to exercise the authenticated receive cap.
    frames = [sender_session._codec.protect(payload).frame for payload in captured]
    for frame in frames:
        sender_session._sock.sendall(frame)

    _wait_for_state(receiver, "error")
    received = [row for row in _audit_bodies(receiver)
                if row["event"] == "verified_receipt"]
    assert len(received) == 2
    with pytest.raises(SparcError):
        sender.wait_for_receipt(message_ids[-1], timeout=0.1)

    rows = _wait_for_rate_limit_audit(receiver, 1)
    assert rows
    metadata = rows[-1]["metadata"]
    assert {"code", "reason", "count"} <= metadata.keys()
    assert metadata["count"] >= 1
    assert verify_log(
        receiver.data_dir / "audit.jsonl",
        receiver._identity.public_bytes,
        receiver._audit.checkpoint_path,
    ).valid


def test_rejection_audit_failure_stops_listener_and_active_session(
    peer_pair, monkeypatch
):
    service = peer_pair.alice
    session = service._slot.session
    queued = []
    original_enqueue = session.enqueue
    monkeypatch.setattr(
        session, "enqueue", lambda payload, control=False: queued.append(payload)
    )
    message_id = service.send_text("pending while rejection audit fails")
    assert queued

    original_append = service._audit.append

    def fail_rate_limit_append(kind, metadata):
        if kind == "rate_limit_rejected":
            raise SparcError("audit_storage_failed", "injected rate-limit audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(service._audit, "append", fail_rate_limit_append)
    assert service._record_rate_limit_rejection("connection") is False

    assert service._listener is None
    assert session._cancel.wait(timeout=1)
    with pytest.raises(SparcError):
        service.wait_for_receipt(message_id, timeout=1)
    monkeypatch.setattr(session, "enqueue", original_enqueue)
    with pytest.raises(SparcError) as raised:
        session.enqueue({"kind": "chat"})
    assert raised.value.code == "operation_cancelled"


def test_connection_limit_precedes_handshake_and_rejection_audit_is_bounded(
    tmp_path, monkeypatch, credential_provider
):
    service = PeerService(
        tmp_path / "listener",
        Limits(connections_per_source=2, connections_global=10),
        credential_provider=credential_provider,
    )
    handshake_entered = threading.Event()
    handshake_calls = []
    clients = []

    def hold_handshake(*args, **kwargs):
        handshake_calls.append(args)
        handshake_entered.set()
        cancel = args[5]
        cancel.wait()
        raise SparcError("operation_cancelled", "test handshake released")

    monkeypatch.setattr("sparc.peer.service.perform_handshake", hold_handshake)
    endpoint = service.start_listener("127.0.0.1", 0)
    started = time.monotonic()
    try:
        first = socket.create_connection((endpoint.ip, endpoint.port), timeout=1)
        clients.append(first)
        assert handshake_entered.wait(timeout=1)

        # The first of these is accepted under the quota but refused as busy;
        # it must still consume a source attempt. The next two exceed the quota
        # while the original socket remains inside the held handshake.
        for _ in range(3):
            client = socket.create_connection((endpoint.ip, endpoint.port), timeout=1)
            clients.append(client)
            client.settimeout(0.5)
            assert client.recv(1) == b""

        rows = _wait_for_rate_limit_audit(service, 2, timeout=6.5)
        assert time.monotonic() - started <= 6.5
        assert sum(row["metadata"]["count"] for row in rows) == 2
        assert all({"code", "reason", "count"} <= row["metadata"].keys()
                   for row in rows)
        audit_times = [datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                       for row in rows]
        assert all((later - earlier).total_seconds() >= 5.0
                   for earlier, later in zip(audit_times, audit_times[1:]))
        assert verify_log(
            service.data_dir / "audit.jsonl",
            service._identity.public_bytes,
            service._audit.checkpoint_path,
        ).valid

        # The rejected sockets never reached expensive handshake work.
        assert handshake_entered.is_set()
        assert len(handshake_calls) == 1
        assert service._slot is not None
        assert service._slot.role.value == "responder"
    finally:
        service.close()
        for client in clients:
            client.close()
