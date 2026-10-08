"""C5d service pairing, trust commit, and session adoption boundaries."""

import hashlib
import json
import queue
import threading
import time

import pytest

from sparc.identity import TrustStore
from sparc.models import Endpoint, SparcError
from sparc.peer.service import PeerService


def _wait_pairing(service, timeout=6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        data = event.data
        if isinstance(data, dict) and "request_id" in data:
            return event
    raise AssertionError("service did not publish a pairing request before the deadline")


def _assert_pairing_snapshot(event, candidate_fingerprint, own_fingerprint):
    assert event.data["candidate_fingerprint"] == candidate_fingerprint
    assert event.data["own_fingerprint"] == own_fingerprint
    assert not {"public_key", "private_key", "session_id"}.intersection(event.data)
    assert len(event.data["request_id"]) == 32
    int(event.data["request_id"], 16)


def _wait_state(service, state, timeout=6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == state:
            return
        time.sleep(0.005)
    assert service.state == state, f"service stayed in {service.state!r}, expected {state!r}"


def _assert_no_pairing_request(service, timeout=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        assert "request_id" not in event.data


def _connect_when_idle(service, endpoint, timeout=2.0):
    deadline = time.monotonic() + timeout
    while True:
        try:
            service.connect(endpoint)
            return
        except SparcError as error:
            if error.code != "busy" or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _start_responder(tmp_path, name="responder"):
    service = PeerService(tmp_path / name)
    endpoint = service.start_listener("127.0.0.1", 0)
    return service, endpoint


def _audit_events(service):
    records = [
        json.loads(line)
        for line in (service.data_dir / "audit.jsonl").read_text("utf-8").splitlines()
    ]
    return [record["body"]["event"] for record in records]


def test_both_unknown_peers_approve_exact_fingerprints_and_commit_before_adoption(
    tmp_path, monkeypatch
):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    try:
        pin_calls = []
        original_pin = initiator._trust.pin

        def inspect_durable_outcomes(public_key, peer_endpoint, label=""):
            event_names = _audit_events(initiator)
            assert "pairing_outcome" in event_names
            assert "session_established" in event_names
            assert event_names.index("pairing_outcome") < event_names.index("session_established")
            pin_calls.append((public_key, peer_endpoint))
            return original_pin(public_key, peer_endpoint, label)

        monkeypatch.setattr(initiator._trust, "pin", inspect_durable_outcomes)
        initiator.connect(endpoint)

        initiator_request = _wait_pairing(initiator)
        _assert_pairing_snapshot(
            initiator_request, responder.own_fingerprint, initiator.own_fingerprint
        )
        # Public event containers can be changed by a consumer without changing the
        # immutable candidate retained by the coordinator.
        initiator_request.data["candidate_fingerprint"] = "0" * 64
        initiator.respond_to_pairing(initiator_request.data["request_id"], True)

        responder_request = _wait_pairing(responder)
        _assert_pairing_snapshot(
            responder_request, initiator.own_fingerprint, responder.own_fingerprint
        )
        responder.respond_to_pairing(responder_request.data["request_id"], True)

        _wait_state(initiator, "connected")
        _wait_state(responder, "connected")
        assert len(pin_calls) == 1
        assert pin_calls[0][0] == responder._identity.public_bytes
        assert initiator.trusted_peers()[0]["fingerprint"] == responder.own_fingerprint
        assert responder.trusted_peers()[0]["fingerprint"] == initiator.own_fingerprint
        initiator_rows = [
            json.loads(line)
            for line in (initiator.data_dir / "audit.jsonl").read_text("utf-8").splitlines()
        ]
        trust_rows = [row for row in initiator_rows if row["body"]["event"] == "trust_changed"]
        assert len(trust_rows) == 1
        trust_row = trust_rows[0]
        assert trust_row["body"]["metadata"] == {
            "fingerprint": responder.own_fingerprint,
            "endpoint": f"{endpoint.ip}:{endpoint.port}",
            "state": "pinned",
        }
        assert trust_row["signature"]
        events = [row["body"]["event"] for row in initiator_rows]
        assert events.index("session_established") < events.index("trust_changed")
    finally:
        initiator.close()
        responder.close()


def test_stale_pairing_response_cannot_approve_new_session(tmp_path):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    try:
        initiator.connect(endpoint)
        request_a = _wait_pairing(initiator)
        initiator.respond_to_pairing(request_a.data["request_id"], False)
        _wait_state(initiator, "error")
        assert initiator.trusted_peers() == []

        _connect_when_idle(initiator, endpoint)
        request_b = _wait_pairing(initiator)
        assert request_a.data["request_id"] != request_b.data["request_id"]

        try:
            initiator.respond_to_pairing(request_a.data["request_id"], True)
        except SparcError:
            pass  # Rejecting a stale request is also a valid no-op.
        initiator.respond_to_pairing(request_b.data["request_id"], True)

        responder_request = _wait_pairing(responder)
        responder.respond_to_pairing(responder_request.data["request_id"], True)
        _wait_state(initiator, "connected")
        _wait_state(responder, "connected")
        assert initiator.trusted_peers()[0]["fingerprint"] == responder.own_fingerprint
    finally:
        initiator.close()
        responder.close()


def test_failed_handshake_or_audit_never_connects_or_pins(tmp_path, monkeypatch):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    try:
        def fail_audit(_kind, _metadata):
            raise SparcError("audit_storage_failed", "injected durable audit failure")

        monkeypatch.setattr(initiator._audit, "append", fail_audit)
        initiator.connect(endpoint)
        initiator_request = _wait_pairing(initiator)
        initiator.respond_to_pairing(initiator_request.data["request_id"], True)
        responder_request = _wait_pairing(responder)
        responder.respond_to_pairing(responder_request.data["request_id"], True)

        _wait_state(initiator, "error")
        assert initiator.state != "connected"
        assert initiator.trusted_peers() == []
        assert "session_established" not in _audit_events(initiator)
    finally:
        initiator.close()
        responder.close()


def test_failed_trust_pin_never_connects(tmp_path, monkeypatch):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    try:
        def fail_pin(_public_key, _endpoint, label=""):
            raise SparcError("trust_write_failed", "injected trust persistence failure")

        monkeypatch.setattr(initiator._trust, "pin", fail_pin)
        initiator.connect(endpoint)
        initiator_request = _wait_pairing(initiator)
        initiator.respond_to_pairing(initiator_request.data["request_id"], True)
        responder_request = _wait_pairing(responder)
        responder.respond_to_pairing(responder_request.data["request_id"], True)

        _wait_state(initiator, "error")
        assert initiator.state != "connected"
        assert initiator.trusted_peers() == []
    finally:
        initiator.close()
        responder.close()


def test_post_pin_trust_audit_failure_keeps_pin_without_adoption(tmp_path, monkeypatch):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    original_append = initiator._audit.append
    original_pin = initiator._trust.pin
    pin_completed = threading.Event()

    def observe_pin(public_key, peer_endpoint, label=""):
        result = original_pin(public_key, peer_endpoint, label)
        pin_completed.set()
        return result

    def fail_trust_event(kind, metadata):
        if kind == "trust_changed":
            raise SparcError("audit_storage_failed", "injected post-pin audit failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(initiator._trust, "pin", observe_pin)
    monkeypatch.setattr(initiator._audit, "append", fail_trust_event)
    try:
        initiator.connect(endpoint)
        request = _wait_pairing(initiator)
        initiator.respond_to_pairing(request.data["request_id"], True)
        remote_request = _wait_pairing(responder)
        responder.respond_to_pairing(remote_request.data["request_id"], True)
        _wait_state(initiator, "error")
        assert pin_completed.is_set()
        assert initiator.trusted_peers()[0]["fingerprint"] == responder.own_fingerprint
        assert initiator._slot is None or initiator._slot.session is None
        assert initiator.state == "error"
        assert not any(
            event.kind == "state" and event.data.get("state") == "connected"
            for event in list(initiator.events.queue)
        )
    finally:
        initiator.close()
        responder.close()


def test_known_peer_skips_prompt_and_changed_peer_blocks_before_prompt(tmp_path):
    responder, endpoint = _start_responder(tmp_path, "responder-known")
    initiator_dir = tmp_path / "initiator-known"
    TrustStore(initiator_dir).pin(responder._identity.public_bytes, endpoint, label="remembered")
    initiator = PeerService(initiator_dir)
    try:
        initiator.connect(endpoint)
        responder_request = _wait_pairing(responder)
        _assert_pairing_snapshot(
            responder_request, initiator.own_fingerprint, responder.own_fingerprint
        )
        responder.respond_to_pairing(responder_request.data["request_id"], True)
        _wait_state(initiator, "connected")
        _wait_state(responder, "connected")
        _assert_no_pairing_request(initiator)
    finally:
        initiator.close()
        responder.close()

    changed_responder, changed_endpoint = _start_responder(tmp_path, "responder-changed")
    changed_dir = tmp_path / "initiator-changed"
    remembered_key = b"R" * 32
    TrustStore(changed_dir).pin(remembered_key, changed_endpoint)
    changed = PeerService(changed_dir)
    try:
        changed.connect(changed_endpoint)
        _wait_state(changed, "error")
        _assert_no_pairing_request(changed)
        assert changed.state != "connected"
        assert [entry["fingerprint"] for entry in changed.trusted_peers()] == [
            hashlib.sha256(remembered_key).hexdigest()
        ]
    finally:
        changed.close()
        changed_responder.close()


def test_canceled_pairing_prompt_never_begins_trust_commit(tmp_path):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    try:
        initiator.connect(endpoint)
        request = _wait_pairing(initiator)
        initiator.close()
        assert initiator.state != "connected"
        assert initiator.trusted_peers() == []
        # A response delivered after close cannot authorize the canceled prompt.
        try:
            initiator.respond_to_pairing(request.data["request_id"], True)
        except SparcError:
            pass
        assert initiator.trusted_peers() == []
    finally:
        initiator.close()
        responder.close()


def test_cancel_during_pin_completion_never_adopts_session(tmp_path):
    responder, endpoint = _start_responder(tmp_path)
    initiator = PeerService(tmp_path / "initiator")
    entered_pin = threading.Event()
    release_pin = threading.Event()
    close_done = threading.Event()
    original_pin = initiator._trust.pin

    def pause_after_durable_pin(public_key, peer_endpoint, label=""):
        result = original_pin(public_key, peer_endpoint, label)
        entered_pin.set()
        release_pin.wait(timeout=2)
        return result

    initiator._trust.pin = pause_after_durable_pin
    try:
        initiator.connect(endpoint)
        initiator_request = _wait_pairing(initiator)
        initiator.respond_to_pairing(initiator_request.data["request_id"], True)
        responder_request = _wait_pairing(responder)
        responder.respond_to_pairing(responder_request.data["request_id"], True)
        assert entered_pin.wait(timeout=6)

        closer = threading.Thread(target=lambda: (initiator.close(), close_done.set()))
        closer.start()
        assert initiator._cancel.wait(timeout=1)
        release_pin.set()
        assert close_done.wait(timeout=2)
        closer.join(timeout=1)
        assert not closer.is_alive()
        assert initiator.state != "connected"
        # The pin was already durably underway, so its presence is permitted.
        assert initiator.trusted_peers()[0]["fingerprint"] == responder.own_fingerprint
    finally:
        release_pin.set()
        initiator.close()
        responder.close()
