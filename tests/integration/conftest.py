"""Shared connected-peer fixtures for service integration tests."""

from __future__ import annotations

import queue
import time
from dataclasses import dataclass

import pytest

from sparc.models import Endpoint, Limits
from sparc.peer.service import PeerService


def wait_event(service: PeerService, kind: str, message_id: str | None = None,
               timeout: float = 6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if event.kind != kind:
            continue
        if message_id is not None and event.data.get("message_id") != message_id:
            continue
        return event
    raise AssertionError(f"timed out waiting for {kind!r} event")


def _pairing_request(service: PeerService, timeout: float = 6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = service.events.get(timeout=min(0.05, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if event.kind == "pairing_required" or "request_id" in event.data:
            return event
    raise AssertionError("timed out waiting for explicit peer approval")


def _connected(service: PeerService, timeout: float = 6.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.state == "connected":
            return
        time.sleep(0.005)
    assert service.state == "connected"


@dataclass(frozen=True)
class PeerPair:
    alice: PeerService
    bob: PeerService
    alice_endpoint: Endpoint
    bob_endpoint: Endpoint


@pytest.fixture
def peer_pair(tmp_path, request):
    limits = getattr(request, "param", Limits())
    alice = PeerService(tmp_path / "alice", limits)
    bob = PeerService(tmp_path / "bob", limits)
    alice_endpoint = alice.start_listener("127.0.0.1", 0)
    bob_endpoint = bob.start_listener("127.0.0.1", 0)
    try:
        alice.connect(bob_endpoint)
        alice_request = _pairing_request(alice)
        assert alice_request.data["candidate_fingerprint"] == bob.own_fingerprint
        assert alice_request.data["own_fingerprint"] == alice.own_fingerprint
        alice.respond_to_pairing(alice_request.data["request_id"], True)

        bob_request = _pairing_request(bob)
        assert bob_request.data["candidate_fingerprint"] == alice.own_fingerprint
        assert bob_request.data["own_fingerprint"] == bob.own_fingerprint
        bob.respond_to_pairing(bob_request.data["request_id"], True)
        _connected(alice)
        _connected(bob)
        yield PeerPair(alice, bob, alice_endpoint, bob_endpoint)
    finally:
        alice.close()
        bob.close()
