"""Initiator handshake choreography and bounded-I/O contract tests."""

import base64
import hashlib
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def _identity(seed=41):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _raw_x25519(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _tcp_pair():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(2)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(listener.getsockname())
    server, _ = listener.accept()
    listener.close()
    server.settimeout(2)
    return client, server


def _send(sock, kind, body):
    from sparc.protocol.framing import pack_frame

    sock.sendall(pack_frame(kind, body))


def _read(sock, cancel=None):
    from threading import Event
    from sparc.models import Limits
    from sparc.protocol.framing import read_frame

    return read_frame(sock, cancel or Event(), time.monotonic() + 2, Limits())


def _fake_peer(sock, identity=None, *, signature_domain=None, finished_digest=None, ephemeral_raw=None):
    """Run the peer half of the wire protocol and return its observations."""
    from sparc.crypto import derive_traffic_keys
    from sparc.encoding import canonical, parse_object
    from sparc.protocol.framing import Frame
    from sparc.protocol.handshake_transcript import HANDSHAKE_INITIATOR_DOMAIN, HANDSHAKE_RESPONDER_DOMAIN
    from sparc.protocol.records import SessionCodec
    from sparc.models import Role

    identity = identity or _identity(51)
    result = {}
    try:
        frame = _read(sock)
        assert frame.kind == 1
        client_hello = parse_object(frame.body)
        server_ephemeral = X25519PrivateKey.generate()
        server_random = os_random = __import__("os").urandom(32)
        server_hello = {
            "kind": "server_hello",
            "protocol": "SPARC",
            "version": 1,
            "identity_key": base64.b64encode(identity.public_bytes).decode("ascii"),
            "ephemeral_key": base64.b64encode(ephemeral_raw if ephemeral_raw is not None else _raw_x25519(server_ephemeral)).decode("ascii"),
            "random": base64.b64encode(server_random).decode("ascii"),
        }
        transcript = canonical({"client_hello": client_hello, "server_hello": server_hello})
        domain = signature_domain if signature_domain is not None else HANDSHAKE_RESPONDER_DOMAIN
        signature = identity.private_key.sign(domain + transcript)
        _send(sock, 2, canonical({**server_hello, "signature": base64.b64encode(signature).decode("ascii")}))
        try:
            auth = _read(sock)
        except Exception as exc:
            result["after_server_hello"] = getattr(exc, "code", type(exc).__name__)
            return result
        assert auth.kind == 3
        auth_payload = parse_object(auth.body)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(client_hello["identity_key"])).verify(
            base64.b64decode(auth_payload["signature"]), HANDSHAKE_INITIATOR_DOMAIN + transcript
        )
        shared = server_ephemeral.exchange(
            X25519PublicKey.from_public_bytes(base64.b64decode(client_hello["ephemeral_key"]))
        )
        keys = derive_traffic_keys(shared, transcript)
        codec = SessionCodec(identity, base64.b64decode(client_hello["identity_key"]), Role.RESPONDER, keys[:2], keys[2])
        digest = finished_digest if finished_digest is not None else hashlib.sha256(transcript).hexdigest()
        protected = codec.protect({"kind": "finished", "transcript_sha256": digest}, frame_type=4)
        sock.sendall(protected.frame)
        try:
            finished = _read(sock)
            result["initiator_finished"] = codec.open(finished).payload
        except Exception as exc:
            result["after_client_auth"] = getattr(exc, "code", type(exc).__name__)
        return result
    except Exception as exc:
        result["error"] = exc
        return result


def _start_peer(sock, **kwargs):
    result = {}
    def run():
        result.update(_fake_peer(sock, **kwargs))
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def _run(client, server, trust, approve, *, cancel=None, limits=None):
    from sparc.models import Limits
    from sparc.protocol.handshake_initiator import run_initiator

    return run_initiator(
        client, _identity(), trust, approve, cancel or threading.Event(),
        limits or Limits(), time.monotonic() + 5,
    )


def test_initiator_validates_before_approval_and_completes_finished_exchange(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import SparcError

    client, server = _tcp_pair()
    thread, peer = _start_peer(server)
    trust = TrustStore(tmp_path)
    seen = []
    session = _run(client, server, trust, lambda candidate: seen.append(candidate) or True)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert len(seen) == 1
    assert session.peer == seen[0]
    assert session.newly_approved is True
    assert session.transcript_hash == peer["initiator_finished"]["transcript_sha256"]
    assert peer["initiator_finished"]["kind"] == "finished"
    assert trust.check(session.peer.public_key, session.peer.endpoint) == "unknown"
    client.close()
    server.close()

    # A correctly shaped but incorrectly signed hello must fail before asking.
    client, server = _tcp_pair()
    thread, peer = _start_peer(server, signature_domain=b"wrong signature domain\x00")
    trust = TrustStore(tmp_path / "bad-signature")
    prompts = []
    with pytest.raises(SparcError) as error:
        _run(client, server, trust, lambda candidate: prompts.append(candidate) or True)
    thread.join(timeout=2)
    assert error.value.code == "handshake_signature_failed"
    assert prompts == []
    assert not (tmp_path / "bad-signature" / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_initiator_rejects_changed_key_without_prompt_or_pin_write(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import SparcError

    client, server = _tcp_pair()
    endpoint = client.getpeername()
    trust = TrustStore(tmp_path)
    trust.pin(_identity(52).public_bytes, __import__("sparc.models", fromlist=["Endpoint"]).Endpoint(*endpoint))
    before = (tmp_path / "trusted_peers.json").read_bytes()
    thread, _ = _start_peer(server)
    prompts = []
    with pytest.raises(SparcError) as error:
        _run(client, server, trust, lambda candidate: prompts.append(candidate) or True)
    thread.join(timeout=2)
    assert error.value.code == "changed_identity"
    assert prompts == []
    assert (tmp_path / "trusted_peers.json").read_bytes() == before
    client.close()
    server.close()


def test_initiator_rejects_reflected_signature(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import HANDSHAKE_INITIATOR_DOMAIN

    client, server = _tcp_pair()
    thread, _ = _start_peer(server, signature_domain=HANDSHAKE_INITIATOR_DOMAIN)
    with pytest.raises(SparcError) as error:
        _run(client, server, TrustStore(tmp_path), lambda _candidate: True)
    thread.join(timeout=2)
    assert error.value.code == "handshake_signature_failed"
    client.close()
    server.close()


def test_finished_hash_must_match_validated_transcript(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import SparcError

    client, server = _tcp_pair()
    thread, peer = _start_peer(server, finished_digest="0" * 64)
    with pytest.raises(SparcError) as error:
        _run(client, server, TrustStore(tmp_path), lambda _candidate: True)
    thread.join(timeout=2)
    assert error.value.code == "transcript_mismatch"
    assert peer.get("after_client_auth") == "tcp_loss" or "initiator_finished" not in peer
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


@pytest.mark.parametrize("decision,canceled,expected", [(False, False, "pairing_rejected"), (True, True, "canceled")])
def test_rejected_or_canceled_pairing_never_pins(tmp_path, decision, canceled, expected):
    from sparc.identity import TrustStore
    from sparc.models import SparcError

    client, server = _tcp_pair()
    thread, peer = _start_peer(server)
    trust = TrustStore(tmp_path)
    cancel = threading.Event()
    def approve(_candidate):
        if canceled:
            cancel.set()
        return decision
    with pytest.raises(SparcError) as error:
        _run(client, server, trust, approve, cancel=cancel)
    thread.join(timeout=2)
    assert error.value.code == expected
    assert not (tmp_path / "trusted_peers.json").exists()
    assert "initiator_finished" not in peer
    client.close()
    server.close()


def test_all_zero_exchange_is_rejected_without_authentication_or_pin(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import SparcError

    client, server = _tcp_pair()
    thread, peer = _start_peer(server, ephemeral_raw=b"\x00" * 32)
    with pytest.raises(SparcError) as error:
        _run(client, server, TrustStore(tmp_path), lambda _candidate: True)
    thread.join(timeout=2)
    assert error.value.code == "invalid_key_exchange"
    assert not (tmp_path / "trusted_peers.json").exists()
    assert peer.get("after_server_hello") == "tcp_loss" or "initiator_finished" not in peer
    client.close()
    server.close()


def test_bounded_approval_timeout_sets_cancel_and_ignores_late_true():
    from sparc.models import Endpoint, Limits, SparcError
    from sparc.protocol.handshake_transcript import _bounded_approval
    from sparc.protocol.handshake_types import PeerCandidate

    cancel = threading.Event()
    candidate = PeerCandidate(b"k" * 32, hashlib.sha256(b"k" * 32).hexdigest(), Endpoint("127.0.0.1", 43210))
    release = threading.Event()
    limits = Limits(pairing_timeout_seconds=0.04, cancel_poll_seconds=0.005)
    started = time.monotonic()
    with pytest.raises(SparcError) as error:
        _bounded_approval(candidate, lambda _candidate: (release.wait(1), True)[1], cancel, limits, time.monotonic() + 1)
    assert error.value.code == "pairing_timeout"
    assert cancel.is_set()
    assert time.monotonic() - started < 0.5
    release.set()


def test_bounded_approval_checks_cancel_before_accepting_completed_decision():
    from sparc.models import Endpoint, Limits, SparcError
    from sparc.protocol.handshake_transcript import _bounded_approval
    from sparc.protocol.handshake_types import PeerCandidate

    cancel = threading.Event()
    cancel.set()
    candidate = PeerCandidate(b"c" * 32, hashlib.sha256(b"c" * 32).hexdigest(), Endpoint("127.0.0.1", 43211))
    with pytest.raises(SparcError) as error:
        _bounded_approval(candidate, lambda _candidate: True, cancel, Limits(), time.monotonic() + 1)
    assert error.value.code == "canceled"


class _PartialSocket:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.timeout = None
        self.sent = bytearray()
    def gettimeout(self):
        return self.timeout
    def settimeout(self, value):
        self.timeout = value
    def send(self, view):
        outcome = next(self.outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        amount = min(outcome, len(view))
        self.sent.extend(view[:amount])
        return amount


def test_send_frame_handles_partial_send_then_deadline_and_tcp_loss(monkeypatch):
    from sparc.models import Limits, SparcError
    from sparc.protocol.handshake_transcript import _send_frame

    cancel = threading.Event()
    sock = _PartialSocket([2, socket.timeout(), socket.timeout()])
    limits = Limits(cancel_poll_seconds=0.005)
    fake_now = [100.0]
    def advance_clock():
        value = fake_now[0]
        fake_now[0] += 0.01
        return value
    with monkeypatch.context() as clock_patch:
        clock_patch.setattr("sparc.protocol.handshake_transcript.time.monotonic", advance_clock)
        with pytest.raises(SparcError) as error:
            _send_frame(sock, b"abcdefgh", cancel, limits, 100.025)
    assert error.value.code == "handshake_timeout"
    assert sock.sent == b"ab"
    assert sock.timeout is None

    broken = _PartialSocket([OSError("simulated loss")])
    with pytest.raises(SparcError) as error:
        _send_frame(broken, b"abc", threading.Event(), Limits(), time.monotonic() + 1)
    assert error.value.code == "tcp_loss"


def test_check_deadline_reports_cancel_before_expiry():
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import _check_deadline

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(SparcError) as error:
        _check_deadline(cancel, time.monotonic() + 10)
    assert error.value.code == "canceled"
    with pytest.raises(SparcError) as error:
        _check_deadline(threading.Event(), time.monotonic() - 1)
    assert error.value.code == "handshake_timeout"
