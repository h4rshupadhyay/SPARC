"""End-to-end SPARC handshake checks on connected IPv4 loopback sockets."""

import base64
import hashlib
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _identity(seed):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _tcp_pair():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(3)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener_address = listener.getsockname()
    initiator = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    initiator.settimeout(3)
    initiator.connect(listener_address)
    responder, _ = listener.accept()
    listener.close()
    responder.settimeout(3)
    return initiator, responder, listener_address


def _run_pair(initiator_sock, responder_sock, initiator_id, responder_id, initiator_trust,
              responder_trust, initiator_approve, responder_approve):
    from sparc.models import Role, Limits
    from sparc.protocol.handshake import perform_handshake

    outcomes = {"initiator": {}, "responder": {}}
    cancel_i, cancel_r = threading.Event(), threading.Event()

    def run(name, sock, role, identity, trust, approve, cancel):
        try:
            outcomes[name]["session"] = perform_handshake(
                sock, role, identity, trust, approve, cancel, Limits()
            )
        except Exception as exc:
            outcomes[name]["error"] = exc

    workers = [
        threading.Thread(target=run, args=("initiator", initiator_sock, Role.INITIATOR,
                                            initiator_id, initiator_trust, initiator_approve, cancel_i), daemon=True),
        threading.Thread(target=run, args=("responder", responder_sock, Role.RESPONDER,
                                            responder_id, responder_trust, responder_approve, cancel_r), daemon=True),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    assert all(not worker.is_alive() for worker in workers), "handshake worker did not finish"
    return outcomes


def _close_pair(*sockets):
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def _assert_success(outcomes):
    assert "error" not in outcomes["initiator"], outcomes["initiator"].get("error")
    assert "error" not in outcomes["responder"], outcomes["responder"].get("error")
    return outcomes["initiator"]["session"], outcomes["responder"]["session"]


def _frame_from_bytes(frame_bytes):
    from sparc.protocol.framing import Frame

    length = int.from_bytes(frame_bytes[:4], "big")
    return Frame(frame_bytes[4], frame_bytes[5:], length)


def test_unknown_and_known_real_socket_handshakes_and_unicode_records(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint
    from sparc.protocol.messages import prepare_text

    initiator_id, responder_id = _identity(81), _identity(82)
    initiator_store = TrustStore(tmp_path / "initiator")
    responder_store = TrustStore(tmp_path / "responder")
    initiator_prompts, responder_prompts = [], []
    client, server, listener_address = _tcp_pair()
    try:
        outcomes = _run_pair(
            client, server, initiator_id, responder_id, initiator_store, responder_store,
            lambda candidate: initiator_prompts.append(candidate) or True,
            lambda candidate: responder_prompts.append(candidate) or True,
        )
        initiator_session, responder_session = _assert_success(outcomes)
        assert initiator_session.codec.session_id == responder_session.codec.session_id
        assert initiator_session.transcript_hash == responder_session.transcript_hash
        assert initiator_session.peer.public_key == responder_id.public_bytes
        assert responder_session.peer.public_key == initiator_id.public_bytes
        assert initiator_session.newly_approved is responder_session.newly_approved is True
        assert len(initiator_prompts) == len(responder_prompts) == 1
        assert initiator_prompts[0].fingerprint == responder_id.fingerprint
        assert responder_prompts[0].fingerprint == initiator_id.fingerprint
        assert initiator_store.check(responder_id.public_bytes, initiator_prompts[0].endpoint) == "unknown"
        assert responder_store.check(initiator_id.public_bytes, responder_prompts[0].endpoint) == "unknown"

        outbound = prepare_text("Zażółć gęślą jaźń — こんにちは 🌍", "a" * 32)[0]
        protected = initiator_session.codec.protect(outbound)
        opened = responder_session.codec.open(_frame_from_bytes(protected.frame))
        assert opened.payload["text"] == outbound["text"]

        reverse = prepare_text("नमस्ते — café — مرحبا", "b" * 32)[0]
        reverse_protected = responder_session.codec.protect(reverse)
        reverse_opened = initiator_session.codec.open(_frame_from_bytes(reverse_protected.frame))
        assert reverse_opened.payload["text"] == reverse["text"]
    finally:
        _close_pair(client, server)

    # Pins are prepared for a fresh pair using the role-specific TCP endpoints.
    client, server, listener_address = _tcp_pair()
    initiator_store.pin(responder_id.public_bytes, Endpoint(*listener_address))
    responder_store.pin(initiator_id.public_bytes, Endpoint(*client.getsockname()))
    before_i = (tmp_path / "initiator" / "trusted_peers.json").read_bytes()
    before_r = (tmp_path / "responder" / "trusted_peers.json").read_bytes()
    prompts = []
    try:
        outcomes = _run_pair(
            client, server, initiator_id, responder_id, initiator_store, responder_store,
            lambda candidate: prompts.append(candidate) or True,
            lambda candidate: prompts.append(candidate) or True,
        )
        initiator_session, responder_session = _assert_success(outcomes)
        assert initiator_session.newly_approved is responder_session.newly_approved is False
        assert prompts == []
        assert (tmp_path / "initiator" / "trusted_peers.json").read_bytes() == before_i
        assert (tmp_path / "responder" / "trusted_peers.json").read_bytes() == before_r
    finally:
        _close_pair(client, server)


def test_reconnect_uses_fresh_session_and_transcript(tmp_path):
    from sparc.identity import TrustStore

    initiator_id, responder_id = _identity(83), _identity(84)
    initiator_store = TrustStore(tmp_path / "initiator")
    responder_store = TrustStore(tmp_path / "responder")
    results = []
    for _ in range(2):
        client, server, _listener = _tcp_pair()
        try:
            outcomes = _run_pair(
                client, server, initiator_id, responder_id, initiator_store, responder_store,
                lambda _candidate: True, lambda _candidate: True,
            )
            first, second = _assert_success(outcomes)
            results.append((first.codec.session_id, first.transcript_hash, second.codec.session_id))
            assert first.codec.session_id == second.codec.session_id
        finally:
            _close_pair(client, server)
    assert results[0][0] != results[1][0]
    assert results[0][1] != results[1][1]
    assert not (tmp_path / "initiator" / "trusted_peers.json").exists()
    assert not (tmp_path / "responder" / "trusted_peers.json").exists()


def test_tampered_hello_random_causes_signature_failure_without_pins(tmp_path, monkeypatch):
    import sparc.protocol.handshake_initiator as initiator_module
    from sparc.encoding import canonical, parse_object
    from sparc.identity import TrustStore
    from sparc.models import Role, Limits
    from sparc.protocol.framing import pack_frame
    from sparc.protocol.handshake import perform_handshake

    initiator_id, responder_id = _identity(85), _identity(86)
    initiator_store = TrustStore(tmp_path / "initiator")
    responder_store = TrustStore(tmp_path / "responder")
    client, server, _listener = _tcp_pair()
    original_send = initiator_module._send_frame
    tampered = []

    def intercept(sock, frame, cancel, limits, deadline):
        if len(frame) >= 5 and frame[4] == 1:
            payload = parse_object(frame[5:])
            payload["random"] = base64.b64encode(b"z" * 32).decode("ascii")
            frame = pack_frame(1, canonical(payload))
            tampered.append(True)
        return original_send(sock, frame, cancel, limits, deadline)

    monkeypatch.setattr(initiator_module, "_send_frame", intercept)
    outcomes = {"initiator": {}, "responder": {}}
    def run_initiator():
        try:
            outcomes["initiator"]["session"] = perform_handshake(
                client, Role.INITIATOR, initiator_id, initiator_store,
                lambda _candidate: True, threading.Event(), Limits(),
            )
        except Exception as exc:
            outcomes["initiator"]["error"] = exc
    def run_responder():
        try:
            outcomes["responder"]["session"] = perform_handshake(
                server, Role.RESPONDER, responder_id, responder_store,
                lambda _candidate: True, threading.Event(), Limits(),
            )
        except Exception as exc:
            outcomes["responder"]["error"] = exc
    workers = [threading.Thread(target=run_initiator, daemon=True), threading.Thread(target=run_responder, daemon=True)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    try:
        assert all(not worker.is_alive() for worker in workers)
        assert tampered == [True]
        assert getattr(outcomes["initiator"].get("error"), "code", None) == "handshake_signature_failed"
        assert not (tmp_path / "initiator" / "trusted_peers.json").exists()
        assert not (tmp_path / "responder" / "trusted_peers.json").exists()
    finally:
        _close_pair(client, server)
