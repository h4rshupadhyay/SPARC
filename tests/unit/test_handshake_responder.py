"""Responder handshake behavior over connected loopback TCP sockets."""

import base64
import hashlib
import os
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _identity(seed):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


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


def _read(sock, timeout=2):
    from sparc.models import Limits
    from sparc.protocol.framing import read_frame

    return read_frame(sock, threading.Event(), time.monotonic() + timeout, Limits())


def _client_handshake(sock, client_identity=None, *, auth_mode="valid", finished_digest=None, secret_override=None, send_finished=True):
    """Independently construct client transcript/auth and complete finished records."""
    from sparc.crypto import derive_traffic_keys, record_aad
    from sparc.encoding import canonical, parse_object
    from sparc.models import Role
    from sparc.protocol.handshake_transcript import HANDSHAKE_INITIATOR_DOMAIN, HANDSHAKE_RESPONDER_DOMAIN
    from sparc.protocol.records import SessionCodec
    from sparc.protocol.framing import Frame, pack_frame

    client_identity = client_identity or _identity(62)
    ephemeral = X25519PrivateKey.generate()
    client_hello = {
        "kind": "client_hello",
        "protocol": "SPARC",
        "version": 1,
        "identity_key": base64.b64encode(client_identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
        "random": base64.b64encode(os.urandom(32)).decode("ascii"),
    }
    _send(sock, 1, canonical(client_hello))
    server_frame = _read(sock)
    assert server_frame.kind == 2
    server_signed = parse_object(server_frame.body)
    signature = base64.b64decode(server_signed["signature"], validate=True)
    server_unsigned = {key: value for key, value in server_signed.items() if key != "signature"}
    transcript = canonical({"client_hello": client_hello, "server_hello": server_unsigned})
    server_key = base64.b64decode(server_unsigned["identity_key"], validate=True)
    Ed25519PublicKey.from_public_bytes(server_key).verify(signature, HANDSHAKE_RESPONDER_DOMAIN + transcript)

    if auth_mode == "valid":
        auth_signature = client_identity.private_key.sign(HANDSHAKE_INITIATOR_DOMAIN + transcript)
    elif auth_mode == "stale":
        auth_signature = client_identity.private_key.sign(HANDSHAKE_INITIATOR_DOMAIN + transcript + b"stale")
    elif auth_mode == "reflected":
        auth_signature = client_identity.private_key.sign(HANDSHAKE_RESPONDER_DOMAIN + transcript)
    elif auth_mode == "bad":
        auth_signature = b"x" * 64
    else:
        raise AssertionError("unknown auth mode")
    _send(sock, 3, canonical({"kind": "client_auth", "signature": base64.b64encode(auth_signature).decode("ascii")}))
    if auth_mode != "valid":
        try:
            return {"failure_frame": _read(sock)}
        except Exception as exc:
            return {"peer_error": getattr(exc, "code", type(exc).__name__)}

    try:
        shared = secret_override if secret_override is not None else ephemeral.exchange(
            X25519PublicKey.from_public_bytes(base64.b64decode(server_unsigned["ephemeral_key"], validate=True))
        )
    except Exception as exc:
        return {"exchange_error": type(exc).__name__}
    i2r, r2i, session_id = derive_traffic_keys(shared, transcript)
    correct_hash = hashlib.sha256(transcript).hexdigest()
    wrong_keys = secret_override is not None
    if wrong_keys:
        wrong_i2r, wrong_r2i, _ = derive_traffic_keys(secret_override, transcript)
        recv_keys = (wrong_i2r, wrong_r2i)
        # Send directly with the correct session ID but incorrect traffic key.
        plain = canonical({"kind": "finished", "transcript_sha256": correct_hash})
        seq = (0).to_bytes(8, "big")
        length = 1 + 32 + 8 + len(plain) + 16
        aad = record_aad(5, session_id, 0, 0, length)
        wrong_frame = pack_frame(5, session_id + seq + AESGCM(recv_keys[0]).encrypt(b"\x00" * 4 + seq, plain, aad))
        finished = _read(sock)
        _send(sock, 5, wrong_frame[5:])
        return {"wrong_key_sent": finished.kind == 4}

    codec = SessionCodec(client_identity, server_key, Role.INITIATOR, (i2r, r2i), session_id)
    finished = _read(sock)
    assert finished.kind == 4
    opened = codec.open(finished)
    if not send_finished:
        return {"server_finished": opened.payload, "transcript": transcript}
    digest = finished_digest if finished_digest is not None else correct_hash
    client_finished = codec.protect({"kind": "finished", "transcript_sha256": digest}, frame_type=5)
    sock.sendall(client_finished.frame)
    return {
        "server_finished": opened.payload,
        "transcript": transcript,
        "server_key": server_key,
        "server_endpoint_source": sock.getsockname(),
    }


def _start_responder(sock, data_dir, approve, *, cancel=None, limits=None, overall_timeout=5):
    from sparc.identity import TrustStore
    from sparc.models import Limits
    from sparc.protocol.handshake_responder import run_responder

    result = {}
    identity = _identity(70)
    trust = TrustStore(data_dir)
    def run():
        try:
            result["session"] = run_responder(
                sock, identity, trust, approve, cancel or threading.Event(), limits or Limits(),
                time.monotonic() + overall_timeout,
            )
        except Exception as exc:
            result["error"] = exc
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result, trust, identity


def _assert_error(result, code):
    assert "error" in result
    assert getattr(result["error"], "code", None) == code


def _start_client(sock, **kwargs):
    result = {}
    def run():
        try:
            result["value"] = _client_handshake(sock, **kwargs)
        except Exception as exc:
            result["error"] = exc
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def test_responder_validates_full_client_auth_and_finishes_without_pinning(tmp_path):
    from sparc.models import SparcError

    client, server = _tcp_pair()
    prompts = []
    thread, result, trust, _responder_identity = _start_responder(
        server, tmp_path, lambda candidate: prompts.append(candidate) or True
    )
    client_result = _client_handshake(client)
    thread.join(timeout=2)
    assert not thread.is_alive()
    session = result["session"]
    assert session.newly_approved is True
    assert len(prompts) == 1
    assert session.peer == prompts[0]
    assert session.transcript_hash == hashlib.sha256(client_result["transcript"]).hexdigest()
    assert session.peer.endpoint.ip == "127.0.0.1"
    assert session.peer.endpoint.port == client_result["server_endpoint_source"][1]
    assert session.peer.endpoint.port != server.getsockname()[1]
    assert trust.check(session.peer.public_key, session.peer.endpoint) == "unknown"
    client.close()
    server.close()


@pytest.mark.parametrize("mode", ["stale", "reflected", "bad"])
def test_responder_rejects_invalid_or_reflected_client_auth_before_approval(tmp_path, mode):
    client, server = _tcp_pair()
    prompts = []
    thread, result, _trust, _responder_identity = _start_responder(
        server, tmp_path, lambda candidate: prompts.append(candidate) or True
    )
    client_result = _client_handshake(client, auth_mode=mode)
    thread.join(timeout=2)
    assert not thread.is_alive()
    _assert_error(result, "handshake_signature_failed")
    assert prompts == []
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_responder_rejects_all_zero_exchange_without_finished_or_pin(tmp_path):
    from sparc.encoding import canonical

    client, server = _tcp_pair()
    # Build a signed hello with an all-zero ephemeral key and an otherwise valid
    # client authentication over that exact transcript.
    prompts = []
    thread, result, _trust, _responder_identity = _start_responder(
        server, tmp_path, lambda candidate: prompts.append(candidate) or True
    )
    client_identity = _identity(71)
    hello = {
        "kind": "client_hello", "protocol": "SPARC", "version": 1,
        "identity_key": base64.b64encode(client_identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(b"\x00" * 32).decode("ascii"),
        "random": base64.b64encode(os.urandom(32)).decode("ascii"),
    }
    _send(client, 1, canonical(hello))
    server_frame = _read(client)
    from sparc.encoding import parse_object
    server_unsigned = {key: value for key, value in parse_object(server_frame.body).items() if key != "signature"}
    transcript = canonical({"client_hello": hello, "server_hello": server_unsigned})
    from sparc.protocol.handshake_transcript import HANDSHAKE_INITIATOR_DOMAIN
    signature = client_identity.private_key.sign(HANDSHAKE_INITIATOR_DOMAIN + transcript)
    _send(client, 3, canonical({"kind": "client_auth", "signature": base64.b64encode(signature).decode("ascii")}))
    thread.join(timeout=2)
    assert not thread.is_alive()
    _assert_error(result, "invalid_key_exchange")
    assert len(prompts) == 1
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


@pytest.mark.parametrize("case,expected", [("wrong_key", "gcm_authentication_failed"), ("wrong_hash", "transcript_mismatch")])
def test_client_finished_requires_correct_keys_and_transcript_hash(tmp_path, case, expected):
    client, server = _tcp_pair()
    thread, result, _trust, _responder_identity = _start_responder(server, tmp_path, lambda _candidate: True)
    if case == "wrong_key":
        client_result = _client_handshake(client, secret_override=b"w" * 32)
    else:
        client_result = _client_handshake(client, finished_digest="0" * 64)
    thread.join(timeout=2)
    assert not thread.is_alive()
    _assert_error(result, expected)
    assert "session" not in result
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_responder_hello_and_client_auth_deadlines_fail_closed(tmp_path):
    from sparc.models import Limits

    client, server = _tcp_pair()
    limits = Limits(hello_timeout_seconds=0.04, cancel_poll_seconds=0.005)
    thread, result, _trust, _responder_identity = _start_responder(server, tmp_path / "hello", lambda _candidate: True, limits=limits)
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "handshake_timeout")
    assert not (tmp_path / "hello" / "trusted_peers.json").exists()
    client.close()
    server.close()

    client, server = _tcp_pair()
    limits = Limits(client_auth_timeout_seconds=0.04, cancel_poll_seconds=0.005)
    thread, result, _trust, _responder_identity = _start_responder(server, tmp_path / "auth", lambda _candidate: True, limits=limits)
    # Send only the client hello. The server sends its signed hello and then
    # waits for client_auth until the shortened phase deadline.
    from sparc.encoding import canonical
    ephemeral = X25519PrivateKey.generate()
    client_identity = _identity(72)
    hello = {
        "kind": "client_hello", "protocol": "SPARC", "version": 1,
        "identity_key": base64.b64encode(client_identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
        "random": base64.b64encode(os.urandom(32)).decode("ascii"),
    }
    _send(client, 1, canonical(hello))
    assert _read(client).kind == 2
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "handshake_timeout")
    assert not (tmp_path / "auth" / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_responder_approval_timeout_cancels_and_late_true_never_finishes_or_pins(tmp_path):
    from sparc.models import Limits

    client, server = _tcp_pair()
    entered = threading.Event()
    release = threading.Event()
    def delayed(_candidate):
        entered.set()
        release.wait(1)
        return True
    limits = Limits(pairing_timeout_seconds=0.04, cancel_poll_seconds=0.005)
    thread, result, _trust, _responder_identity = _start_responder(
        server, tmp_path, delayed, limits=limits
    )
    client_thread, client_result = _start_client(client)
    assert entered.wait(1)
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "pairing_timeout")
    assert not (tmp_path / "trusted_peers.json").exists()
    release.set()
    client_thread.join(timeout=1)
    assert getattr(client_result.get("error"), "code", None) == "tcp_loss"
    client.close()
    server.close()


def test_responder_cancel_race_does_not_accept_completed_approval(tmp_path):
    client, server = _tcp_pair()
    cancel = threading.Event()
    def cancel_then_approve(_candidate):
        cancel.set()
        return True
    thread, result, _trust, _responder_identity = _start_responder(
        server, tmp_path, cancel_then_approve, cancel=cancel
    )
    client_thread, client_result = _start_client(client)
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "canceled")
    assert not (tmp_path / "trusted_peers.json").exists()
    client_thread.join(timeout=1)
    assert getattr(client_result.get("error"), "code", None) == "tcp_loss"
    client.close()
    server.close()


def test_responder_overall_deadline_caps_client_auth_phase(tmp_path):
    from sparc.models import Limits
    from sparc.encoding import canonical

    client, server = _tcp_pair()
    limits = Limits(client_auth_timeout_seconds=1, cancel_poll_seconds=0.005)
    thread, result, _trust, _responder_identity = _start_responder(
        server, tmp_path, lambda _candidate: True, limits=limits, overall_timeout=0.05
    )
    client_identity = _identity(73)
    ephemeral = X25519PrivateKey.generate()
    hello = {
        "kind": "client_hello", "protocol": "SPARC", "version": 1,
        "identity_key": base64.b64encode(client_identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
        "random": base64.b64encode(os.urandom(32)).decode("ascii"),
    }
    _send(client, 1, canonical(hello))
    assert _read(client).kind == 2
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "handshake_timeout")
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_responder_client_finished_deadline_fails_without_session_or_pin(tmp_path):
    from sparc.models import Limits

    client, server = _tcp_pair()
    limits = Limits(client_finished_timeout_seconds=0.04, cancel_poll_seconds=0.005)
    thread, result, _trust, _identity = _start_responder(
        server, tmp_path, lambda _candidate: True, limits=limits
    )
    peer_result = _client_handshake(client, send_finished=False)
    assert peer_result["server_finished"]["kind"] == "finished"
    thread.join(timeout=1)
    assert not thread.is_alive()
    _assert_error(result, "handshake_timeout")
    assert not (tmp_path / "trusted_peers.json").exists()
    client.close()
    server.close()


def test_responder_advances_phase_deadline_after_client_auth(tmp_path, monkeypatch):
    from sparc.crypto import derive_traffic_keys
    from sparc.encoding import canonical, parse_object
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, Limits, Role
    from sparc.protocol import handshake_responder
    from sparc.protocol.framing import Frame, pack_frame
    from sparc.protocol.handshake_transcript import (
        HANDSHAKE_INITIATOR_DOMAIN,
        HANDSHAKE_RESPONDER_DOMAIN,
        _check_deadline,
    )
    from sparc.protocol.records import SessionCodec

    class VirtualClock:
        now = 0.0
        def monotonic(self):
            return self.now

    clock = VirtualClock()
    monkeypatch.setattr(handshake_responder, "time", clock)
    monkeypatch.setattr("sparc.protocol.handshake_transcript.time", clock)
    client_sock, responder_sock = _tcp_pair()
    peer_endpoint = Endpoint(*client_sock.getsockname())
    server_identity, client_identity = _identity(90), _identity(91)
    client_ephemeral = X25519PrivateKey.generate()
    client_hello = {
        "kind": "client_hello",
        "protocol": "SPARC",
        "version": 1,
        "identity_key": base64.b64encode(client_identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(
            client_ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii"),
        "random": base64.b64encode(b"c" * 32).decode("ascii"),
    }
    hello_body = canonical(client_hello)
    script = [Frame(1, hello_body, 1 + len(hello_body))]
    state = {}
    cancel = threading.Event()

    def scripted_read(_sock, read_cancel, deadline, _limits):
        _check_deadline(read_cancel, deadline)
        if not state.get("server_hello_sent"):
            assert deadline == 20.0
            return script.pop(0)
        if not state.get("auth_read"):
            # The peer sends client_auth 90 virtual seconds after server_hello.
            assert deadline == 150.0
            clock.now = 90.0
            state["auth_read"] = True
            auth_signature = client_identity.private_key.sign(
                HANDSHAKE_INITIATOR_DOMAIN + state["transcript"]
            )
            auth_payload = {
                "kind": "client_auth",
                "signature": base64.b64encode(auth_signature).decode("ascii"),
            }
            encoded = pack_frame(3, canonical(auth_payload))
            return Frame(3, encoded[5:], int.from_bytes(encoded[:4], "big"))
        # The client finished is returned after responder approval finishes at t=180.
        assert deadline == 190.0
        state["client_finished"] = state["client_codec"].protect(
            {"kind": "finished", "transcript_sha256": hashlib.sha256(state["transcript"]).hexdigest()},
            frame_type=5,
        ).frame
        finished = state["client_finished"]
        return Frame(5, finished[5:], int.from_bytes(finished[:4], "big"))

    def scripted_send(_sock, frame_bytes, send_cancel, _limits, deadline):
        _check_deadline(send_cancel, deadline)
        kind = frame_bytes[4]
        if kind == 2:
            assert deadline == 20.0
            signed_server = parse_object(frame_bytes[5:])
            server_unsigned = {key: value for key, value in signed_server.items() if key != "signature"}
            transcript = canonical({"client_hello": client_hello, "server_hello": server_unsigned})
            signature = base64.b64decode(signed_server["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(server_identity.public_bytes).verify(
                signature, HANDSHAKE_RESPONDER_DOMAIN + transcript
            )
            shared = client_ephemeral.exchange(
                X25519PublicKey.from_public_bytes(base64.b64decode(server_unsigned["ephemeral_key"], validate=True))
            )
            keys = derive_traffic_keys(shared, transcript)
            state.update({"transcript": transcript, "server_key": server_identity.public_bytes, "keys": keys})
            state["server_hello_sent"] = True
        else:
            assert kind == 4
            assert deadline == 240.0
            i2r, r2i, session_id = state["keys"]
            client_codec = SessionCodec(
                client_identity,
                state["server_key"],
                Role.INITIATOR,
                (i2r, r2i),
                session_id,
            )
            length = int.from_bytes(frame_bytes[:4], "big")
            opened = client_codec.open(Frame(4, frame_bytes[5:], length))
            assert opened.payload["transcript_sha256"] == hashlib.sha256(state["transcript"]).hexdigest()
            state["client_codec"] = client_codec

    monkeypatch.setattr(handshake_responder, "read_frame", scripted_read)
    monkeypatch.setattr(handshake_responder, "_send_frame", scripted_send)

    approval_times = []
    def approval(_candidate):
        approval_times.append(clock.now)
        # A 90 virtual-second decision, from t=90 through t=180.
        clock.now = 180.0
        return True

    trust = TrustStore(tmp_path)
    limits = Limits(
        hello_timeout_seconds=20,
        client_auth_timeout_seconds=150,
        pairing_timeout_seconds=120,
        responder_finished_timeout_seconds=150,
        handshake_timeout_seconds=300,
    )
    try:
        session = handshake_responder.run_responder(
            responder_sock,
            server_identity,
            trust,
            approval,
            cancel,
            limits,
            overall_deadline=300.0,
        )
        assert approval_times == [90.0]
        assert session.transcript_hash == hashlib.sha256(state["transcript"]).hexdigest()
        assert session.newly_approved is True
        assert session.peer.endpoint == peer_endpoint
        assert responder_sock.fileno() >= 0
        assert not (tmp_path / "trusted_peers.json").exists()
    finally:
        client_sock.close()
        responder_sock.close()
