"""Responder side of the authenticated SPARC handshake."""

import base64
import hashlib
import ipaddress
import socket
import time
from collections.abc import Callable
from threading import Event

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from ..crypto import derive_traffic_keys
from ..encoding import canonical, parse_object
from ..identity import TrustStore
from ..models import Endpoint, Identity, Limits, Role, SparcError
from .framing import Frame, pack_frame, read_frame
from .handshake_transcript import (
    HANDSHAKE_INITIATOR_DOMAIN,
    HANDSHAKE_RESPONDER_DOMAIN,
    _bounded_approval,
    _send_frame,
    _validate_client_auth,
    make_hello,
    transcript,
    validate_hello,
)
from .handshake_types import EstablishedSession, PeerCandidate
from .records import SessionCodec


def _peer_endpoint(sock: socket.socket) -> Endpoint:
    """Return the connected client's literal IPv4 source endpoint."""
    try:
        if sock.family != socket.AF_INET:
            raise ValueError("unsupported socket family")
        address = sock.getpeername()
        if not isinstance(address, tuple) or len(address) < 2:
            raise ValueError("malformed socket address")
        ip, port = address[0], address[1]
        if not isinstance(ip, str):
            raise ValueError("non-string address")
        parsed = ipaddress.IPv4Address(ip)
        if str(parsed) != ip or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid peer endpoint")
        return Endpoint(ip, port)
    except (OSError, ValueError, TypeError) as exc:
        raise SparcError("invalid_endpoint", "Connected peer endpoint must be literal IPv4") from exc


def _require_frame(frame: Frame, kind: int) -> None:
    if frame.kind != kind:
        raise SparcError("invalid_record_type", "Handshake frame type does not match its phase")


def run_responder(
    sock: socket.socket,
    identity: Identity,
    trust: TrustStore,
    approve: Callable[[PeerCandidate], bool],
    cancel: Event,
    limits: Limits,
    overall_deadline: float,
) -> EstablishedSession:
    """Run client hello through both finished records as the TCP responder."""
    codec = None
    try:
        if not isinstance(identity, Identity) or not isinstance(trust, TrustStore):
            raise SparcError("invalid_schema", "Handshake identity or trust store is invalid")
        if not isinstance(cancel, Event) or not isinstance(limits, Limits):
            raise SparcError("invalid_schema", "Handshake controls are invalid")

        hello_deadline = min(overall_deadline, time.monotonic() + limits.hello_timeout_seconds)
        client_frame = read_frame(sock, cancel, hello_deadline, limits)
        _require_frame(client_frame, 1)
        client_hello = parse_object(client_frame.body)
        validate_hello(client_hello, signed=False)
        if client_hello.get("kind") != "client_hello":
            raise SparcError("invalid_schema", "Expected a client hello")

        server_hello, ephemeral_private = make_hello(identity, "server_hello")
        full_transcript = transcript(client_hello, server_hello)
        signature = identity.private_key.sign(HANDSHAKE_RESPONDER_DOMAIN + full_transcript)
        signed_server_hello = {
            **server_hello,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        _send_frame(
            sock,
            pack_frame(2, canonical(signed_server_hello)),
            cancel,
            limits,
            hello_deadline,
        )
        server_hello_sent = time.monotonic()
        client_auth_deadline = min(
            overall_deadline, server_hello_sent + limits.client_auth_timeout_seconds
        )

        auth_frame = read_frame(sock, cancel, client_auth_deadline, limits)
        _require_frame(auth_frame, 3)
        client_auth_received = time.monotonic()
        responder_finished_deadline = min(
            overall_deadline,
            client_auth_received + limits.responder_finished_timeout_seconds,
        )
        client_auth = parse_object(auth_frame.body)
        _validate_client_auth(client_auth)
        client_key = base64.b64decode(client_hello["identity_key"], validate=True)
        client_signature = base64.b64decode(client_auth["signature"], validate=True)
        try:
            Ed25519PublicKey.from_public_bytes(client_key).verify(
                client_signature, HANDSHAKE_INITIATOR_DOMAIN + full_transcript
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise SparcError("handshake_signature_failed", "Peer handshake signature is invalid") from exc

        endpoint = _peer_endpoint(sock)
        peer = PeerCandidate(client_key, hashlib.sha256(client_key).hexdigest(), endpoint)
        trust_status = trust.check(peer.public_key, peer.endpoint)
        if trust_status == "changed":
            raise SparcError("changed_identity", "Peer identity changed at a trusted endpoint")
        if trust_status == "known":
            newly_approved = False
        elif trust_status == "unknown":
            newly_approved = _bounded_approval(
                peer, approve, cancel, limits, responder_finished_deadline
            )
        else:
            raise SparcError("invalid_schema", "Trust store returned an invalid peer status")

        try:
            peer_ephemeral = X25519PublicKey.from_public_bytes(
                base64.b64decode(client_hello["ephemeral_key"], validate=True)
            )
            shared_secret = ephemeral_private.exchange(peer_ephemeral)
        except Exception as exc:
            raise SparcError("invalid_key_exchange", "Peer key exchange could not be completed") from exc
        if len(shared_secret) != 32 or not any(shared_secret):
            raise SparcError("invalid_key_exchange", "Peer key exchange produced an invalid secret")

        i2r_key, r2i_key, session_id = derive_traffic_keys(shared_secret, full_transcript)
        codec = SessionCodec(identity, client_key, Role.RESPONDER, (i2r_key, r2i_key), session_id)
        transcript_hash = hashlib.sha256(full_transcript).hexdigest()
        responder_finished = codec.protect(
            {"kind": "finished", "transcript_sha256": transcript_hash}, frame_type=4
        )
        _send_frame(
            sock,
            responder_finished.frame,
            cancel,
            limits,
            responder_finished_deadline,
        )

        client_finished_deadline = min(
            overall_deadline, time.monotonic() + limits.client_finished_timeout_seconds
        )
        finished_frame = read_frame(sock, cancel, client_finished_deadline, limits)
        _require_frame(finished_frame, 5)
        finished = codec.open(finished_frame)
        if finished.payload.get("transcript_sha256") != transcript_hash:
            raise SparcError("transcript_mismatch", "Peer finished record names a different transcript")
        return EstablishedSession(codec, peer, newly_approved, transcript_hash)
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
