"""Initiator side of the authenticated SPARC handshake."""

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
    make_hello,
    transcript,
    validate_hello,
)
from .handshake_types import EstablishedSession, PeerCandidate
from .records import SessionCodec


def _peer_endpoint(sock: socket.socket) -> Endpoint:
    """Return the connected socket's literal IPv4 peer endpoint."""
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


def run_initiator(
    sock: socket.socket,
    identity: Identity,
    trust: TrustStore,
    approve: Callable[[PeerCandidate], bool],
    cancel: Event,
    limits: Limits,
    overall_deadline: float,
) -> EstablishedSession:
    """Run client hello through both finished records as the TCP initiator."""
    codec = None
    try:
        if not isinstance(identity, Identity) or not isinstance(trust, TrustStore):
            raise SparcError("invalid_schema", "Handshake identity or trust store is invalid")
        if not isinstance(cancel, Event) or not isinstance(limits, Limits):
            raise SparcError("invalid_schema", "Handshake controls are invalid")

        hello_deadline = min(overall_deadline, time.monotonic() + limits.hello_timeout_seconds)
        client_hello, ephemeral_private = make_hello(identity, "client_hello")
        _send_frame(sock, pack_frame(1, canonical(client_hello)), cancel, limits, hello_deadline)
        server_frame = read_frame(sock, cancel, hello_deadline, limits)
        server_hello_received = time.monotonic()
        client_auth_deadline = min(
            overall_deadline, server_hello_received + limits.client_auth_timeout_seconds
        )
        _require_frame(server_frame, 2)
        server_signed = parse_object(server_frame.body)
        validate_hello(server_signed, signed=True)

        server_signature = base64.b64decode(server_signed["signature"], validate=True)
        server_unsigned = {key: value for key, value in server_signed.items() if key != "signature"}
        full_transcript = transcript(client_hello, server_unsigned)
        peer_key = base64.b64decode(server_unsigned["identity_key"], validate=True)
        try:
            Ed25519PublicKey.from_public_bytes(peer_key).verify(
                server_signature, HANDSHAKE_RESPONDER_DOMAIN + full_transcript
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise SparcError("handshake_signature_failed", "Peer handshake signature is invalid") from exc

        endpoint = _peer_endpoint(sock)
        peer = PeerCandidate(peer_key, hashlib.sha256(peer_key).hexdigest(), endpoint)
        trust_status = trust.check(peer.public_key, peer.endpoint)
        if trust_status == "changed":
            raise SparcError("changed_identity", "Peer identity changed at a trusted endpoint")
        if trust_status == "known":
            newly_approved = False
        elif trust_status == "unknown":
            newly_approved = _bounded_approval(peer, approve, cancel, limits, client_auth_deadline)
        else:
            raise SparcError("invalid_schema", "Trust store returned an invalid peer status")

        client_signature = identity.private_key.sign(
            HANDSHAKE_INITIATOR_DOMAIN + full_transcript
        )
        client_auth = {
            "kind": "client_auth",
            "signature": base64.b64encode(client_signature).decode("ascii"),
        }
        _send_frame(
            sock, pack_frame(3, canonical(client_auth)), cancel, limits, client_auth_deadline
        )

        try:
            server_ephemeral = X25519PublicKey.from_public_bytes(
                base64.b64decode(server_unsigned["ephemeral_key"], validate=True)
            )
            shared_secret = ephemeral_private.exchange(server_ephemeral)
        except Exception as exc:
            raise SparcError("invalid_key_exchange", "Peer key exchange could not be completed") from exc
        if len(shared_secret) != 32 or not any(shared_secret):
            raise SparcError("invalid_key_exchange", "Peer key exchange produced an invalid secret")
        i2r_key, r2i_key, session_id = derive_traffic_keys(shared_secret, full_transcript)
        codec = SessionCodec(identity, peer_key, Role.INITIATOR, (i2r_key, r2i_key), session_id)

        responder_finished_deadline = min(
            overall_deadline, time.monotonic() + limits.responder_finished_timeout_seconds
        )
        finished_frame = read_frame(sock, cancel, responder_finished_deadline, limits)
        _require_frame(finished_frame, 4)
        finished = codec.open(finished_frame)
        transcript_hash = hashlib.sha256(full_transcript).hexdigest()
        if finished.payload.get("transcript_sha256") != transcript_hash:
            raise SparcError("transcript_mismatch", "Peer finished record names a different transcript")

        initiator_finished = codec.protect(
            {"kind": "finished", "transcript_sha256": transcript_hash}, frame_type=5
        )
        _send_frame(
            sock,
            initiator_finished.frame,
            cancel,
            limits,
            responder_finished_deadline,
        )
        return EstablishedSession(codec, peer, newly_approved, transcript_hash)
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
