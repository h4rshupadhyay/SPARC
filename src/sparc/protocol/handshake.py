"""Public dispatcher for authenticated SPARC initiator/responder handshakes."""

import socket
import time
from collections.abc import Callable
from threading import Event

from ..identity import TrustStore
from ..models import Identity, Limits, Role, SparcError
from .handshake_initiator import run_initiator
from .handshake_responder import run_responder
from .handshake_types import EstablishedSession, PeerCandidate


def perform_handshake(
    sock: socket.socket,
    role: Role,
    identity: Identity,
    trust: TrustStore,
    approve: Callable[[PeerCandidate], bool],
    cancel: Event,
    limits: Limits,
) -> EstablishedSession:
    """Dispatch one handshake and establish its single overall deadline."""
    try:
        if not isinstance(sock, socket.socket):
            raise SparcError("invalid_schema", "Handshake socket is invalid")
        if not isinstance(role, Role):
            raise SparcError("invalid_schema", "Handshake role is invalid")
        if not isinstance(identity, Identity) or not isinstance(trust, TrustStore):
            raise SparcError("invalid_schema", "Handshake identity or trust store is invalid")
        if not callable(approve):
            raise SparcError("invalid_schema", "Peer approval callback is invalid")
        if not isinstance(cancel, Event) or not isinstance(limits, Limits):
            raise SparcError("invalid_schema", "Handshake controls are invalid")

        overall_deadline = time.monotonic() + limits.handshake_timeout_seconds
        if role is Role.INITIATOR:
            return run_initiator(sock, identity, trust, approve, cancel, limits, overall_deadline)
        if role is Role.RESPONDER:
            return run_responder(sock, identity, trust, approve, cancel, limits, overall_deadline)
        raise SparcError("invalid_schema", "Handshake role is unsupported")
    except BaseException:
        try:
            sock.close()
        except (AttributeError, OSError):
            pass
        raise


__all__ = ["perform_handshake", "PeerCandidate", "EstablishedSession"]
