"""Immutable value objects used at the authenticated handshake boundary."""

from dataclasses import dataclass

from ..models import Endpoint
from .records import SessionCodec


@dataclass(frozen=True)
class PeerCandidate:
    """An authenticated peer identity and its connected IPv4 endpoint."""

    public_key: bytes
    fingerprint: str
    endpoint: Endpoint


@dataclass(frozen=True)
class EstablishedSession:
    """A session whose handshake and finished-record exchange completed."""

    codec: SessionCodec
    peer: PeerCandidate
    newly_approved: bool
    transcript_hash: str
