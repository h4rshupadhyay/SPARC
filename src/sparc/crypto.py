"""SPARC session key derivation and authenticated context construction."""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .encoding import canonical
from .models import SparcError


_SESSION_DOMAIN = b"SPARC-v1 session\x00"
_TRAFFIC_DOMAIN = b"SPARC-v1 traffic\x00"
_RECORD_DOMAIN = b"SPARC-v1 record\x00"
_MESSAGE_DOMAIN = b"SPARC-v1 message\x00"
_MIN_ENCRYPTED_LENGTH = 58
_MAX_FRAME_LENGTH = 128 * 1024
_UINT32_MAX = 2**32 - 1
_UINT64_MAX = 2**64 - 1


def derive_traffic_keys(secret: bytes, transcript: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive initiator→responder and responder→initiator keys plus session ID."""
    if not isinstance(secret, bytes) or len(secret) != 32 or not any(secret):
        raise SparcError("invalid_key_exchange", "Shared secret must be a nonzero 32-byte value")
    if not isinstance(transcript, bytes) or not transcript:
        raise SparcError("invalid_key_exchange", "Handshake transcript must be nonempty bytes")

    session_id = hashlib.sha256(_SESSION_DOMAIN + transcript).digest()
    traffic = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=_TRAFFIC_DOMAIN + session_id,
    ).derive(secret)
    return traffic[:32], traffic[32:], session_id


def _uint(value: object, maximum: int, field: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise SparcError("invalid_record_type", f"{field} is outside its permitted integer range")
    return value


def _session_id(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise SparcError("session_mismatch", "Session ID must contain exactly 32 bytes")
    return value


def _direction(value: object) -> int:
    if type(value) is not int or value not in (0, 1):
        raise SparcError("invalid_record_type", "Direction must be zero or one")
    return value


def record_aad(kind: int, session_id: bytes, direction: int, sequence: int, length: int) -> bytes:
    """Build the exact AES-GCM associated data for an encrypted frame."""
    if type(kind) is not int or kind not in (4, 5, 6):
        raise SparcError("invalid_record_type", "AAD requires an encrypted frame type")
    sid = _session_id(session_id)
    direction_byte = _direction(direction)
    sequence_value = _uint(sequence, _UINT64_MAX, "sequence")
    length_value = _uint(length, _UINT32_MAX, "frame length")
    if not _MIN_ENCRYPTED_LENGTH <= length_value <= _MAX_FRAME_LENGTH:
        raise SparcError("malformed_frame", "Encrypted frame length is outside the protocol bounds")
    return (
        _RECORD_DOMAIN
        + bytes((kind,))
        + sid
        + bytes((direction_byte,))
        + sequence_value.to_bytes(8, "big")
        + length_value.to_bytes(4, "big")
    )


def message_context(session_id: bytes, direction: int, sequence: int, projection: dict) -> bytes:
    """Build the exact signed message context for a canonical projection."""
    sid = _session_id(session_id)
    direction_byte = _direction(direction)
    sequence_value = _uint(sequence, _UINT64_MAX, "sequence")
    if not isinstance(projection, dict):
        raise SparcError("invalid_schema", "Signing projection must be an object")
    return (
        _MESSAGE_DOMAIN
        + sid
        + bytes((direction_byte,))
        + sequence_value.to_bytes(8, "big")
        + canonical(projection)
    )
