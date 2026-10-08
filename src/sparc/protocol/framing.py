"""Bounded, cancellation-aware TCP frame encoding and reading."""

from dataclasses import dataclass
import socket
import struct
import time
from threading import Event

from ..models import Limits, SparcError


_PREFIX = struct.Struct(">I")
_MAX_FRAME_LENGTH = 128 * 1024
_MAX_HANDSHAKE_LENGTH = 8 * 1024
_VALID_KINDS = frozenset(range(1, 7))
_JSON_KINDS = frozenset((1, 2, 3))
_ENCRYPTED_KINDS = frozenset((4, 5, 6))
_MIN_ENCRYPTED_LENGTH = 58  # type + session ID + sequence + ciphertext + GCM tag


@dataclass(frozen=True)
class Frame:
    """A decoded frame; length is N and excludes the four-byte prefix."""

    kind: int
    body: bytes
    length: int


def _validate_kind(kind: int) -> None:
    if type(kind) is not int or kind not in _VALID_KINDS:
        raise SparcError("malformed_frame", "Frame type is outside the supported range")


def _validate_length(kind: int, length: int, limits: Limits | None = None) -> None:
    """Validate N, before any body bytes are read or allocated."""
    _validate_kind(kind)
    max_frame = limits.frame_bytes if limits is not None else _MAX_FRAME_LENGTH
    max_handshake = limits.handshake_json_bytes if limits is not None else _MAX_HANDSHAKE_LENGTH
    if length < 1 or length > min(max_frame, _MAX_FRAME_LENGTH):
        raise SparcError("malformed_frame", "Frame length is outside the permitted range")
    if kind in _JSON_KINDS and length > min(max_handshake, _MAX_HANDSHAKE_LENGTH):
        raise SparcError("malformed_frame", "Handshake frame exceeds the JSON size limit")
    if kind in _ENCRYPTED_KINDS and length < _MIN_ENCRYPTED_LENGTH:
        raise SparcError("malformed_frame", "Encrypted frame is too short to contain a record")


def pack_frame(kind: int, body: bytes) -> bytes:
    """Encode one frame using the protocol's fixed production limits."""
    _validate_kind(kind)
    if not isinstance(body, bytes):
        raise TypeError("frame body must be bytes")
    length = 1 + len(body)
    _validate_length(kind, length)
    return _PREFIX.pack(length) + bytes((kind,)) + body


def _read_exact(sock: socket.socket, size: int, cancel: Event,
                deadline: float | None, frame_deadline: float | None,
                limits: Limits) -> bytes:
    """Read exactly size bytes, checking cancellation and both deadlines."""
    chunks = bytearray()
    poll_interval = min(float(limits.cancel_poll_seconds), 1.0)
    while len(chunks) < size:
        if cancel.is_set():
            raise SparcError("canceled", "Frame read was canceled")

        now = time.monotonic()
        if deadline is not None and now >= deadline:
            raise SparcError("handshake_timeout", "Handshake deadline expired while reading a frame")
        if frame_deadline is not None and now >= frame_deadline:
            raise SparcError("frame_timeout", "Incomplete frame exceeded its deadline")

        wait = poll_interval
        if deadline is not None:
            wait = min(wait, max(0.0, deadline - now))
        if frame_deadline is not None:
            wait = min(wait, max(0.0, frame_deadline - now))
        # Do not let settimeout(0) turn into nonblocking behavior at the boundary.
        wait = max(wait, 0.001)
        try:
            sock.settimeout(wait)
            part = sock.recv(size - len(chunks))
        except (socket.timeout, TimeoutError):
            continue
        except OSError as exc:
            raise SparcError("tcp_loss", "Socket failed while reading a frame") from exc
        if not part:
            if chunks:
                raise SparcError("malformed_frame", "Connection closed during an incomplete frame")
            raise SparcError("tcp_loss", "Connection closed while reading a frame")
        chunks.extend(part)
    return bytes(chunks)


def read_frame(sock: socket.socket, cancel: Event, deadline: float | None,
               limits: Limits) -> Frame:
    """Read and validate one bounded frame from a connected socket.

    An incomplete-frame deadline begins when the first prefix byte arrives. An
    optional handshake deadline applies even while the connection is otherwise
    idle and always takes precedence when it expires.
    """
    if not isinstance(limits, Limits):
        raise TypeError("limits must be a Limits instance")
    if not isinstance(cancel, Event):
        raise TypeError("cancel must be a threading.Event")
    try:
        prior_timeout = sock.gettimeout()
    except OSError as exc:
        raise SparcError("tcp_loss", "Socket is unavailable for frame reading") from exc

    poll_interval = min(float(limits.cancel_poll_seconds), 1.0)
    prefix = bytearray()
    frame_deadline = None
    try:
        # The first prefix byte is special: before it arrives only a supplied
        # handshake deadline can expire. Subsequent prefix/body reads are bounded.
        while len(prefix) < _PREFIX.size:
            if cancel.is_set():
                raise SparcError("canceled", "Frame read was canceled")
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise SparcError("handshake_timeout", "Handshake deadline expired while waiting for a frame")
            if frame_deadline is not None and now >= frame_deadline:
                raise SparcError("frame_timeout", "Incomplete frame exceeded its deadline")
            wait = poll_interval
            if deadline is not None:
                wait = min(wait, max(0.001, deadline - now))
            if frame_deadline is not None:
                wait = min(wait, max(0.001, frame_deadline - now))
            try:
                sock.settimeout(wait)
                part = sock.recv(_PREFIX.size - len(prefix))
            except (socket.timeout, TimeoutError):
                continue
            except OSError as exc:
                raise SparcError("tcp_loss", "Socket failed while reading a frame prefix") from exc
            if not part:
                if prefix:
                    raise SparcError("malformed_frame", "Connection closed during the frame prefix")
                raise SparcError("tcp_loss", "Connection closed while waiting for a frame")
            if frame_deadline is None:
                frame_deadline = time.monotonic() + limits.frame_timeout_seconds
            prefix.extend(part)

        length = _PREFIX.unpack(prefix)[0]
        # N must be checked against the absolute protocol limit before even
        # reading the type byte; otherwise an oversized frame can cause work.
        if length < 1 or length > min(limits.frame_bytes, _MAX_FRAME_LENGTH):
            raise SparcError("malformed_frame", "Frame length is outside the permitted range")
        header = _read_exact(sock, 1, cancel, deadline, frame_deadline, limits)
        kind = header[0]
        _validate_length(kind, length, limits)
        body = _read_exact(sock, length - 1, cancel, deadline, frame_deadline, limits)
        return Frame(kind=kind, body=body, length=length)
    finally:
        try:
            sock.settimeout(prior_timeout)
        except OSError:
            pass
