"""Generation-bound, bounded user approval requests for authenticated peers."""

from __future__ import annotations

import math
import secrets
import threading
import time
from dataclasses import dataclass
from threading import Event
from typing import Callable

from ..models import Endpoint, ServiceEvent, SparcError
from ..protocol.handshake_types import PeerCandidate


@dataclass
class _PendingApproval:
    candidate: PeerCandidate
    own_fingerprint: str
    generation: int
    cancel: Event
    approved: bool | None = None


class PairingRequests:
    """Coordinate immutable candidate snapshots with one exact request ID."""

    def __init__(self, emit: Callable[[ServiceEvent, Event], None],
                 poll_seconds: float = 0.05) -> None:
        if not callable(emit):
            raise SparcError("invalid_schema", "Pairing event callback is invalid")
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)) or poll_seconds <= 0:
            raise SparcError("invalid_schema", "Pairing poll interval must be positive")
        self._emit = emit
        self._poll_seconds = float(poll_seconds)
        self._condition = threading.Condition()
        self._pending: dict[str, _PendingApproval] = {}
        self._closed = False

    def ask(self, candidate: PeerCandidate, own_fingerprint: str, generation: int,
            cancel: Event, timeout: float) -> bool:
        if not isinstance(candidate, PeerCandidate) or not isinstance(candidate.endpoint, Endpoint):
            raise SparcError("invalid_schema", "Pairing candidate is invalid")
        if not isinstance(own_fingerprint, str) or type(generation) is not int or generation < 0:
            raise SparcError("invalid_schema", "Pairing request identity is invalid")
        if not isinstance(cancel, Event):
            raise SparcError("invalid_schema", "Pairing cancellation event is invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise SparcError("invalid_schema", "Pairing timeout must be finite and positive")

        request_id = secrets.token_hex(16)
        pending = _PendingApproval(candidate, own_fingerprint, generation, cancel)
        with self._condition:
            if self._closed or cancel.is_set():
                raise SparcError("operation_cancelled", "Pairing request was canceled")
            self._pending[request_id] = pending

        event = ServiceEvent(
            "pairing_request",
            {
                "request_id": request_id,
                "candidate_fingerprint": candidate.fingerprint,
                "own_fingerprint": own_fingerprint,
                "endpoint": {"ip": candidate.endpoint.ip, "port": candidate.endpoint.port},
            },
        )
        try:
            self._emit(event, cancel)
            deadline = time.monotonic() + timeout
            with self._condition:
                while True:
                    if self._closed or cancel.is_set():
                        raise SparcError("operation_cancelled", "Pairing request was canceled")
                    if pending.approved is not None:
                        return pending.approved
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SparcError("pairing_timeout", "Peer approval deadline expired")
                    self._condition.wait(timeout=min(remaining, self._poll_seconds))
        finally:
            with self._condition:
                if self._pending.get(request_id) is pending:
                    del self._pending[request_id]
                self._condition.notify_all()

    def respond(self, request_id: str, approved: bool, generation: int) -> None:
        if not isinstance(request_id, str) or type(approved) is not bool or type(generation) is not int:
            raise SparcError("invalid_schema", "Pairing response is invalid")
        with self._condition:
            pending = self._pending.get(request_id)
            if (
                self._closed
                or pending is None
                or pending.generation != generation
                or pending.cancel.is_set()
            ):
                raise SparcError("pairing_request_unavailable", "Pairing request is no longer active")
            if pending.approved is not None:
                raise SparcError("pairing_request_unavailable", "Pairing request already has a response")
            pending.approved = approved
            self._condition.notify_all()

    def cancel_all(self) -> None:
        with self._condition:
            self._closed = True
            for pending in self._pending.values():
                pending.cancel.set()
            self._condition.notify_all()
