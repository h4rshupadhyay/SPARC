"""Bounded ping/pong and inactivity tracking for one authenticated session."""

from __future__ import annotations

import re
import secrets
import threading
from typing import Callable

from ..models import Limits, SparcError


_PING_ID = re.compile(r"[0-9a-f]{32}\Z")


class Liveness:
    """Track outgoing idleness, valid incoming activity, and one pending ping."""

    def __init__(self, clock: Callable[[], float], *, limits: Limits = Limits()) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        self._clock = clock
        self._limits = limits
        self._lock = threading.Lock()
        initial = clock()
        self._last_sent = initial
        self._last_received = initial
        self._pending_ping: str | None = None
        self._loss_elapsed_ns: int | None = None

    @property
    def loss_elapsed_ns(self) -> int | None:
        with self._lock:
            return self._loss_elapsed_ns

    def sent(self) -> None:
        with self._lock:
            self._last_sent = self._clock()

    def received(self) -> None:
        with self._lock:
            self._last_received = self._clock()

    def tick(self, *, allow_ping: bool = True) -> tuple[dict | None, bool]:
        if type(allow_ping) is not bool:
            raise TypeError("allow_ping must be a boolean")
        with self._lock:
            now = self._clock()
            if self._loss_elapsed_ns is not None:
                return None, True
            silence = max(0.0, now - self._last_received)
            if silence >= self._limits.peer_timeout_seconds:
                self._loss_elapsed_ns = max(0, int(silence * 1_000_000_000))
                return None, True
            if (allow_ping and self._pending_ping is None
                    and now - self._last_sent >= self._limits.heartbeat_seconds):
                ping_id = secrets.token_hex(16)
                self._pending_ping = ping_id
                return {"kind": "ping", "ping_id": ping_id}, False
            return None, False

    def accept_pong(self, ping_id: str) -> None:
        if not isinstance(ping_id, str) or _PING_ID.fullmatch(ping_id) is None:
            raise SparcError("invalid_record", "Pong ID is invalid")
        with self._lock:
            if self._pending_ping != ping_id:
                raise SparcError("invalid_record", "Pong does not match an outstanding ping")
            self._pending_ping = None
