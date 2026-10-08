"""Bounded connection-attempt rate limiting for peer listeners."""

from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Callable

from ..models import Limits


class ConnectionLimiter:
    """Apply per-source and global rolling-window connection limits."""

    def __init__(self, clock: Callable[[], float], *, limits: Limits = Limits()) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        self._clock = clock
        self._limits = limits
        self._global: deque[float] = deque(maxlen=limits.connections_global)
        self._sources: dict[str, deque[float]] = {}
        self._lock = Lock()

    def _expire(self, queue: deque[float], cutoff: float) -> None:
        while queue and queue[0] <= cutoff:
            queue.popleft()

    def allow(self, ip: str) -> bool:
        if not isinstance(ip, str):
            raise TypeError("ip must be a string")

        with self._lock:
            # Serialize clock sampling with deque mutations so even a clock
            # that advances between competing callers cannot append out of
            # order.
            now = self._clock()
            cutoff = now - self._limits.connection_window_seconds
            self._expire(self._global, cutoff)
            for source, attempts in tuple(self._sources.items()):
                self._expire(attempts, cutoff)
                if not attempts:
                    del self._sources[source]

            attempts = self._sources.get(ip)
            if attempts is None:
                if len(self._sources) >= self._limits.source_buckets:
                    # The source table cannot grow. Still account for this
                    # attempt globally, as every connection attempt is counted.
                    self._global.append(now)
                    return False
                attempts = deque(maxlen=self._limits.connections_per_source)
                self._sources[ip] = attempts

            accepted = (
                len(attempts) < self._limits.connections_per_source
                and len(self._global) < self._limits.connections_global
            )
            # Rejected attempts count too. The bounded deques retain only the
            # most recent quota-sized set of timestamps.
            attempts.append(now)
            self._global.append(now)
            return accepted


class RecordBucket:
    """A token bucket for application records in one direction of a session."""

    def __init__(self, clock: Callable[[], float], *, limits: Limits = Limits()) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        self._clock = clock
        self._rate = float(limits.record_rate)
        self._capacity = float(limits.record_burst)
        self._tokens = self._capacity
        self._updated = clock()
        self._lock = Lock()

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._updated = max(self._updated, now)

    def allow(self) -> bool:
        with self._lock:
            self._refill(self._clock())
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    def wait(self, cancel, *, maintenance: Callable[[], bool] | None = None) -> bool:
        """Wait for a token, optionally running bounded caller maintenance."""
        if not callable(getattr(cancel, "wait", None)) or not callable(
            getattr(cancel, "is_set", None)
        ):
            raise TypeError("cancel must be an event-like object")
        if maintenance is not None and not callable(maintenance):
            raise TypeError("maintenance must be callable")
        while True:
            if cancel.is_set():
                return False
            if maintenance is not None and not maintenance():
                return False
            if cancel.is_set():
                return False
            with self._lock:
                self._refill(self._clock())
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return not cancel.is_set()
                delay = (1.0 - self._tokens) / self._rate
                if maintenance is not None:
                    delay = min(delay, 1.0)
            if cancel.wait(delay):
                return False


class ReconnectPolicy:
    """Return the finite retry schedule for eligible established-session loss."""

    _ELIGIBLE = frozenset({"tcp_loss", "delivery_timeout", "peer_inactivity"})

    def __init__(self, clock: Callable[[], float], *, limits: Limits = Limits()) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        self._clock = clock
        self._limits = limits

    def delays(self, error_code: str, explicit_stop: bool) -> tuple[float, ...]:
        if not isinstance(error_code, str):
            raise TypeError("error_code must be a string")
        if not error_code:
            raise ValueError("error_code must be a nonempty category")
        if type(explicit_stop) is not bool:
            raise TypeError("explicit_stop must be a boolean")
        if explicit_stop or error_code not in self._ELIGIBLE:
            return ()
        return self._limits.reconnect_delays
