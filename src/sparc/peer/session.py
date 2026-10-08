"""Writer and lifecycle owner for one established peer session."""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from ..models import Limits, OpenedRecord, ProtectedRecord, ServiceEvent, SparcError
from ..protocol.framing import read_frame


@dataclass(frozen=True)
class SessionHooks:
    """Callbacks supplied by the service that owns this session."""

    on_payload: Callable[[OpenedRecord], None]
    on_closed: Callable[[SparcError], None]
    emit: Callable[[ServiceEvent], None]
    on_written: Callable[[dict, ProtectedRecord], None] | None = None
    on_poll: Callable[[], None] | None = None


class ActiveSession:
    """Own the application writer and finite cancellation lifecycle for a session."""

    def __init__(self, sock, established, hooks: SessionHooks, limits: Limits,
                 *, cancel: threading.Event | None = None) -> None:
        if not isinstance(hooks, SessionHooks):
            raise SparcError("invalid_schema", "Session callbacks are invalid")
        if not isinstance(limits, Limits):
            raise SparcError("invalid_schema", "Session limits are invalid")
        if cancel is not None and not isinstance(cancel, threading.Event):
            raise SparcError("invalid_schema", "Session cancellation event is invalid")
        codec = getattr(established, "codec", None)
        session_id = getattr(codec, "session_id", None)
        if not isinstance(session_id, bytes):
            raise SparcError("invalid_schema", "Established session is invalid")
        if not callable(getattr(sock, "sendall", None)):
            raise SparcError("invalid_schema", "Session socket is invalid")

        self._sock = sock
        self._codec = codec
        self._hooks = hooks
        self._limits = limits
        self._session_id = session_id
        self._outbound: deque[dict] = deque()
        self._control: deque[dict] = deque()
        self._cancel = cancel if cancel is not None else threading.Event()
        self._state_lock = threading.Lock()
        self._queue_condition = threading.Condition()
        self._terminal = False
        self._worker: threading.Thread | None = None
        self._reader_worker: threading.Thread | None = None
        self._callback_lock = threading.RLock()

    @property
    def session_id(self) -> bytes:
        return self._session_id

    def start(self) -> None:
        """Start the single writer and reader for this established session."""
        failure = None
        failure_cause = None
        with self._state_lock:
            if self._terminal:
                return
            if self._worker is not None or self._reader_worker is not None:
                return
            writer = threading.Thread(
                target=self._writer_loop,
                name="sparc-session-writer",
                daemon=True,
            )
            reader = threading.Thread(
                target=self._reader_loop,
                name="sparc-session-reader",
                daemon=True,
            )
            self._worker = writer
            self._reader_worker = reader
            try:
                writer.start()
                reader.start()
            except Exception as exc:
                failure = SparcError("session_unusable", "Could not start session workers")
                failure_cause = exc
        if failure is not None:
            self._terminate(failure)
            raise failure from failure_cause

    def enqueue(self, payload: dict, control: bool = False) -> None:
        if not isinstance(payload, dict) or type(control) is not bool:
            raise SparcError("invalid_schema", "Outbound session payload is invalid")
        with self._queue_condition:
            if not control:
                if self._cancel.is_set():
                    raise self._cancelled_error()
                if len(self._outbound) >= self._limits.outbound_queue:
                    raise SparcError("busy", "Outbound session queue is full")
                self._outbound.append(payload)
                self._queue_condition.notify()
                return

            while len(self._control) >= self._limits.control_queue:
                if self._cancel.is_set():
                    raise self._cancelled_error()
                self._queue_condition.wait(timeout=self._limits.cancel_poll_seconds)
            if self._cancel.is_set():
                raise self._cancelled_error()
            self._control.append(payload)
            self._queue_condition.notify()

    def close(self) -> None:
        """Request terminal cancellation and notify the owner once."""
        self._terminate(SparcError("operation_cancelled", "Session was closed"))

    def join(self, timeout: float = 2) -> bool:
        """Wait at most ``timeout`` seconds for the writer to finish."""
        deadline = time.monotonic() + max(0.0, timeout)
        complete = True
        for worker in (self._worker, self._reader_worker):
            if worker is None or not worker.is_alive():
                continue
            if worker is threading.current_thread():
                complete = False
                continue
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
            complete = complete and not worker.is_alive()
        return complete

    @staticmethod
    def _cancelled_error() -> SparcError:
        return SparcError("operation_cancelled", "Session is closing")

    def _next_payload(self) -> dict | None:
        with self._queue_condition:
            if self._cancel.is_set():
                return None
            if self._control:
                payload = self._control.popleft()
                self._queue_condition.notify_all()
                return payload
            if self._outbound:
                payload = self._outbound.popleft()
                self._queue_condition.notify_all()
                return payload
            self._queue_condition.wait(timeout=self._limits.cancel_poll_seconds)
            return None

    def _writer_loop(self) -> None:
        while not self._cancel.is_set():
            payload = self._next_payload()
            if self._cancel.is_set():
                return
            if payload is None:
                if not self._run_poll():
                    return
                continue
            try:
                protected = self._codec.protect(payload)
            except SparcError as error:
                self._terminate(error)
                return
            except Exception as exc:
                self._terminate(SparcError("session_unusable", "Could not protect an outbound record"))
                return
            if self._cancel.is_set():
                return
            if self._hooks.on_written is not None:
                try:
                    self._hooks.on_written(payload, protected)
                except SparcError as error:
                    self._terminate(error)
                    return
                except Exception:
                    self._terminate(SparcError("session_unusable", "Could not record an outbound frame"))
                    return
            if self._cancel.is_set():
                return
            try:
                self._sock.sendall(protected.frame)
            except Exception as exc:
                self._terminate(SparcError("tcp_loss", "Socket failed while writing a record"))
                return
            if not self._run_poll():
                return

    def _reader_loop(self) -> None:
        while not self._cancel.is_set():
            try:
                frame = read_frame(self._sock, self._cancel, None, self._limits)
                opened = self._codec.open(frame)
                if self._cancel.is_set():
                    return
                with self._callback_lock:
                    if not self._cancel.is_set():
                        self._hooks.on_payload(opened)
            except SparcError as error:
                if self._cancel.is_set() or error.code == "canceled":
                    return
                self._terminate(error)
                return
            except Exception:
                self._terminate(SparcError("session_unusable", "Could not process an incoming record"))
                return

    def _run_poll(self) -> bool:
        if self._hooks.on_poll is None:
            return not self._cancel.is_set()
        try:
            self._hooks.on_poll()
        except SparcError as error:
            self._terminate(error)
            return False
        except Exception:
            self._terminate(SparcError("session_unusable", "Session polling failed"))
            return False
        return not self._cancel.is_set()

    def _terminate(self, error: SparcError) -> None:
        """Run the one terminal transition, with hooks outside the state lock."""
        with self._state_lock:
            if self._terminal:
                return
            self._terminal = True
            self._cancel.set()

        with self._queue_condition:
            self._queue_condition.notify_all()

        self._close_transport()
        self._call_closed(error)

    def _close_transport(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def _call_closed(self, error: SparcError) -> None:
        try:
            with self._callback_lock:
                self._hooks.on_closed(error)
        except Exception:
            # A broken service hook cannot revive or recursively close this session.
            self._cancel.set()
