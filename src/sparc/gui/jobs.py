"""Bounded background jobs whose callbacks are dispatched on the Tk thread."""

from __future__ import annotations

import queue
import threading
from typing import Callable


_QUEUE_SIZE = 64
_POLL_MS = 100
_BATCH_SIZE = 64


class JobController:
    """Run one cancellable job and deliver its events through ``root.after``."""

    def __init__(self, root, on_result: Callable[[str, object], None]) -> None:
        self._root = root
        self._on_result = on_result
        self._queue: queue.Queue[tuple[int, str, object]] = queue.Queue(_QUEUE_SIZE)
        self._generation = 0
        self._worker: threading.Thread | None = None
        self._cancel_event: threading.Event | None = None
        self._after_id = None
        self._closed = False
        self._lock = threading.Lock()

    def start(self, work: Callable[[threading.Event, Callable[[str, object], None]], object]) -> None:
        """Start work, rejecting a second run while the prior worker is active."""
        with self._lock:
            if self._closed:
                raise RuntimeError("job controller is closed")
            if self._worker is not None and self._worker.is_alive():
                raise RuntimeError("a job is already active")
            self._generation += 1
            generation = self._generation
            cancel = threading.Event()
            self._cancel_event = cancel
            if self._after_id is None:
                self._after_id = self._root.after(_POLL_MS, self._poll)

            def emit(kind: str, value: object) -> None:
                item = (generation, kind, value)
                while not cancel.is_set():
                    try:
                        self._queue.put(item, timeout=0.05)
                        return
                    except queue.Full:
                        continue

            def run() -> None:
                try:
                    result = work(cancel, emit)
                except BaseException as exc:
                    emit("error", exc)
                else:
                    emit("result", result)

            self._worker = threading.Thread(target=run, name="sparc-job", daemon=True)
            self._worker.start()

    def _poll(self) -> None:
        self._after_id = None
        if self._closed:
            return
        for _ in range(_BATCH_SIZE):
            try:
                generation, kind, value = self._queue.get_nowait()
            except queue.Empty:
                break
            if generation == self._generation and not self._closed:
                self._on_result(kind, value)
        if not self._closed:
            self._after_id = self._root.after(_POLL_MS, self._poll)

    def cancel(self) -> None:
        """Invalidate queued events and request cooperative worker cancellation."""
        with self._lock:
            self._generation += 1
            cancel = self._cancel_event
            worker = self._worker
        if cancel is not None:
            cancel.set()
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2.0)

    def close(self) -> None:
        """Cancel active work, stop polling, and ignore all later results."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._generation += 1
            cancel = self._cancel_event
            worker = self._worker
            after_id = self._after_id
            self._after_id = None
        if cancel is not None:
            cancel.set()
        if after_id is not None:
            try:
                self._root.after_cancel(after_id)
            except Exception:
                pass
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2.0)
