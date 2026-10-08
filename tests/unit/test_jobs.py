"""C7a contracts for bounded, main-thread-dispatched background jobs.

Worker events use ``result`` for a returned value and ``error`` for an
uncaught worker exception. Work may emit named progress events through emit.
"""

from __future__ import annotations

import threading
import time

import pytest

from sparc.gui.jobs import JobController


class FakeRoot:
    """A deterministic Tk ``after`` scheduler driven by the test thread."""

    def __init__(self):
        self.owner = threading.get_ident()
        self.callbacks = {}
        self.next_id = 0
        self.cancelled = []

    def after(self, delay, callback):
        assert threading.get_ident() == self.owner
        self.next_id += 1
        self.callbacks[self.next_id] = (delay, callback)
        return self.next_id

    def after_cancel(self, callback_id):
        assert threading.get_ident() == self.owner
        self.cancelled.append(callback_id)
        self.callbacks.pop(callback_id, None)

    def run_one(self):
        if self.callbacks:
            callback_id = next(iter(self.callbacks))
            _delay, callback = self.callbacks.pop(callback_id)
            callback()


def _wait(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert predicate(), "worker did not reach expected state"


def test_jobs_one_active_and_queue_bound_64():
    root = FakeRoot()
    delivered = []
    jobs = JobController(root, lambda kind, value: delivered.append((kind, value)))
    release = threading.Event()
    entered = threading.Event()

    def held_work(cancel, emit):
        entered.set()
        release.wait(1)
        return "first"

    jobs.start(held_work)
    assert entered.wait(1)
    with pytest.raises((RuntimeError, ValueError)):
        jobs.start(lambda cancel, emit: "second")
    release.set()
    _wait(lambda: bool(root.callbacks))
    deadline = time.monotonic() + 1.0
    while not delivered and time.monotonic() < deadline:
        root.run_one()
        time.sleep(0.005)
    assert delivered == [("result", "first")]

    # 64 events fit; the 65th must wait with bounded, cancel-aware backpressure.
    attempted = threading.Event()
    finished = threading.Event()

    def flood_work(cancel, emit):
        for index in range(65):
            if index == 64:
                attempted.set()
            emit("progress", index)
        finished.set()

    jobs.start(flood_work)
    assert attempted.wait(1)
    time.sleep(0.05)
    assert not finished.is_set()
    jobs.close()
    assert finished.wait(1), "close must wake a worker blocked on a full event queue"
    assert len(delivered) <= 65


def test_cancel_discards_stale_result_generation():
    root = FakeRoot()
    delivered = []
    jobs = JobController(root, lambda kind, value: delivered.append((kind, value)))
    release = threading.Event()
    entered = threading.Event()

    def work(cancel, emit):
        entered.set()
        release.wait(1)
        return "stale"

    jobs.start(work)
    assert entered.wait(1)
    jobs.cancel()
    release.set()
    jobs.close()
    while root.callbacks:
        root.run_one()
    assert delivered == []
    jobs.close()


def test_completed_jobs_keep_one_poll_and_close_removes_it():
    root = FakeRoot()
    delivered = []
    jobs = JobController(root, lambda kind, value: delivered.append((kind, value)))

    for value in ("first", "second"):
        completed = threading.Event()

        def work(cancel, emit, result=value):
            completed.set()
            return result

        jobs.start(work)
        assert completed.wait(1)
        deadline = time.monotonic() + 1.0
        while len(delivered) < (1 if value == "first" else 2) and time.monotonic() < deadline:
            root.run_one()
            time.sleep(0.005)
        assert delivered[-1] == ("result", value)
        assert len(root.callbacks) <= 1

    jobs.close()
    assert root.callbacks == {}
