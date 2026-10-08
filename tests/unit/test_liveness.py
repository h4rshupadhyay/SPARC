import re
import threading
import time

import pytest

from sparc.models import Limits, SparcError
from sparc.peer.liveness import Liveness
from sparc.peer.policy import RecordBucket


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_ping_after_five_seconds_matching_pong_and_loss_after_fifteen():
    clock = FakeClock()
    liveness = Liveness(clock)

    clock.advance(4.999)
    assert liveness.tick() == (None, False)
    clock.advance(0.001)
    ping, lost = liveness.tick()
    assert not lost
    assert ping is not None
    assert ping["kind"] == "ping"
    assert re.fullmatch(r"[0-9a-f]{32}", ping["ping_id"])
    liveness.sent()

    with pytest.raises(SparcError):
        liveness.accept_pong("f" * 32)
    liveness.accept_pong(ping["ping_id"])

    clock.advance(6.0)
    liveness.received()
    assert liveness.loss_elapsed_ns is None
    clock.advance(14.999)
    assert liveness.tick()[1] is False
    assert liveness.loss_elapsed_ns is None
    clock.advance(0.001)
    _ping, lost = liveness.tick()
    assert lost is True
    assert liveness.loss_elapsed_ns == 15_000_000_000


def test_tick_emits_new_ping_only_after_outgoing_idle_interval():
    clock = FakeClock()
    limits = Limits(heartbeat_seconds=3.0, peer_timeout_seconds=9.0)
    liveness = Liveness(clock, limits=limits)

    clock.advance(3.0)
    first, lost = liveness.tick()
    assert not lost
    assert first is not None
    liveness.sent()
    liveness.accept_pong(first["ping_id"])

    clock.advance(2.999)
    assert liveness.tick() == (None, False)
    clock.advance(0.001)
    second, lost = liveness.tick()
    assert not lost
    assert second is not None
    assert second["ping_id"] != first["ping_id"]


def test_loss_only_tick_does_not_create_a_pending_ping():
    clock = FakeClock()
    liveness = Liveness(clock)
    clock.advance(5.0)

    assert liveness.tick(allow_ping=False) == (None, False)
    ping, lost = liveness.tick()
    assert not lost
    assert ping is not None


def test_slow_bucket_wait_runs_maintenance_outside_lock_at_most_once_per_second():
    bucket = RecordBucket(
        FakeClock(), limits=Limits(record_rate=0.01, record_burst=1)
    )
    assert bucket.allow()
    cancel = threading.Event()
    calls = []
    result = []

    def maintenance():
        calls.append(time.monotonic())
        # Re-entering the bucket would deadlock if maintenance ran under its lock.
        assert bucket.allow() is False
        if len(calls) == 3:
            cancel.set()
            return False
        return True

    worker = threading.Thread(
        target=lambda: result.append(bucket.wait(cancel, maintenance=maintenance)),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=2.5)

    assert not worker.is_alive()
    assert result == [False]
    assert len(calls) == 3
    assert all(later - earlier <= 1.1 for earlier, later in zip(calls, calls[1:]))
