import threading
import time

from sparc.models import Limits
from sparc.peer.policy import RecordBucket


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


def test_record_burst_401_is_denied_and_refills_at_configured_rate():
    clock = FakeClock()
    bucket = RecordBucket(clock)

    assert all(bucket.allow() for _ in range(400))
    assert not bucket.allow()

    clock.now += 0.004
    assert not bucket.allow()
    clock.now += 0.001
    assert bucket.allow()
    assert not bucket.allow()


def test_wait_returns_false_when_cancelled_while_bucket_is_empty():
    bucket = RecordBucket(FakeClock(), limits=Limits(record_rate=1.0, record_burst=1))
    assert bucket.allow()
    cancel = threading.Event()
    cancel.set()

    assert bucket.wait(cancel) is False


def test_waiting_writer_wakes_promptly_when_cancellation_is_set():
    bucket = RecordBucket(
        FakeClock(), limits=Limits(record_rate=0.01, record_burst=1)
    )
    assert bucket.allow()
    cancel = threading.Event()
    waiting = threading.Event()
    result = []

    class ObservedCancel:
        def is_set(self):
            return cancel.is_set()

        def wait(self, timeout=None):
            waiting.set()
            return cancel.wait(timeout)

    worker = threading.Thread(target=lambda: result.append(bucket.wait(ObservedCancel())))
    worker.start()
    assert waiting.wait(timeout=1)
    started = time.monotonic()
    cancel.set()
    worker.join(timeout=0.5)

    assert not worker.is_alive()
    assert result == [False]
    assert time.monotonic() - started < 0.5
