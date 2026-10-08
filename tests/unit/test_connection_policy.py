from sparc.models import Limits
from sparc.peer.policy import ConnectionLimiter


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_source_and_global_limits():
    clock = FakeClock()
    limiter = ConnectionLimiter(clock)

    assert all(limiter.allow("192.0.2.1") for _ in range(20))
    assert not limiter.allow("192.0.2.1")
    assert limiter.allow("192.0.2.2")

    # The global quota spans sources, and a denied source attempt still counts
    # as an attempt against the global quota.
    for index in range(3, 41):
        assert limiter.allow(f"198.51.100.{index}")
    assert not limiter.allow("203.0.113.1")


def test_rolling_window_expiry_has_no_fixed_minute_rollover():
    clock = FakeClock()
    limiter = ConnectionLimiter(clock)

    assert all(limiter.allow("192.0.2.8") for _ in range(20))
    clock.advance(59.0)
    assert not limiter.allow("192.0.2.8")
    clock.advance(1.0)
    # The denied attempt at t=59 also counts and displaced one t=0 entry
    # from the capped deque. At t=60, it leaves room for only 19 attempts.
    assert all(limiter.allow("192.0.2.8") for _ in range(19))
    assert not limiter.allow("192.0.2.8")


def test_source_buckets_never_exceed_256_and_expired_sources_are_evicted():
    clock = FakeClock()
    limits = Limits(source_buckets=2, connections_per_source=20,
                    connections_global=60)
    limiter = ConnectionLimiter(clock, limits=limits)

    assert limiter.allow("192.0.2.1")
    assert limiter.allow("192.0.2.2")
    assert not limiter.allow("192.0.2.3")

    # A full table stays full while its buckets contain live attempts.
    clock.advance(59.0)
    assert not limiter.allow("192.0.2.3")

    # Once entries expire, the table reclaims them and admits a new source.
    clock.advance(1.0)
    assert limiter.allow("192.0.2.3")
