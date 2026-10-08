"""C5a's single-writer ordering and finite cancellation contract."""

import struct
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from sparc.models import Limits, ProtectedRecord, SparcError
from sparc.peer.session import ActiveSession, SessionHooks


def _payload(index):
    return {"kind": "test", "index": index}


class _Codec:
    """Small deterministic stand-in that exposes writer ownership and ordering."""

    def __init__(self, fail_at=None):
        self.session_id = b"S" * 32
        self.calls = []
        self.fail_at = fail_at
        self._lock = threading.Lock()

    def protect(self, payload):
        with self._lock:
            sequence = len(self.calls)
            self.calls.append(payload)
        if sequence == self.fail_at:
            raise SparcError("session_unusable", "test codec failure")
        return ProtectedRecord(frame=struct.pack(">I", sequence) + repr(payload).encode())


class _Socket:
    def __init__(self):
        self.frames = []
        self.closed = threading.Event()
        self.written = threading.Event()
        self.fail = False
        self._lock = threading.Lock()
        self._timeout = None

    def sendall(self, frame):
        if self.fail:
            raise OSError("deliberate transport failure")
        with self._lock:
            self.frames.append(frame)
        self.written.set()

    def shutdown(self, _how):
        self.closed.set()

    def close(self):
        self.closed.set()

    def gettimeout(self):
        return self._timeout

    def settimeout(self, value):
        self._timeout = value

    def recv(self, _size):
        if self.closed.wait(self._timeout or 0.01):
            return b""
        raise socket.timeout()


def _session(*, limits=None, codec=None, sock=None, on_closed=None, on_written=None, cancel=None):
    codec = codec or _Codec()
    sock = sock or _Socket()
    closed = []
    callbacks = {
        "on_payload": lambda _record: None,
        "on_closed": lambda error: (closed.append(error), on_closed(error) if on_closed else None),
        "emit": lambda _event: None,
    }
    if on_written is not None:
        callbacks["on_written"] = on_written
    hooks = SessionHooks(**callbacks)
    established = SimpleNamespace(codec=codec, peer=SimpleNamespace(public_key=b"P" * 32))
    kwargs = {} if cancel is None else {"cancel": cancel}
    session = ActiveSession(
        sock, established, hooks, limits or Limits(cancel_poll_seconds=0.01), **kwargs
    )
    return session, sock, codec, closed


def _wait_until(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.002)
    return predicate()


def test_one_writer_serializes_sequences_and_bytes():
    session, sock, codec, closed = _session()
    count = 32
    barrier = threading.Barrier(count)

    def enqueue(index):
        barrier.wait()
        session.enqueue(_payload(index))

    producers = [threading.Thread(target=enqueue, args=(index,)) for index in range(count)]
    for producer in producers:
        producer.start()
    for producer in producers:
        producer.join(timeout=1)
        assert not producer.is_alive()

    session.start()
    assert _wait_until(lambda: len(sock.frames) == count)
    session.close()
    assert session.join(timeout=1)

    assert [struct.unpack(">I", frame[:4])[0] for frame in sock.frames] == list(range(count))
    assert len(codec.calls) == count
    assert len({repr(call) for call in codec.calls}) == count
    assert closed and len(closed) == 1


def test_control_queue_has_priority():
    session, sock, _codec, _closed = _session()
    session.enqueue({"kind": "ordinary"})
    session.enqueue({"kind": "control"}, control=True)
    session.start()
    assert _wait_until(lambda: len(sock.frames) == 2)
    session.close()
    assert session.join(timeout=1)
    assert b"control" in sock.frames[0]
    assert b"ordinary" in sock.frames[1]


def test_optional_on_written_hook_runs_before_sendall_with_payload_and_protected_record():
    events = []
    sock = _Socket()
    original_sendall = sock.sendall

    def observe_sendall(frame):
        events.append(("sendall", frame))
        original_sendall(frame)

    sock.sendall = observe_sendall
    payload = _payload("hook")
    session, _sock, _codec, _closed = _session(
        sock=sock,
        on_written=lambda written_payload, protected: events.append(
            ("on_written", written_payload, protected)
        ),
    )
    session.enqueue(payload)
    session.start()
    assert sock.written.wait(timeout=1)
    session.close()
    assert session.join(timeout=1)

    assert len(events) == 2
    assert events[0][0] == "on_written"
    assert events[0][1] == payload
    assert isinstance(events[0][2], ProtectedRecord)
    assert events[1][0] == "sendall"


def test_write_failure_discards_session_and_notifies_once():
    codec = _Codec()
    sock = _Socket()
    sock.fail = True
    session, _sock, _codec, closed = _session(codec=codec, sock=sock)
    session.enqueue(_payload(1))
    session.start()
    assert session.join(timeout=1)
    assert len(codec.calls) == 1
    assert len(closed) == 1
    assert closed[0].code == "tcp_loss"


def test_simultaneous_close_and_write_failure_notify_once():
    entered = threading.Event()
    release = threading.Event()
    sock = _Socket()

    def blocking_send(_frame):
        entered.set()
        release.wait(1)
        raise OSError("deliberate transport failure")

    sock.sendall = blocking_send
    session, _sock, _codec, closed = _session(sock=sock)
    session.enqueue(_payload(1))
    session.start()
    assert entered.wait(1)
    session.close()
    release.set()
    assert session.join(timeout=1)
    assert len(closed) == 1
    assert closed[0].code in {"operation_cancelled", "tcp_loss"}


def test_full_control_queue_producer_wakes_on_cancel():
    limits = Limits(control_queue=1, cancel_poll_seconds=0.01)
    session, _sock, _codec, _closed = _session(limits=limits)
    session.enqueue({"kind": "control", "index": 1}, control=True)
    result = []

    def blocked_enqueue():
        try:
            session.enqueue({"kind": "control", "index": 2}, control=True)
        except SparcError as error:
            result.append(error.code)

    producer = threading.Thread(target=blocked_enqueue)
    producer.start()
    time.sleep(0.03)
    session.close()
    producer.join(timeout=1)
    assert not producer.is_alive()
    assert result == ["operation_cancelled"]


def test_full_ordinary_queue_fails_visibly_and_postcancel_enqueue_is_rejected():
    limits = Limits(outbound_queue=1, cancel_poll_seconds=0.01)
    session, _sock, _codec, _closed = _session(limits=limits)
    session.enqueue(_payload(1))
    with pytest.raises(SparcError) as raised:
        session.enqueue(_payload(2))
    assert raised.value.code == "busy"
    session.close()
    with pytest.raises(SparcError) as canceled:
        session.enqueue(_payload(3))
    assert canceled.value.code == "operation_cancelled"


def test_idle_writer_cancels_and_joins_with_finite_timeout():
    session, _sock, _codec, closed = _session()
    session.start()
    session.close()
    started = time.monotonic()
    assert session.join(timeout=0.5)
    assert time.monotonic() - started < 0.5
    assert len(closed) == 1


def test_ordinary_enqueue_wakes_idle_writer_promptly():
    limits = Limits(cancel_poll_seconds=0.75)
    session, sock, _codec, _closed = _session(limits=limits)
    waiting = threading.Event()

    condition = session._queue_condition

    class ObservedCondition:
        def __enter__(self):
            condition.__enter__()
            return self

        def __exit__(self, *args):
            return condition.__exit__(*args)

        def wait(self, timeout=None):
            waiting.set()
            return condition.wait(timeout)

        def notify(self, count=1):
            condition.notify(count)

        def notify_all(self):
            condition.notify_all()

    session._queue_condition = ObservedCondition()
    session.start()
    assert waiting.wait(timeout=1)
    session.enqueue(_payload("after-idle"))
    assert sock.written.wait(timeout=0.2)
    session.close()
    assert session.join(timeout=1)


def test_close_from_writer_callback_skips_self_join():
    sock = _Socket()
    session_ref = []
    callback_results = []

    def close_from_callback(_error):
        session_ref[0].close()
        started = time.monotonic()
        joined = session_ref[0].join(timeout=0.05)
        callback_results.append((joined, time.monotonic() - started))

    session, _sock, codec, closed = _session(sock=sock, codec=_Codec(fail_at=0), on_closed=close_from_callback)
    session_ref.append(session)
    session.enqueue(_payload(1))
    session.start()
    assert session.join(timeout=1)
    assert len(codec.calls) == 1
    assert len(closed) == 1
    assert len(callback_results) == 1
    assert callback_results[0][0] is False
    assert callback_results[0][1] < 0.05


def test_session_close_signals_the_shared_attempt_cancel_before_on_closed():
    attempt_cancel = threading.Event()
    observed = []
    session, _sock, _codec, _closed = _session(
        cancel=attempt_cancel,
        on_closed=lambda _error: observed.append(attempt_cancel.is_set()),
    )
    session.close()
    assert attempt_cancel.is_set()
    assert observed == [True]


def test_writer_failure_signals_the_shared_attempt_cancel():
    attempt_cancel = threading.Event()
    sock = _Socket()
    sock.fail = True
    session, _sock, _codec, closed = _session(sock=sock, cancel=attempt_cancel)
    session.enqueue(_payload("shared cancellation"))
    session.start()
    assert session.join(timeout=1)
    assert attempt_cancel.is_set()
    assert len(closed) == 1
