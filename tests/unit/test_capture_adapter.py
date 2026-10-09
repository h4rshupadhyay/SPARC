"""Lifecycle contract for the synchronous offline-capture adapter."""

from __future__ import annotations

import asyncio
import gc
import inspect
import sys
import threading
import time
import types
import weakref
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest


def _row_packet(number="1"):
    return SimpleNamespace(
        number=number,
        sniff_timestamp="1.25",
        captured_length="60",
        length="60",
        highest_layer="FRAME",
    )


class _StopCapture(Exception):
    pass


class _Packet(SimpleNamespace):
    """Weak-referenceable packet stand-in for retention checks."""


class _FakeCapture:
    def __init__(self, reader, close=None, *, constructor_error=None):
        self.reader = reader
        self.close_impl = close
        self.constructor_error = constructor_error
        self.options = None
        self.constructor_thread = None
        self.constructor_loop = None
        self.reader_thread = None
        self.reader_loop = None
        self.close_thread = None
        self.close_loop = None
        self.close_calls = 0
        self.close_active = 0
        self.max_close_active = 0
        self._lock = threading.Lock()
        self.reader_started = threading.Event()
        self.reader_cancelled = threading.Event()
        self.close_started = threading.Event()

    def __call__(self, **options):
        self.options = options
        self.constructor_thread = threading.get_ident()
        self.constructor_loop = asyncio.get_running_loop()
        if self.constructor_error is not None:
            raise self.constructor_error
        return self

    def packets_from_tshark(self, callback, *, close_tshark=True):
        assert close_tshark is False
        assert not inspect.iscoroutinefunction(callback)
        self.callback = callback

        async def read():
            self.reader_thread = threading.get_ident()
            self.reader_loop = asyncio.get_running_loop()
            self.reader_started.set()
            try:
                await self.reader(callback)
            except asyncio.CancelledError:
                self.reader_cancelled.set()
                raise

        return read()

    async def close_async(self):
        with self._lock:
            self.close_calls += 1
            self.close_active += 1
            self.max_close_active = max(self.max_close_active, self.close_active)
        self.close_thread = threading.get_ident()
        self.close_loop = asyncio.get_running_loop()
        self.close_started.set()
        try:
            if self.close_impl is not None:
                await self.close_impl()
        finally:
            with self._lock:
                self.close_active -= 1


def _install_pyshark(monkeypatch, fake):
    package = types.ModuleType("pyshark")
    package.__path__ = []
    package.FileCapture = fake
    capture_package = types.ModuleType("pyshark.capture")
    capture_package.__path__ = []
    capture_package.FileCapture = fake
    capture_package.StopCapture = _StopCapture
    capture_module = types.ModuleType("pyshark.capture.capture")
    capture_module.FileCapture = fake
    capture_module.StopCapture = _StopCapture
    capture_package.capture = capture_module
    package.capture = capture_package
    monkeypatch.setitem(sys.modules, "pyshark", package)
    monkeypatch.setitem(sys.modules, "pyshark.capture", capture_package)
    monkeypatch.setitem(sys.modules, "pyshark.capture.capture", capture_module)


def _adapter():
    from sparc.traffic.capture import iter_capture

    return iter_capture


def _domain_error(call, code):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        call()
    assert caught.value.code == code
    return caught.value


def _collect(iterator, cancel, timeout=4.0):
    outcome = Queue()

    def consume():
        try:
            outcome.put((True, list(iterator)))
        except BaseException as exc:
            outcome.put((False, exc))

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        cancel.set()
        worker.join(2.5)
        assert not worker.is_alive(), "capture consumer did not unwind after cancellation"
        pytest.fail("capture iteration exceeded its bounded test deadline")
    succeeded, result = outcome.get_nowait()
    if not succeeded:
        raise result
    return result


def _assert_capture_closed(fake):
    assert fake.close_calls == 1
    assert fake.max_close_active == 1
    assert fake.close_thread == fake.constructor_thread
    assert fake.close_loop is fake.constructor_loop
    assert fake.constructor_loop.is_closed()


def test_stream_closes_capture_after_eof_or_parse_error(tmp_path, monkeypatch):
    packet_refs = []

    async def normal_reader(callback):
        packet = _Packet(**vars(_row_packet()))
        packet_refs.append(weakref.ref(packet))
        callback(packet)
        del packet

    fake = _FakeCapture(normal_reader)
    _install_pyshark(monkeypatch, fake)
    cancel = threading.Event()
    rows = _collect(_adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel), cancel)
    assert len(rows) == 1 and rows[0].number == 1
    _assert_capture_closed(fake)
    gc.collect()
    assert packet_refs[0]() is None

    async def malformed_reader(callback):
        callback(_row_packet(number="not-a-number"))

    fake = _FakeCapture(malformed_reader)
    _install_pyshark(monkeypatch, fake)
    _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        "capture_parse_failed",
    )
    _assert_capture_closed(fake)

    async def failing_reader(_callback):
        raise RuntimeError("decoder private detail")

    fake = _FakeCapture(failing_reader)
    _install_pyshark(monkeypatch, fake)
    error = _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        "capture_parse_failed",
    )
    assert "decoder private detail" not in error.message
    _assert_capture_closed(fake)


def test_stream_filter_and_no_resolution_arguments(tmp_path, monkeypatch):
    callback_seen = threading.Event()

    async def reader(callback):
        packet = _row_packet()
        callback(packet)
        callback_seen.set()

    fake = _FakeCapture(reader)
    _install_pyshark(monkeypatch, fake)
    source = tmp_path / "trace ; $(literal).pcap"
    tool = tmp_path / "TShark (literal)"
    display_filter = 'tcp.port == 443 && frame contains "x ; y"'
    cancel = threading.Event()
    rows = _collect(_adapter()(source, tool, cancel, display_filter), cancel)
    assert len(rows) == 1 and callback_seen.is_set()
    assert fake.options["input_file"] == str(source)
    assert fake.options["tshark_path"] == str(tool)
    assert fake.options["display_filter"] == display_filter
    assert fake.options["keep_packets"] is False
    assert fake.options["eventloop"] is fake.constructor_loop
    assert fake.options.get("use_json", False) is False
    assert fake.options.get("use_ek", False) is False
    assert fake.options.get("only_summaries", False) is False
    assert fake.reader_thread == fake.constructor_thread == fake.close_thread
    assert fake.reader_loop is fake.constructor_loop is fake.close_loop
    _assert_capture_closed(fake)


@pytest.mark.parametrize(
    "import_failure,expected_code",
    [
        (ModuleNotFoundError("No module named 'pyshark'", name="pyshark"), "pyshark_missing"),
        (ImportError("broken dependency"), "capture_parse_failed"),
    ],
)
def test_missing_python_dependency_is_domain_error(tmp_path, monkeypatch, import_failure, expected_code):
    import builtins

    fake = _FakeCapture(lambda _callback: None)
    original_import = builtins.__import__

    def fail_pyshark(name, *args, **kwargs):
        if name == "pyshark" or name.startswith("pyshark."):
            raise import_failure
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_pyshark)
    _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        expected_code,
    )
    assert fake.close_calls == 0


def test_worker_owns_and_closes_event_loop(tmp_path, monkeypatch):
    async def reader(callback):
        callback(_row_packet())

    fake = _FakeCapture(reader)
    _install_pyshark(monkeypatch, fake)
    caller_loop = asyncio.new_event_loop()
    previous = None
    try:
        try:
            previous = asyncio.get_event_loop()
        except RuntimeError:
            pass
        asyncio.set_event_loop(caller_loop)
        cancel = threading.Event()
        assert _collect(_adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel), cancel)
        assert asyncio.get_event_loop() is caller_loop
        assert not caller_loop.is_closed()
        assert fake.constructor_thread != threading.get_ident()
        assert fake.reader_thread == fake.constructor_thread == fake.close_thread
        assert fake.reader_loop is fake.constructor_loop is fake.close_loop
        assert fake.constructor_loop.is_closed()
        _assert_capture_closed(fake)
    finally:
        asyncio.set_event_loop(previous)
        caller_loop.close()


def test_cancel_while_decoder_has_no_packets(tmp_path, monkeypatch):
    cancel = threading.Event()

    async def waiting_reader(_callback):
        await asyncio.Event().wait()

    fake = _FakeCapture(waiting_reader)
    _install_pyshark(monkeypatch, fake)
    generator = _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel)
    outcome = Queue()

    def consume():
        try:
            outcome.put(("row", next(generator)))
        except BaseException as exc:
            outcome.put(("error", exc))

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    try:
        assert fake.reader_started.wait(1.0)
        cancel.set()
        worker.join(2.5)
        assert not worker.is_alive()
        kind, value = outcome.get_nowait()
        assert kind == "error"
        assert getattr(value, "code", None) == "capture_cancelled"
        assert fake.reader_cancelled.wait(0.2)
        _assert_capture_closed(fake)
    finally:
        cancel.set()
        generator.close()
        worker.join(2.5)
        assert not worker.is_alive()


def test_generator_close_unblocks_full_queue_without_caller_cancel(tmp_path, monkeypatch):
    callback_entered = threading.Event()
    cancel = threading.Event()

    async def filling_reader(callback):
        for number in range(1, 131):
            if number == 130:
                callback_entered.set()
            callback(_row_packet(str(number)))

    fake = _FakeCapture(filling_reader)
    _install_pyshark(monkeypatch, fake)
    generator = _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel)
    try:
        first = next(generator)
        assert first.number == 1
        assert callback_entered.wait(1.5)
        started = time.monotonic()
        generator.close()
        assert time.monotonic() - started < 2.0
        assert not cancel.is_set()
        _assert_capture_closed(fake)
    finally:
        generator.close()
        cancel.set()


def test_cleanup_failure_never_publishes_completed_eof(tmp_path, monkeypatch):
    async def reader(callback):
        callback(_row_packet())

    async def failed_close():
        raise RuntimeError("private cleanup detail")

    fake = _FakeCapture(reader, failed_close)
    _install_pyshark(monkeypatch, fake)
    outcome = _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        "capture_cleanup_failed",
    )
    assert "private cleanup detail" not in outcome.message
    _assert_capture_closed(fake)


def test_close_timeout_is_not_successful_eof(tmp_path, monkeypatch):
    async def reader(callback):
        callback(_row_packet())

    async def stuck_close():
        await asyncio.Event().wait()

    fake = _FakeCapture(reader, stuck_close)
    _install_pyshark(monkeypatch, fake)
    started = time.monotonic()
    _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        "capture_cleanup_failed",
    )
    assert time.monotonic() - started < 5.0
    assert fake.close_calls == 1
    assert fake.max_close_active == 1
    assert fake.constructor_loop.is_closed()


def test_cancel_before_first_iteration_creates_no_parser(tmp_path, monkeypatch):
    cancel = threading.Event()
    cancel.set()
    fake = _FakeCapture(lambda _callback: None)
    _install_pyshark(monkeypatch, fake)
    generator = _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel)
    _domain_error(lambda: next(generator), "capture_cancelled")
    assert fake.options is None
    assert fake.close_calls == 0


def test_constructor_failure_uses_done_outcome_without_close(tmp_path, monkeypatch):
    fake = _FakeCapture(lambda _callback: None, constructor_error=RuntimeError("private startup detail"))
    _install_pyshark(monkeypatch, fake)
    error = _domain_error(
        lambda: _collect(
            _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel := threading.Event()), cancel
        ),
        "capture_parse_failed",
    )
    assert "private startup detail" not in error.message
    assert fake.close_calls == 0


@pytest.mark.parametrize("termination", ["cancelled", "stop_capture"])
def test_unrequested_reader_cancel_never_becomes_eof(tmp_path, monkeypatch, termination):
    async def reader(callback):
        callback(_row_packet())
        if termination == "cancelled":
            raise asyncio.CancelledError()
        raise _StopCapture()

    fake = _FakeCapture(reader)
    _install_pyshark(monkeypatch, fake)
    cancel = threading.Event()
    iterator = _adapter()(tmp_path / "in.pcap", tmp_path / "tshark", cancel)

    assert next(iterator).number == 1
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        next(iterator)
    assert caught.value.code == "capture_parse_failed"
    assert not cancel.is_set()
    _assert_capture_closed(fake)
