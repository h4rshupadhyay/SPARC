"""Normalize PyShark's default XML packet objects to scalar records."""

from collections.abc import Iterator, Sequence
import asyncio
from decimal import Decimal, InvalidOperation
import os
from pathlib import Path
from queue import Empty, Full, Queue
import re
import shutil
import threading
from typing import Any

from sparc.models import SparcError

from .models import PacketRow


_DECIMAL_INTEGER = re.compile(r"[0-9]+", re.ASCII)
_TIMESTAMP = re.compile(r"-?[0-9]+(?:\.[0-9]+)?", re.ASCII)
_RETRANSMISSION_FIELDS = frozenset(
    {
        "analysis_retransmission",
        "analysis_fast_retransmission",
        "analysis_spurious_retransmission",
    }
)
_MISSING = object()


def find_tshark(explicit: Path | None = None) -> Path:
    """Find a usable TShark executable without launching it."""
    message = (
        "TShark is required for traffic capture. Install the TShark executable "
        "or configure its path."
    )
    try:
        if explicit is not None:
            candidate = Path(explicit)
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                raise SparcError("tshark_missing", message)
        else:
            found = shutil.which("tshark")
            if found is None:
                raise SparcError("tshark_missing", message)
            candidate = Path(found)
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                raise SparcError("tshark_missing", message)
        return candidate.resolve()
    except SparcError:
        raise
    except (OSError, RuntimeError) as exc:
        raise SparcError("tshark_missing", message) from exc


def _read(obj: Any, attribute: str, label: str) -> Any:
    """Read a public attribute, translating access failures to safe domain errors."""
    try:
        return getattr(obj, attribute)
    except AttributeError:
        return _MISSING
    except Exception as exc:
        raise SparcError("capture_parse_failed", f"Could not read capture field: {label}") from exc


def _invalid(label: str) -> SparcError:
    return SparcError("capture_parse_failed", f"Invalid capture field: {label}")


def _required(packet: Any, primary: str, fallback: str, label: str) -> Any:
    value = _read(packet, primary, label)
    if value is not _MISSING and value is not None:
        return value

    frame = _read(packet, "frame_info", label)
    if frame is not _MISSING and frame is not None:
        value = _read(frame, fallback, label)
        if value is not _MISSING and value is not None:
            return value
    raise SparcError("capture_parse_failed", f"Could not read capture field: {label}")


def _integer(value: Any, label: str, *, port: bool = False) -> int:
    maximum = 65535 if port else 2**63 - 1
    if isinstance(value, bool):
        raise _invalid(label)
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value and _DECIMAL_INTEGER.fullmatch(value):
        significant = value.lstrip("0") or "0"
        bound = str(maximum)
        if len(significant) > len(bound) or (len(significant) == len(bound) and significant > bound):
            raise _invalid(label)
        result = int(significant, 10)
    else:
        raise _invalid(label)
    if result < 0 or result > maximum:
        raise _invalid(label)
    return result


def _timestamp(value: Any) -> str:
    label = "timestamp"
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _invalid(label)
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise _invalid(label) from exc
    if not parsed.is_finite():
        raise _invalid(label)
    return str(value)


def _optional_layer(packet: Any, name: str) -> Any:
    layer = _read(packet, name, name)
    return None if layer is _MISSING or layer is None else layer


def _optional_integer(layer: Any, attribute: str, label: str, *, port: bool = False) -> int | None:
    value = _read(layer, attribute, label)
    if value is _MISSING or value is None:
        return None
    return _integer(value, label, port=port)


def _optional_text(layer: Any, attribute: str, label: str, *, allow_empty: bool = False) -> str | None:
    value = _read(layer, attribute, label)
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, str) or (not allow_empty and not value) or value != value.strip():
        raise _invalid(label)
    return str(value)


def _addresses(packet: Any) -> tuple[str | None, str | None]:
    layer_name = "ip"
    layer = _optional_layer(packet, layer_name)
    if layer is None:
        layer_name = "ipv6"
        layer = _optional_layer(packet, layer_name)
    if layer is None:
        return None, None
    src = _optional_text(layer, "src", f"{layer_name}.src")
    dst = _optional_text(layer, "dst", f"{layer_name}.dst")
    return src, dst


def _transport(packet: Any) -> tuple[int | None, int | None, int | None, str | None, bool | None]:
    tcp = _optional_layer(packet, "tcp")
    if tcp is not None:
        src_port = _optional_integer(tcp, "srcport", "tcp.srcport", port=True)
        dst_port = _optional_integer(tcp, "dstport", "tcp.dstport", port=True)
        stream = _optional_integer(tcp, "stream", "tcp.stream")
        flags = _optional_text(tcp, "flags", "tcp.flags")

        names = _read(tcp, "field_names", "tcp.field_names")
        if names is _MISSING or names is None:
            names = ()
        elif not isinstance(names, Sequence) or isinstance(names, (str, bytes)):
            raise _invalid("tcp.field_names")
        elif any(not isinstance(name, str) for name in names):
            raise _invalid("tcp.field_names")
        retransmission = True if any(name in _RETRANSMISSION_FIELDS for name in names) else None
        return src_port, dst_port, stream, flags, retransmission

    udp = _optional_layer(packet, "udp")
    if udp is None:
        return None, None, None, None, None
    return (
        _optional_integer(udp, "srcport", "udp.srcport", port=True),
        _optional_integer(udp, "dstport", "udp.dstport", port=True),
        None,
        None,
        None,
    )


def _highest_protocol(packet: Any) -> str:
    try:
        value = getattr(packet, "highest_layer")
    except AttributeError:
        return "FRAME"
    except IndexError:
        return "FRAME"
    except Exception as exc:
        raise SparcError("capture_parse_failed", "Could not read capture field: highest_layer") from exc
    if value is None:
        return "FRAME"
    if not isinstance(value, str):
        raise _invalid("highest_layer")
    if value == "":
        return "FRAME"
    if value != value.strip():
        raise _invalid("highest_layer")
    return str(value)


def normalize_packet(packet: Any) -> PacketRow:
    """Extract validated scalar metadata from one PyShark XML packet."""
    number = _integer(_required(packet, "number", "number", "number"), "number")
    timestamp = _timestamp(_required(packet, "sniff_timestamp", "time_epoch", "timestamp"))
    captured_length = _integer(
        _required(packet, "captured_length", "cap_len", "captured_length"), "captured_length"
    )
    wire_length = _integer(_required(packet, "length", "len", "wire_length"), "wire_length")
    highest_protocol = _highest_protocol(packet)
    src, dst = _addresses(packet)
    src_port, dst_port, tcp_stream, tcp_flags, retransmission = _transport(packet)
    return PacketRow(
        number=number,
        timestamp=timestamp,
        captured_length=captured_length,
        wire_length=wire_length,
        highest_protocol=highest_protocol,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=tcp_stream,
        tcp_flags=tcp_flags,
        retransmission=retransmission,
    )


_QUEUE_SIZE = 128
_POLL_SECONDS = 0.1
_CLOSE_SECONDS = 2.0
_JOIN_SECONDS = 2.0
_GENERIC_PARSE_MESSAGE = "Could not read the saved capture"
_CLEANUP_MESSAGE = "Offline capture cleanup could not be confirmed"
_CANCEL_MESSAGE = "Offline capture analysis was canceled"


def _fresh_error(error: SparcError) -> SparcError:
    """Copy only public error fields, discarding traceback/context references."""
    return SparcError(error.code, error.message)


def _capture_error() -> SparcError:
    return SparcError("capture_parse_failed", _GENERIC_PARSE_MESSAGE)


def iter_capture(
    path: Path,
    tshark: Path,
    cancel: threading.Event,
    display_filter: str | None = None,
) -> Iterator[PacketRow]:
    """Yield normalized rows from one offline capture on an owned worker loop."""
    rows: Queue[PacketRow | SparcError | None] = Queue(maxsize=_QUEUE_SIZE)
    stop = threading.Event()
    done = threading.Event()
    outcome: dict[str, Any] = {"status": None, "error": None}
    worker: threading.Thread | None = None
    started = False

    def stopped() -> bool:
        return cancel.is_set() or stop.is_set()

    def producer() -> None:
        loop: asyncio.AbstractEventLoop | None = None
        capture: Any = None
        reader: asyncio.Task[Any] | None = None
        watcher: asyncio.Task[Any] | None = None
        reader_settled = True
        status = "success"
        failure: SparcError | None = None
        cleanup_failed = False
        finalized = True

        async def watch_reader() -> None:
            assert reader is not None
            while not reader.done():
                if stopped():
                    reader.cancel()
                    return
                await asyncio.sleep(_POLL_SECONDS)

        async def supervise() -> None:
            nonlocal reader, watcher, reader_settled, status, failure
            assert capture is not None

            def callback(packet: Any) -> None:
                if stopped():
                    raise StopCapture()
                try:
                    row = normalize_packet(packet)
                except SparcError as error:
                    raise _fresh_error(error) from None
                except Exception:
                    raise _capture_error() from None
                while True:
                    if stopped():
                        raise StopCapture()
                    try:
                        rows.put(row, timeout=_POLL_SECONDS)
                    except Full:
                        continue
                    if stopped():
                        raise StopCapture()
                    return

            reader = loop.create_task(capture.packets_from_tshark(callback, close_tshark=False))
            watcher = loop.create_task(watch_reader())
            try:
                await reader
            except asyncio.CancelledError:
                if stopped():
                    status = "stopped"
                else:
                    failure = _capture_error()
                    status = "error"
            except SparcError as error:
                failure = _fresh_error(error)
                status = "error"
            except StopCapture:
                if stopped():
                    status = "stopped"
                else:
                    failure = _capture_error()
                    status = "error"
            except Exception:
                failure = _capture_error()
                status = "error"
            finally:
                if watcher is not None:
                    watcher.cancel()
                    try:
                        await asyncio.wait_for(asyncio.gather(watcher, return_exceptions=True), _CLOSE_SECONDS)
                    except (asyncio.TimeoutError, Exception):
                        status = "error"
                        failure = SparcError("capture_cleanup_failed", _CLEANUP_MESSAGE)

        async def construct_and_supervise(file_capture: Any) -> None:
            nonlocal capture
            capture = file_capture(
                input_file=str(path),
                tshark_path=str(tshark),
                display_filter=display_filter,
                keep_packets=False,
                eventloop=loop,
            )
            await supervise()

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            if stopped():
                status = "stopped"
            else:
                try:
                    from pyshark import FileCapture
                    from pyshark.capture.capture import StopCapture
                except ModuleNotFoundError as error:
                    if error.name == "pyshark" or (error.name or "").startswith("pyshark."):
                        failure = SparcError("pyshark_missing", "PyShark is required to read saved captures")
                    else:
                        failure = _capture_error()
                    status = "error"
                except Exception:
                    failure = _capture_error()
                    status = "error"
                else:
                    if stopped():
                        status = "stopped"
                    else:
                        try:
                            loop.run_until_complete(construct_and_supervise(FileCapture))
                        except asyncio.CancelledError:
                            if stopped():
                                status = "stopped"
                            else:
                                failure = _capture_error()
                                status = "error"
                        except Exception:
                            failure = _capture_error()
                            status = "error"
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                status = "error"
                failure = _capture_error()
                raise
            failure = _capture_error()
            status = "error"
        finally:
            if loop is not None:
                if reader is not None and not reader.done():
                    reader.cancel()
                    try:
                        loop.run_until_complete(asyncio.wait_for(asyncio.shield(reader), _CLOSE_SECONDS))
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        reader_settled = reader.done()
                    except Exception:
                        reader_settled = reader.done()
                if reader is not None and not reader.done():
                    reader_settled = False
                if capture is not None and reader_settled:
                    try:
                        loop.run_until_complete(asyncio.wait_for(capture.close_async(), _CLOSE_SECONDS))
                    except BaseException:
                        cleanup_failed = True
                elif capture is not None:
                    cleanup_failed = True

                for task in asyncio.all_tasks(loop):
                    task.cancel()
                try:
                    pending = asyncio.all_tasks(loop)
                    if pending:
                        loop.run_until_complete(
                            asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), _CLOSE_SECONDS)
                        )
                except BaseException:
                    finalized = False
                try:
                    loop.run_until_complete(asyncio.wait_for(loop.shutdown_asyncgens(), _CLOSE_SECONDS))
                except BaseException:
                    finalized = False
                try:
                    asyncio.set_event_loop(None)
                    loop.close()
                except BaseException:
                    finalized = False

            # Cleanup and loop finalization dominate all earlier outcomes.
            if cleanup_failed or not finalized:
                outcome["status"] = "error"
                outcome["error"] = SparcError("capture_cleanup_failed", _CLEANUP_MESSAGE)
            elif cancel.is_set():
                outcome["status"] = "cancelled"
            elif status == "error":
                outcome["status"] = "error"
                outcome["error"] = _fresh_error(failure) if failure is not None else _capture_error()
            elif status == "stopped" or stop.is_set():
                outcome["status"] = "stopped"
            else:
                outcome["status"] = "success"

            terminal: PacketRow | SparcError | None
            if outcome["status"] == "success":
                terminal = None
            elif outcome["status"] == "error":
                terminal = outcome["error"]
            else:
                terminal = None  # Stop/cancel outcomes are carried by done/outcome only.
            try:
                if terminal is not None or outcome["status"] == "success":
                    while not stopped():
                        try:
                            rows.put(terminal, timeout=_POLL_SECONDS)
                            break
                        except Full:
                            continue
            finally:
                done.set()

    def ensure_worker() -> None:
        nonlocal worker, started
        if started:
            return
        started = True
        worker = threading.Thread(target=producer, name="sparc-capture-reader", daemon=True)
        worker.start()

    try:
        if cancel.is_set():
            raise SparcError("capture_cancelled", _CANCEL_MESSAGE)
        ensure_worker()
        while True:
            if cancel.is_set():
                raise SparcError("capture_cancelled", _CANCEL_MESSAGE)
            try:
                item = rows.get(timeout=_POLL_SECONDS)
            except Empty:
                if done.is_set():
                    status = outcome["status"]
                    if status == "success" and not stopped():
                        return
                    if status == "error":
                        raise _fresh_error(outcome["error"])
                    if cancel.is_set() or status == "cancelled":
                        raise SparcError("capture_cancelled", _CANCEL_MESSAGE)
                    if status == "stopped" and stop.is_set():
                        return
                    raise _capture_error()
                continue
            if cancel.is_set():
                raise SparcError("capture_cancelled", _CANCEL_MESSAGE)
            if item is None:
                if done.is_set() and outcome["status"] == "success" and not stopped():
                    return
                if done.is_set() and outcome["status"] == "error":
                    raise _fresh_error(outcome["error"])
                if done.is_set() and (cancel.is_set() or outcome["status"] == "cancelled"):
                    raise SparcError("capture_cancelled", _CANCEL_MESSAGE)
                if done.is_set() and outcome["status"] == "stopped" and stop.is_set():
                    return
                if done.is_set() and outcome["status"] != "success":
                    raise _capture_error()
                continue
            if isinstance(item, SparcError):
                raise _fresh_error(item)
            yield item
    finally:
        if started:
            stop.set()
            assert worker is not None
            worker.join(_JOIN_SECONDS)
            if worker.is_alive():
                raise SparcError("capture_cleanup_failed", _CLEANUP_MESSAGE)
            if outcome["status"] == "error" and isinstance(outcome["error"], SparcError):
                # Preserve an error already raised by the consumer; cleanup failure is
                # the only later outcome allowed to replace it.
                if outcome["error"].code == "capture_cleanup_failed":
                    raise _fresh_error(outcome["error"])
