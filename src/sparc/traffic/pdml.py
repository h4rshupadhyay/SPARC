"""Unfiltered PDML export with finite process ownership and atomic publication."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import time
from threading import Event
import xml.etree.ElementTree as ET

from sparc.models import SparcError
from . import capture
from .models import ConversionResult
from .sqlite_index import (
    _check_cancel, _hash_source, _observe_versions, _preflight_public_paths,
    _replace_and_sync, _source_fingerprint,
)


_XML_ERROR = "Could not export saved capture as PDML"
_CLEANUP_ERROR = "Saved capture export cleanup could not be confirmed"


def _preflight(source: Path, destination: Path) -> None:
    try:
        _preflight_public_paths(source, destination)
    except SparcError as error:
        if error.code == "traffic_index_failed":
            raise SparcError("traffic_xml_failed", _XML_ERROR) from error
        raise


def _reap(process) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=2)


def _count_packets(stage: Path, cancel: Event) -> int:
    stack = []
    count = 0
    with stage.open("rb") as handle:
        for event, element in ET.iterparse(handle, events=("start", "end")):
            _check_cancel(cancel)
            if event == "start":
                if not stack and element.tag != "pdml":
                    raise ValueError("Invalid PDML root")
                stack.append(element)
            else:
                if len(stack) == 2 and element.tag == "packet":
                    count += 1
                stack.pop()
                if stack:
                    stack[-1].remove(element)
                element.clear()
    _check_cancel(cancel)
    return count


def export_xml(source: Path, destination: Path, tshark: Path, cancel: Event) -> ConversionResult:
    """Publish the original capture's validated PDML; no display filter is used."""
    started_ns = time.perf_counter_ns()
    _check_cancel(cancel)
    source, destination = Path(source), Path(destination)
    _preflight(source, destination)
    try:
        source = source.resolve(strict=True)
        before = _source_fingerprint(source)
        source_hash, source_bytes = _hash_source(source, cancel)
        if _source_fingerprint(source) != before or source_bytes != before[2]:
            raise SparcError("capture_source_changed", "Saved capture changed during export")
    except (OSError, RuntimeError) as error:
        raise SparcError("capture_source_unavailable", "Saved capture source is unavailable") from error
    tool = capture.find_tshark(Path(tshark))
    versions = _observe_versions(tool, cancel)
    destination = destination.absolute()
    stage = None
    stage_fd = None
    stdout = stderr = process = None
    reaped = False
    primary = None
    cleanup_error = None
    count = output_bytes = 0
    try:
        _check_cancel(cancel)
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage_fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        stage = Path(name)
        if os.name == "posix":
            os.fchmod(stage_fd, 0o600)
        stdout = os.fdopen(stage_fd, "w+b")
        stage_fd = None
        stderr = tempfile.TemporaryFile(mode="w+b")
        _check_cancel(cancel)
        process = subprocess.Popen(
            [str(tool), "-n", "-r", str(source), "-T", "pdml"],
            shell=False, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        )
        while process.poll() is None:
            _check_cancel(cancel)
            cancel.wait(0.1)
        _check_cancel(cancel)
        exit_code = process.wait(timeout=2)
        reaped = True
        if exit_code != 0:
            stderr.flush()
            stderr.seek(0, os.SEEK_END)
            stderr.seek(max(0, stderr.tell() - 8192))
            stderr.read(8192)  # Bounded diagnostic input; never disclose decoder text.
            raise SparcError("traffic_xml_failed", _XML_ERROR)
        stdout.flush()
        try:
            stdout.close()
            stderr.close()
        except OSError as error:
            raise SparcError("capture_cleanup_failed", _CLEANUP_ERROR) from error
        count = _count_packets(stage, cancel)
        try:
            current = _source_fingerprint(source)
            final_hash, final_bytes = _hash_source(source, cancel)
            final = _source_fingerprint(source)
        except (OSError, RuntimeError) as error:
            raise SparcError("capture_source_unavailable", "Saved capture source is unavailable") from error
        if current != before or final != before or final_hash != source_hash or final_bytes != source_bytes:
            raise SparcError("capture_source_changed", "Saved capture changed during export")
        with stage.open("rb") as handle:
            os.fsync(handle.fileno())
        _preflight(source, destination)
        output_bytes = _replace_and_sync(stage, destination, cancel)
    except BaseException as error:
        primary = error
    finally:
        if process is not None and not reaped:
            try:
                _reap(process)
            except BaseException as error:
                cleanup_error = error
        for handle in (stdout, stderr):
            if handle is not None and not handle.closed:
                try:
                    handle.close()
                except BaseException as error:
                    cleanup_error = error
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError as error:
                cleanup_error = error
        if stage is not None:
            try:
                stage.unlink(missing_ok=True)
            except OSError as error:
                cleanup_error = error
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    if cleanup_error is not None:
        if not isinstance(cleanup_error, Exception):
            raise cleanup_error
        raise SparcError("capture_cleanup_failed", _CLEANUP_ERROR) from cleanup_error
    if primary is not None:
        if isinstance(primary, SparcError):
            raise primary
        raise SparcError("traffic_xml_failed", _XML_ERROR) from primary
    elapsed = time.perf_counter_ns() - started_ns
    return ConversionResult(
        complete=True, packet_count=count, elapsed_ns=elapsed,
        source_bytes=source_bytes, output_bytes=output_bytes,
        packets_s=count * 1_000_000_000 / elapsed if elapsed > 0 else None,
        versions=versions,
        metadata={
            "source_name": source.name, "source_sha256": source_hash,
            "display_filter": None, "evidence_type": "unspecified",
            "definitions": {"xml": "Unfiltered TShark PDML; encrypted application content remains encrypted"},
            "measurement_scope": "xml_through_final_publication",
        },
    )
