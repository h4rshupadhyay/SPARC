"""Behavioral contracts for finite PDML export and publication."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import threading

import pytest


def _pdml_module():
    try:
        return importlib.import_module("sparc.traffic.pdml")
    except ModuleNotFoundError as error:
        if error.name == "sparc.traffic.pdml":
            pytest.fail("T2c PDML export implementation is not present yet", pytrace=False)
        raise


def _error(call, code):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        call()
    assert caught.value.code == code
    return caught.value


class _Child:
    def __init__(self, stdout, stderr, *, returncode=0, poll_values=None):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.poll_values = iter(poll_values or [returncode])
        self.calls = []

    def poll(self):
        return next(self.poll_values, self.returncode)

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        return self.returncode

    def terminate(self):
        self.calls.append(("terminate",))

    def kill(self):
        self.calls.append(("kill",))


def _configure(monkeypatch, module, *, xml=b"<pdml/>", returncode=0, stderr=b""):
    import sparc.traffic.capture as capture

    calls = []
    child = None

    def find_tshark(_path):
        return Path("/tools/tshark with spaces; 'quoted'")

    def popen(argv, **kwargs):
        nonlocal child
        calls.append((argv, kwargs))
        kwargs["stdout"].write(xml)
        kwargs["stderr"].write(stderr)
        child = _Child(kwargs["stdout"], kwargs["stderr"], returncode=returncode)
        return child

    monkeypatch.setattr(capture, "find_tshark", find_tshark)
    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(module, "_observe_versions", lambda _t, _c: {
        "python": "3", "pyshark": None, "tshark": "TShark 4"
    })
    return calls, lambda: child


def test_export_uses_exact_unfiltered_argv_and_file_streams(tmp_path, monkeypatch):
    module = _pdml_module()
    source = tmp_path / "source ; 'quoted'.pcap"
    destination = tmp_path / "output with spaces.pdml"
    source.write_bytes(b"capture")
    calls, child = _configure(
        monkeypatch, module,
        xml=b"<pdml><packet><proto><field name='nested'><packet/></field></proto></packet><packet/></pdml>",
    )

    result = module.export_xml(source, destination, Path("ignored"), threading.Event())

    argv, kwargs = calls[0]
    assert argv == [
        "/tools/tshark with spaces; 'quoted'", "-n", "-r", str(source), "-T", "pdml"
    ]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is module.subprocess.DEVNULL
    assert kwargs["stdout"] is not module.subprocess.PIPE
    assert kwargs["stderr"] is not module.subprocess.PIPE
    assert result.complete is True
    assert result.packet_count == 2
    assert result.source_bytes == len(b"capture")
    assert result.output_bytes == destination.stat().st_size
    assert result.metadata["display_filter"] is None
    assert result.metadata["measurement_scope"] == "xml_through_final_publication"
    assert destination.read_bytes().startswith(b"<pdml>")
    assert child() is not None
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("xml, count", [(b"<pdml/>", 0), (b"<pdml><packet/><packet/></pdml>", 2)])
def test_valid_pdml_and_empty_document_publish_actual_packet_count(tmp_path, monkeypatch, xml, count):
    module = _pdml_module()
    source = tmp_path / "in.pcap"
    destination = tmp_path / "out.pdml"
    source.write_bytes(b"capture")
    _configure(monkeypatch, module, xml=xml)

    result = module.export_xml(source, destination, Path("ignored"), threading.Event())
    assert result.packet_count == count
    assert destination.read_bytes() == xml


@pytest.mark.parametrize("xml", [b"<pdml><packet/></pdml><tail", b"<wrong/>"])
def test_invalid_pdml_preserves_selected_output_and_cleans_staging(tmp_path, monkeypatch, xml):
    module = _pdml_module()
    source = tmp_path / "in.pcap"
    destination = tmp_path / "out.pdml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"previous output")
    _configure(monkeypatch, module, xml=xml)

    error = _error(
        lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
        "traffic_xml_failed",
    )
    assert "previous" not in error.message
    assert destination.read_bytes() == b"previous output"
    assert not list(tmp_path.glob(f".{destination.name}.*"))


def test_nonzero_child_error_is_safe_and_preserves_output(tmp_path, monkeypatch):
    module = _pdml_module()
    source = tmp_path / "in.pcap"
    destination = tmp_path / "out.pdml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    secret = b"private packet path marker"
    _configure(monkeypatch, module, returncode=3, stderr=secret * 1000)

    error = _error(
        lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
        "traffic_xml_failed",
    )
    assert secret.decode() not in error.message
    assert destination.read_bytes() == b"prior"


def test_pre_cancel_does_not_mutate_source_or_selected_output(tmp_path):
    module = _pdml_module()
    source = tmp_path / "in.pcap"
    destination = tmp_path / "out.pdml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    before = (source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns)
    cancel = threading.Event()
    cancel.set()

    _error(lambda: module.export_xml(source, destination, Path("ignored"), cancel), "capture_cancelled")
    assert (source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns) == before
    assert destination.read_bytes() == b"prior"


@pytest.mark.parametrize("alias", ["same", "hardlink", "symlink"])
def test_source_destination_alias_is_rejected_before_process(tmp_path, monkeypatch, alias):
    module = _pdml_module()
    source = tmp_path / "in.pcap"
    source.write_bytes(b"capture")
    destination = {"same": source, "hardlink": tmp_path / "hard", "symlink": tmp_path / "sym"}[alias]
    if alias == "hardlink":
        os.link(source, destination)
    elif alias == "symlink":
        destination.symlink_to(source)
    popen_calls = []
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: popen_calls.append((a, k)))

    _error(lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()), "traffic_output_alias")
    assert popen_calls == []


@pytest.mark.parametrize("unreaped", [False, True])
def test_cancel_terminates_kills_and_requires_confirmed_reap(tmp_path, monkeypatch, unreaped):
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    cancel = threading.Event()
    _configure(monkeypatch, module)
    calls = []

    class Stalled(_Child):
        def poll(self):
            cancel.set()
            return None

        def wait(self, timeout=None):
            calls.append(("wait", timeout))
            if unreaped or not any(call[0] == "kill" for call in calls):
                raise module.subprocess.TimeoutExpired("tool", timeout)
            self.returncode = -9
            return -9

        def terminate(self):
            calls.append(("terminate",))

        def kill(self):
            calls.append(("kill",))

    def start(argv, **kwargs):
        return Stalled(kwargs["stdout"], kwargs["stderr"])

    monkeypatch.setattr(module.subprocess, "Popen", start)
    _error(lambda: module.export_xml(source, destination, Path("ignored"), cancel),
           "capture_cleanup_failed" if unreaped else "capture_cancelled")
    assert calls == [("terminate",), ("wait", 2), ("kill",), ("wait", 2)]
    assert destination.read_bytes() == b"prior"
    assert source.read_bytes() == b"capture"
    assert set(tmp_path.iterdir()) == {source, destination}


def test_changed_source_prevents_publication(tmp_path, monkeypatch):
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    _configure(monkeypatch, module)
    original = module.subprocess.Popen

    def start(*args, **kwargs):
        child = original(*args, **kwargs)
        source.write_bytes(b"changed source")
        return child

    monkeypatch.setattr(module.subprocess, "Popen", start)
    _error(lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
           "capture_source_changed")
    assert destination.read_bytes() == b"prior"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("failure", ["file_sync", "replace", "directory_sync"])
def test_publication_failure_keeps_correct_output_and_no_staging(tmp_path, monkeypatch, failure):
    import stat
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    xml = b"<pdml><packet/></pdml>"
    _configure(monkeypatch, module, xml=xml)
    real_fsync = os.fsync

    def sync(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if (failure == "directory_sync" and directory) or (failure == "file_sync" and not directory):
            raise OSError("private path marker")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", sync)
    if failure == "replace":
        def replace(*args):
            raise OSError("private path marker")
        monkeypatch.setattr(os, "replace", replace)
    error = _error(lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
                   "traffic_publication_uncertain" if failure == "directory_sync" else "traffic_xml_failed")
    assert "private" not in error.message
    assert destination.read_bytes() == (xml if failure == "directory_sync" else b"prior")
    assert set(tmp_path.iterdir()) == {source, destination}


def test_symlinked_parent_alias_is_rejected(tmp_path, monkeypatch):
    module = _pdml_module()
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    source = real / "in.pcap"
    source.write_bytes(b"capture")
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("decoder launched"))
    _error(lambda: module.export_xml(source, alias / "in.pcap", Path("ignored"), threading.Event()),
           "traffic_output_alias")


def test_large_xml_releases_completed_root_children(tmp_path, monkeypatch):
    import xml.etree.ElementTree as ET
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    _configure(monkeypatch, module, xml=b"<pdml>" + b"<packet><proto><field/></proto></packet>" * 5000 + b"</pdml>")
    original = ET.iterparse
    retained = []

    def observe(*args, **kwargs):
        root = None
        for event, element in original(*args, **kwargs):
            if root is None:
                root = element
            yield event, element
            if event == "end" and element.tag == "packet":
                retained.append(len(root))

    monkeypatch.setattr(ET, "iterparse", observe)
    result = module.export_xml(source, destination, Path("ignored"), threading.Event())
    assert result.packet_count == 5000
    # ElementTree may read ahead by one input block; completed nodes must not
    # accumulate with packet count.
    assert max(retained) < 1000
    assert retained[-1] == 0


def test_elapsed_and_actual_sizes_are_measured(tmp_path, monkeypatch):
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    _configure(monkeypatch, module, xml=b"<pdml><packet/><packet/></pdml>")
    checkpoints = iter([10, 2_000_000_010])
    monkeypatch.setattr(module.time, "perf_counter_ns", lambda: next(checkpoints))
    result = module.export_xml(source, destination, Path("ignored"), threading.Event())
    assert result.elapsed_ns == 2_000_000_000
    assert result.packets_s == 1.0
    assert result.output_bytes == 31


def test_output_close_uncertainty_is_a_cleanup_failure(tmp_path, monkeypatch):
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    destination.write_bytes(b"prior")
    _configure(monkeypatch, module)
    original = os.fdopen

    class CloseFailure:
        def __init__(self, handle):
            self.handle = handle

        def close(self):
            self.handle.close()
            raise OSError("close status uncertain")

        def __getattr__(self, name):
            return getattr(self.handle, name)

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: CloseFailure(original(*a, **k)))
    _error(lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
           "capture_cleanup_failed")
    assert destination.read_bytes() == b"prior"


def test_directory_close_error_does_not_retry_a_released_descriptor(tmp_path, monkeypatch):
    import stat
    module = _pdml_module()
    source, destination = tmp_path / "in.pcap", tmp_path / "out.xml"
    source.write_bytes(b"capture")
    _configure(monkeypatch, module)
    original = os.close
    closed_directory = []
    calls = []

    def close(fd):
        if fd in closed_directory:
            calls.append(fd)
            raise OSError("descriptor may already belong to another worker")
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            calls.append(fd)
            closed_directory.append(fd)
            original(fd)
            raise OSError("close completion uncertain")
        return original(fd)

    monkeypatch.setattr(os, "close", close)
    _error(lambda: module.export_xml(source, destination, Path("ignored"), threading.Event()),
           "traffic_publication_uncertain")
    assert len(calls) == 1
    assert destination.read_bytes() == b"<pdml/>"
