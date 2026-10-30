"""Offline command publication, safe errors and independently retained artifacts."""

import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Event

import pytest

from sparc.models import SparcError

SOURCE = Path(__file__).resolve().parents[1] / "fixtures" / "traffic-small.pcap"


def _module():
    try:
        return importlib.import_module("sparc.traffic.__main__")
    except ModuleNotFoundError as error:
        if error.name == "sparc.traffic.__main__":
            pytest.fail("Offline traffic CLI is not implemented", pytrace=False)
        raise


def _tool():
    from sparc.traffic.capture import find_tshark
    explicit = os.environ.get("SPARC_TEST_TSHARK")
    try:
        return find_tshark(Path(explicit) if explicit else None)
    except SparcError as error:
        if error.code == "tshark_missing":
            pytest.skip("TShark not available")
        raise


def test_missing_tool_exits_2_without_output_mutation(tmp_path, capsys):
    module = _module()
    report = tmp_path / "report.json"
    report.write_bytes(b"prior")
    code = module.main(["analyze", str(SOURCE), "--report", str(report), "--tshark", str(tmp_path / "absent")])
    output = capsys.readouterr()
    assert code == 2
    assert "TShark" in output.err
    assert report.read_bytes() == b"prior"
    assert output.out == ""


@pytest.mark.tshark
def test_success_exits_0_and_report_matches_index(tmp_path, capsys):
    module = _module()
    report, database, xml = tmp_path / "report.json", tmp_path / "index.sqlite", tmp_path / "details.xml"
    assert module.main(["analyze", str(SOURCE), "--report", str(report), "--sqlite", str(database),
                        "--xml", str(xml), "--tshark", str(_tool()), "--display-filter", "tcp.port == 47655"]) == 0
    value = json.loads(report.read_text())
    assert value["packet_count"] == 2
    assert value["captured_bytes_s"] == "108"
    assert value["duration_s"] == "1.000000000"
    assert value["metadata"]["display_filter"] == "tcp.port == 47655"
    assert value["bundle"]["complete"] is True
    assert value["bundle"]["xml_conversion"]["packet_count"] == 5
    assert value["bundle"]["xml_conversion"]["metadata"]["display_filter"] is None
    assert {entry["path"] for entry in value["bundle"]["artifacts"]} == {str(report), str(database), str(xml)}
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 2
        assert json.loads(connection.execute("SELECT value FROM metadata WHERE key='source_sha256'").fetchone()[0]) == value["metadata"]["source_sha256"]
    assert capsys.readouterr().err == ""


@pytest.mark.tshark
def test_malformed_capture_exits_1(tmp_path, capsys):
    module = _module()
    source, report = tmp_path / "bad.pcap", tmp_path / "report.json"
    source.write_bytes(b"private malformed capture marker")
    assert module.main(["analyze", str(source), "--report", str(report), "--tshark", str(_tool())]) == 1
    output = capsys.readouterr()
    assert "private malformed" not in output.err
    assert not report.exists()
    assert "Traceback" not in output.err


@pytest.mark.parametrize("duplicate", ["source_report", "report_index", "index_xml", "report_xml", "hardlink", "symlink"])
def test_alias_or_duplicate_output_rejected_before_mutation(tmp_path, monkeypatch, capsys, duplicate):
    module = _module()
    source = tmp_path / "input.pcap"
    source.write_bytes(SOURCE.read_bytes())
    report, database, xml = tmp_path / "new" / "report", tmp_path / "index", tmp_path / "xml"
    if duplicate == "source_report":
        report = source
    elif duplicate == "report_index":
        database = report
    elif duplicate == "index_xml":
        xml = database
    elif duplicate == "report_xml":
        xml = report
    elif duplicate == "hardlink":
        os.link(source, database)
    else:
        xml.symlink_to(source)
    monkeypatch.setattr(module, "import_sqlite", lambda *a, **k: pytest.fail("decoder started"))
    assert module.main(["analyze", str(source), "--report", str(report), "--sqlite", str(database), "--xml", str(xml)]) == 1
    assert source.read_bytes() == SOURCE.read_bytes()
    assert not (tmp_path / "new").exists()
    assert json.loads(capsys.readouterr().err)["completed_artifacts"] == []


@pytest.mark.tshark
def test_later_xml_failure_reports_completed_index_only(tmp_path, monkeypatch, capsys):
    module = _module()
    report, database, xml = tmp_path / "report", tmp_path / "index", tmp_path / "xml"
    report.write_bytes(b"prior report")
    xml.write_bytes(b"prior XML")
    def fail(*args):
        raise RuntimeError("private decoder/filter marker")
    monkeypatch.setattr(module, "export_xml", fail)
    assert module.main(["analyze", str(SOURCE), "--report", str(report), "--sqlite", str(database),
                        "--xml", str(xml), "--tshark", str(_tool())]) == 1
    output = capsys.readouterr()
    error = json.loads(output.err)
    assert error["complete"] is False
    assert error["completed_artifacts"] == [{"kind": "sqlite", "path": str(database), "complete": True}]
    assert database.is_file()
    assert report.read_bytes() == b"prior report"
    assert xml.read_bytes() == b"prior XML"
    assert "private" not in output.err
    assert output.out == ""


@pytest.mark.tshark
def test_json_durability_uncertainty_retains_candidate_and_reports_unconfirmed(tmp_path, monkeypatch, capsys):
    import stat
    module = _module()
    report = tmp_path / "report.json"
    real = os.fsync
    # Analysis happens in a different directory. Fail only the final report's
    # directory sync after replacement.
    def sync(fd):
        if report.exists() and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("private disk marker")
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    assert module.main(["analyze", str(SOURCE), "--report", str(report), "--tshark", str(_tool())]) == 1
    assert json.loads(report.read_text())["packet_count"] == 5
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["code"] == "traffic_publication_uncertain"
    assert error["unconfirmed_artifacts"] == [{"kind": "report", "path": str(report), "complete": False}]


@pytest.mark.tshark
def test_source_change_between_artifacts_cannot_report_complete_bundle(tmp_path, monkeypatch, capsys):
    module = _module()
    source, report, database = tmp_path / "source.pcap", tmp_path / "report", tmp_path / "index"
    source.write_bytes(SOURCE.read_bytes())
    original = module.import_sqlite
    def changing(*args, **kwargs):
        result = original(*args, **kwargs)
        source.write_bytes(b"changed source")
        return result
    monkeypatch.setattr(module, "import_sqlite", changing)
    assert module.main(["analyze", str(source), "--report", str(report), "--sqlite", str(database),
                        "--tshark", str(_tool())]) == 1
    assert not report.exists()
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["code"] == "capture_source_changed"
    assert len(error["completed_artifacts"]) == 1


@pytest.mark.tshark
@pytest.mark.parametrize("fault", ["serialization", "file_sync", "replace", "interrupt"])
def test_report_failure_preserves_prior_json_and_lists_completed_index(tmp_path, monkeypatch, capsys, fault):
    import stat
    module = _module()
    report, database = tmp_path / "report.json", tmp_path / "index.sqlite"
    report.write_bytes(b"prior report")
    real_dumps, real_sync, real_replace = json.dumps, os.fsync, os.replace
    if fault == "serialization":
        def dumps(value, *args, **kwargs):
            if isinstance(value, dict) and "bundle" in value:
                raise ValueError("private serialization marker")
            return real_dumps(value, *args, **kwargs)
        monkeypatch.setattr(json, "dumps", dumps)
    elif fault in {"file_sync", "interrupt"}:
        def sync(fd):
            if database.exists() and stat.S_ISREG(os.fstat(fd).st_mode):
                if fault == "interrupt":
                    raise KeyboardInterrupt
                raise OSError("private disk marker")
            return real_sync(fd)
        monkeypatch.setattr(os, "fsync", sync)
    else:
        def replace(source, destination):
            if Path(destination) == report:
                raise OSError("private path marker")
            return real_replace(source, destination)
        monkeypatch.setattr(os, "replace", replace)
    assert module.main(["analyze", str(SOURCE), "--report", str(report), "--sqlite", str(database),
                        "--tshark", str(_tool())]) == 1
    output = capsys.readouterr()
    assert "private" not in output.err
    diagnostic = json.loads(output.err)
    assert diagnostic["completed_artifacts"] == [{"kind": "sqlite", "path": str(database), "complete": True}]
    assert report.read_bytes() == b"prior report"
    assert set(tmp_path.iterdir()) == {report, database}
    assert output.out == ""
