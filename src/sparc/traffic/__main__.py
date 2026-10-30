"""Offline capture analysis and independently published evidence artifacts."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from decimal import Decimal
import json
import os
from pathlib import Path
import sys
import tempfile
from threading import Event

from sparc.models import SparcError
from .capture import find_tshark
from .pdml import export_xml
from .sqlite_index import (
    analyze_capture, import_sqlite, _hash_source, _preflight_public_paths,
    _replace_and_sync,
)


_MESSAGES = {
    "tshark_missing": "Install TShark or choose its executable with --tshark",
    "pyshark_missing": "Install the traffic Python extra: pip install '.[traffic]'",
    "capture_source_unavailable": "Saved capture source is unavailable",
    "capture_source_changed": "Saved capture changed between analysis operations",
    "capture_parse_failed": "Could not decode the saved capture",
    "capture_cancelled": "Offline traffic analysis was canceled",
    "capture_cleanup_failed": "Offline traffic cleanup could not be confirmed",
    "traffic_output_alias": "Capture source and output artifacts must be different files",
    "traffic_index_failed": "Could not build the traffic index",
    "traffic_summary_failed": "Could not summarize the completed traffic index",
    "traffic_xml_failed": "Could not export saved capture as PDML",
    "traffic_publication_uncertain": "Traffic artifact publication durability is uncertain",
    "traffic_cli_failed": "Could not complete offline traffic analysis",
}


def _preflight_bundle(source: Path, outputs: list[tuple[str, Path]]) -> None:
    for _kind, path in outputs:
        _preflight_public_paths(source, path)
    try:
        for position, (_kind, path) in enumerate(outputs):
            for _other_kind, other in outputs[position + 1:]:
                if path.resolve() == other.resolve() or (
                    path.exists() and other.exists() and os.path.samefile(path, other)
                ):
                    raise SparcError("traffic_output_alias", _MESSAGES["traffic_output_alias"])
    except (OSError, RuntimeError) as error:
        raise SparcError("traffic_cli_failed", _MESSAGES["traffic_cli_failed"]) from error


def _json_value(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _publish_report(source: Path, destination: Path, content: dict, cancel: Event) -> None:
    encoded = json.dumps(_json_value(content), sort_keys=True, ensure_ascii=True, allow_nan=False,
                         indent=2).encode("utf-8") + b"\n"
    stage = None
    fd = None
    try:
        if cancel.is_set():
            raise SparcError("capture_cancelled", _MESSAGES["capture_cancelled"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        stage = Path(name)
        handle = os.fdopen(fd, "wb")
        fd = None
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _preflight_public_paths(source, destination)
        _replace_and_sync(stage, destination, cancel)
    finally:
        try:
            if fd is not None:
                os.close(fd)
            if stage is not None:
                stage.unlink(missing_ok=True)
        except OSError as error:
            raise SparcError("capture_cleanup_failed", _MESSAGES["capture_cleanup_failed"]) from error


def _check_source(source: Path, expected: str, cancel: Event) -> None:
    try:
        actual, _size = _hash_source(source, cancel)
    except OSError as error:
        raise SparcError("capture_source_unavailable", _MESSAGES["capture_source_unavailable"]) from error
    if actual != expected:
        raise SparcError("capture_source_changed", _MESSAGES["capture_source_changed"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze externally saved captures without live capture privileges")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Analyze a saved capture and publish a JSON report")
    analyze.add_argument("capture", type=Path)
    analyze.add_argument("--report", type=Path, required=True)
    analyze.add_argument("--sqlite", type=Path)
    analyze.add_argument("--xml", type=Path, help="Unfiltered PDML, independent of --display-filter")
    analyze.add_argument("--tshark", type=Path)
    analyze.add_argument("--display-filter")
    args = parser.parse_args(argv)
    cancel = Event()
    completed = []
    active = None
    source_agreement = True
    outputs = [(kind, path) for kind, path in (
        ("sqlite", args.sqlite), ("xml", args.xml), ("report", args.report)
    ) if path is not None]

    def artifact(kind, path, complete=True):
        return {"kind": kind, "path": str(path), "complete": complete}

    try:
        _preflight_bundle(args.capture, outputs)
        tool = find_tshark(args.tshark)
        if args.sqlite is not None:
            active = artifact("sqlite", args.sqlite, False)
            report = import_sqlite(args.capture, args.sqlite, tool, cancel, args.display_filter)
            completed.append(artifact("sqlite", args.sqlite))
        else:
            report = analyze_capture(args.capture, tool, cancel, args.display_filter)
        active = None
        digest = report.metadata["source_sha256"]
        _check_source(args.capture, digest, cancel)
        xml_result = None
        if args.xml is not None:
            _preflight_bundle(args.capture, outputs)
            active = artifact("xml", args.xml, False)
            xml_result = export_xml(args.capture, args.xml, tool, cancel)
            completed.append(artifact("xml", args.xml))
            active = None
            if xml_result.metadata["source_sha256"] != digest:
                source_agreement = False
                raise SparcError("capture_source_changed", _MESSAGES["capture_source_changed"])
        _check_source(args.capture, digest, cancel)
        _preflight_bundle(args.capture, outputs)
        value = asdict(report)
        value["bundle"] = {
            "complete": True,
            "artifacts": [*completed, artifact("report", args.report)],
        }
        if xml_result is not None:
            value["bundle"]["xml_conversion"] = asdict(xml_result)
        active = artifact("report", args.report, False)
        _publish_report(args.capture, args.report, value, cancel)
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            cancel.set()
            code = "capture_cancelled"
        else:
            code = error.code if isinstance(error, SparcError) else "traffic_cli_failed"
        if code not in _MESSAGES:
            code = "traffic_cli_failed"
        diagnostic = {"complete": False, "completed_artifacts": completed,
                      "error": {"code": code, "message": _MESSAGES[code]}}
        if code == "traffic_publication_uncertain" and active is not None:
            diagnostic["unconfirmed_artifacts"] = [active]
        if not source_agreement:
            diagnostic["source_agreement"] = False
        print(json.dumps(diagnostic, ensure_ascii=True, sort_keys=True), file=sys.stderr)
        return 2 if code in {"tshark_missing", "pyshark_missing"} else 1
    print("Offline traffic analysis complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
