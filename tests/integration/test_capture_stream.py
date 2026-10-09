"""Independent checks for the deterministic offline PCAP fixture and decoder."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import threading
from decimal import Decimal

import pytest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "tests" / "fixtures"
CAPTURE_PATH = FIXTURE_DIR / "traffic-small.pcap"
MANIFEST_PATH = FIXTURE_DIR / "traffic-small-manifest.json"
BUILDER_PATH = FIXTURE_DIR / "build_capture.py"

pytestmark = pytest.mark.tshark


def _require_file(path: Path, description: str) -> Path:
    if not path.is_file():
        pytest.fail(f"Required {description} is missing: {path}", pytrace=False)
    return path


def _load_manifest() -> dict:
    _require_file(CAPTURE_PATH, "synthetic PCAP fixture")
    _require_file(MANIFEST_PATH, "synthetic PCAP manifest")
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        pytest.fail(f"Synthetic PCAP manifest cannot be read: {error}", pytrace=False)
    assert isinstance(manifest, dict), "fixture manifest must be a JSON object"
    return manifest


def _load_builder():
    _require_file(BUILDER_PATH, "stdlib fixture builder")
    spec = importlib.util.spec_from_file_location("sparc_test_capture_builder", BUILDER_PATH)
    assert spec is not None and spec.loader is not None, "fixture builder cannot be loaded"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(getattr(module, "build_fixture", None)), "builder must expose build_fixture(destination)"
    return module


def _tshark_path() -> Path:
    explicit = os.environ.get("SPARC_TEST_TSHARK")
    if explicit:
        candidate = Path(explicit)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            pytest.fail("SPARC_TEST_TSHARK does not name an executable file", pytrace=False)
        return candidate.resolve()

    found = shutil.which("tshark")
    if found is None:
        pytest.skip("TShark is not installed or available on PATH")
    candidate = Path(found)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        pytest.fail("PATH resolved TShark to a non-executable file", pytrace=False)
    return candidate.resolve()


def _expected_packets() -> list[dict]:
    return [
        {
            "timestamp": Decimal("1"), "captured_length": 54, "wire_length": 54,
            "protocol": "TCP", "src": "10.0.0.1", "dst": "10.0.0.2",
            "src_port": 12345, "dst_port": 47655,
        },
        {
            "timestamp": Decimal("2"), "captured_length": 54, "wire_length": 54,
            "protocol": "TCP", "src": "10.0.0.2", "dst": "10.0.0.1",
            "src_port": 47655, "dst_port": 12345,
        },
        {
            "timestamp": Decimal("3"), "captured_length": 46, "wire_length": 46,
            "protocol": "UDP", "src": "10.0.0.1", "dst": "10.0.0.2",
            "src_port": 1111, "dst_port": 2222,
        },
        {
            "timestamp": Decimal("4"), "captured_length": 42, "wire_length": 42,
            "protocol": "ARP", "src": None, "dst": None,
            "src_port": None, "dst_port": None,
        },
        {
            "timestamp": Decimal("5"), "captured_length": 66, "wire_length": 66,
            "protocol": "UDP", "src": "2001:db8::1", "dst": "2001:db8::2",
            "src_port": 3333, "dst_port": 4444,
        },
    ]


def test_fixture_builder_is_stdlib_only_and_deterministic(tmp_path):
    module = _load_builder()
    tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"), filename=str(BUILDER_PATH))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= sys.stdlib_module_names, f"builder uses non-stdlib imports: {sorted(imported - sys.stdlib_module_names)}"

    first_path = tmp_path / "first.pcap"
    second_path = tmp_path / "second.pcap"
    first_manifest = module.build_fixture(first_path)
    second_manifest = module.build_fixture(second_path)
    assert isinstance(first_manifest, dict)
    assert first_manifest == second_manifest
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_manifest["source_sha256"] == hashlib.sha256(first_path.read_bytes()).hexdigest()
    assert len(first_path.read_bytes()) == 366


def test_fixture_source_hash_matches_manifest():
    manifest = _load_manifest()
    source = CAPTURE_PATH.read_bytes()
    assert len(source) == 366
    assert manifest["source_bytes"] == len(source)
    assert manifest["source_sha256"] == hashlib.sha256(source).hexdigest()


def test_fixture_decode_matches_manifest():
    manifest = _load_manifest()
    import pyshark  # noqa: F401 - missing decoder dependency is a test failure.

    tshark = _tshark_path()
    from sparc.traffic.capture import iter_capture

    rows = list(iter_capture(CAPTURE_PATH, tshark, threading.Event()))
    expected = _expected_packets()
    assert len(rows) == len(expected) == 5
    assert manifest["packet_count"] == 5
    assert manifest["source_bytes"] == 366
    assert manifest["captured_bytes"] == manifest["wire_bytes"] == 262
    manifest_packets = manifest["packets"]
    assert len(manifest_packets) == 5
    for index, (entry, packet) in enumerate(zip(manifest_packets, expected, strict=True), start=1):
        assert entry["number"] == index
        assert Decimal(str(entry["timestamp"])) == packet["timestamp"]
        assert entry["captured_length"] == packet["captured_length"]
        assert entry["wire_length"] == packet["wire_length"]
        assert entry["protocol"] == packet["protocol"]
        assert entry["src"] == packet["src"]
        assert entry["dst"] == packet["dst"]
        assert entry["src_port"] == packet["src_port"]
        assert entry["dst_port"] == packet["dst_port"]

    actual_bytes = sum(row.captured_length for row in rows)
    actual_wire_bytes = sum(row.wire_length for row in rows)
    assert actual_bytes == actual_wire_bytes == 262
    for index, (row, packet) in enumerate(zip(rows, expected, strict=True), start=1):
        assert row.number == index
        assert Decimal(row.timestamp) == packet["timestamp"]
        assert row.captured_length == packet["captured_length"]
        assert row.wire_length == packet["wire_length"]
        assert isinstance(row.highest_protocol, str) and row.highest_protocol.strip()
        if packet["protocol"] in {"TCP", "ARP"}:
            assert row.highest_protocol == packet["protocol"]
        assert row.src == packet["src"]
        assert row.dst == packet["dst"]
        assert row.src_port == packet["src_port"]
        assert row.dst_port == packet["dst_port"]
        if packet["protocol"] == "TCP":
            assert row.tcp_stream == 0
            assert row.tcp_flags == ("0x0002" if index == 1 else "0x0012")
            assert row.retransmission is None
        else:
            assert row.tcp_stream is None
            assert row.tcp_flags is None
            assert row.retransmission is None
    assert rows[3].src is rows[3].dst is None
    assert rows[3].src_port is rows[3].dst_port is None
