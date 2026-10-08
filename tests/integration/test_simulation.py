"""Independent-process evidence contracts for the secure peer simulation."""

from __future__ import annotations

import hashlib
import importlib
import json
import multiprocessing
import multiprocessing.process
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from sparc.audit import verify_log
from sparc.identity import load_identity
from sparc.models import SparcError


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _simulation_module():
    return importlib.import_module("scripts.simulate_peers")


def _child_pids() -> set[int]:
    return {child.pid for child in multiprocessing.active_children() if child.pid is not None}


def _forbid_process_start(monkeypatch):
    starts = []

    def fail_start(_process, *_args, **_kwargs):
        starts.append(True)
        raise AssertionError("invalid simulation input attempted to start a child")

    monkeypatch.setattr(multiprocessing.process.BaseProcess, "start", fail_start)
    return starts


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    source_path = str(PROJECT_ROOT / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    return environment


def _child_main_then_bob_exits_nonzero(peer_name, data_dir, port, text, connection):
    """Real child entry point with a post-FINAL abnormal Bob exit for regression coverage."""
    from scripts.simulate_peers import _child_main

    _child_main(peer_name, data_dir, port, text, connection)
    if peer_name == "bob":
        os._exit(23)


def test_simulation_is_two_processes_and_two_identities(tmp_path):
    module = _simulation_module()
    root = tmp_path / "simulation"
    text = "Independent peers say café 雪 🚀\nand preserve the newline."
    before = _child_pids()
    started = time.monotonic()

    report = module.run_simulation(root, text=text)

    assert time.monotonic() - started < 30
    assert report["evidence_mode"] == "simulation"
    assert report["complete"] is True
    assert isinstance(report["elapsed_ns"], int) and report["elapsed_ns"] >= 0
    assert set(report) == {
        "evidence_mode", "complete", "elapsed_ns", "peers", "pairing",
        "transfers", "failures", "cleanup",
    }
    assert report["failures"] == []
    assert report["cleanup"] == {"all_children_stopped": True, "terminated": [], "killed": []}

    peers = report["peers"]
    assert set(peers) == {"alice", "bob"}
    alice = peers["alice"]
    bob = peers["bob"]
    coordinator_pid = os.getpid()
    pids = {alice["pid"], bob["pid"]}
    assert None not in pids and len(pids) == 2 and coordinator_pid not in pids
    assert alice["fingerprint"] != bob["fingerprint"]
    assert Path(alice["data_dir"]) == (root.resolve() / "alice")
    assert Path(bob["data_dir"]) == (root.resolve() / "bob")
    assert alice["data_dir"] != bob["data_dir"]

    for name, peer in peers.items():
        assert peer["endpoint"] == {
            "ip": "127.0.0.1",
            "port": peer["endpoint"]["port"],
        }
        assert type(peer["endpoint"]["port"]) is int
        assert 1 <= peer["endpoint"]["port"] <= 65535
        assert Path(peer["audit_path"]) == Path(peer["data_dir"]) / "audit.jsonl"
        assert Path(peer["checkpoint_path"]) == Path(peer["data_dir"]) / "simulation-checkpoint.json"
        assert peer["audit"]["valid"] is True
        assert peer["audit"]["checkpoint_checked"] is True
        assert peer["audit"]["verified_records"] > 0
        assert peer["audit"]["elapsed_ns"] >= 0

    pairing = report["pairing"]
    assert len(pairing) == 2
    assert {item["peer"] for item in pairing} == {"alice", "bob"}
    for item in pairing:
        own = peers[item["peer"]]
        other_name = "bob" if item["peer"] == "alice" else "alice"
        assert item["request_id"]
        assert item["own_fingerprint"] == own["fingerprint"]
        assert item["candidate_fingerprint"] == peers[other_name]["fingerprint"]
        assert item["expected_fingerprint"] == peers[other_name]["fingerprint"]
        assert item["approved"] is True

    expected_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert len(report["transfers"]) == 2
    assert {(item["from"], item["to"]) for item in report["transfers"]} == {
        ("alice", "bob"), ("bob", "alice")
    }
    for transfer in report["transfers"]:
        assert transfer["message_id"]
        assert transfer["plaintext_bytes"] == len(text.encode("utf-8"))
        assert transfer["expected_sha256"] == expected_digest
        assert transfer["sender_sha256"] == expected_digest
        assert transfer["receiver_sha256"] == expected_digest
        assert transfer["text_matches"] is True
        assert transfer["verified"] is True
        receipt = transfer["receipt"]
        assert receipt["message_id"] == transfer["message_id"]
        assert receipt["plaintext_bytes"] == transfer["plaintext_bytes"]
        assert receipt["characters"] == len(text)
        assert receipt["started_ns"] > 0
        assert receipt["finished_ns"] >= receipt["started_ns"]

    for name, peer in peers.items():
        identity = load_identity(Path(peer["data_dir"]))
        assert identity.fingerprint == peer["fingerprint"]
        retained = verify_log(
            Path(peer["audit_path"]),
            identity.public_bytes,
            Path(peer["checkpoint_path"]),
        )
        assert retained.valid is True
        assert retained.checkpoint_checked is True
        assert retained.verified_records == peer["audit"]["verified_records"]
    assert _child_pids() == before


def test_child_failure_is_incomplete_and_cleanup_finite(tmp_path):
    module = _simulation_module()
    root = tmp_path / "broken-simulation"
    bob_dir = root / "bob"
    bob_dir.mkdir(parents=True)
    (bob_dir / "identity.json").write_text("{ malformed identity", encoding="utf-8")
    before = _child_pids()
    started = time.monotonic()

    report = module.run_simulation(root)

    wall_seconds = time.monotonic() - started
    assert wall_seconds < 15
    assert report["complete"] is False
    assert report["evidence_mode"] == "simulation"
    bob = report["peers"]["bob"]
    failures = report["failures"]
    assert any(
        failure["peer"] == "bob" and failure["phase"] == "startup"
        for failure in failures
    )
    assert bob["fingerprint"] is None
    assert bob["endpoint"] is None
    assert bob["audit"] is None
    assert not any("Traceback" in failure["reason"] for failure in failures)
    assert not any("malformed identity" in failure["reason"] for failure in failures)
    assert all(not transfer["verified"] for transfer in report["transfers"])
    assert report["cleanup"]["all_children_stopped"] is True
    assert _child_pids() == before


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"port_a": True}, "invalid_port"),
        ({"port_b": False}, "invalid_port"),
        ({"port_a": -1}, "invalid_port"),
        ({"port_b": 65536}, "invalid_port"),
        ({"port_a": 47656, "port_b": 47656}, "invalid_port"),
        ({"text": ""}, "invalid_text"),
        ({"text": "x" * 16385}, "invalid_text"),
        ({"text": "\ud800"}, "invalid_text"),
        ({"text": 7}, "invalid_text"),
    ],
)
def test_invalid_arguments_fail_before_spawning(tmp_path, monkeypatch, overrides, code):
    module = _simulation_module()
    before = _child_pids()
    starts = _forbid_process_start(monkeypatch)
    with pytest.raises(SparcError) as raised:
        module.run_simulation(tmp_path / "not-created", **overrides)
    assert raised.value.code == code
    assert starts == []
    assert _child_pids() == before


def test_existing_file_root_is_invalid_schema_before_spawning(tmp_path, monkeypatch):
    module = _simulation_module()
    root_file = tmp_path / "not-a-directory"
    root_file.write_text("occupied", encoding="utf-8")
    before = _child_pids()
    starts = _forbid_process_start(monkeypatch)

    with pytest.raises(SparcError) as raised:
        module.run_simulation(root_file)

    assert raised.value.code == "invalid_schema"
    assert starts == []
    assert _child_pids() == before


def test_simulation_reuses_valid_pins_without_fabricating_approval(tmp_path):
    module = _simulation_module()
    root = tmp_path / "reused-simulation"
    before = _child_pids()

    first = module.run_simulation(root, text="first pass: café\n雪")
    assert first["complete"] is True
    assert first["pairing"]
    original_fingerprints = {
        name: first["peers"][name]["fingerprint"] for name in ("alice", "bob")
    }
    assert _child_pids() == before

    second = module.run_simulation(root, text="second pass: 🚀\nretained pins")

    assert second["complete"] is True
    assert second["failures"] == []
    assert second["cleanup"] == {"all_children_stopped": True, "terminated": [], "killed": []}
    assert {
        name: second["peers"][name]["fingerprint"] for name in ("alice", "bob")
    } == original_fingerprints
    assert len(second["pairing"]) < 2
    for item in second["pairing"]:
        own_name = item["peer"]
        other_name = "bob" if own_name == "alice" else "alice"
        assert item["request_id"]
        assert item["own_fingerprint"] == original_fingerprints[own_name]
        assert item["candidate_fingerprint"] == original_fingerprints[other_name]
        assert item["expected_fingerprint"] == original_fingerprints[other_name]
        assert item["approved"] is True
    assert len(second["transfers"]) == 2
    assert {(item["from"], item["to"]) for item in second["transfers"]} == {
        ("alice", "bob"), ("bob", "alice")
    }
    assert all(item["verified"] and item["text_matches"] for item in second["transfers"])
    assert all(
        second["peers"][name]["audit"]["valid"]
        and second["peers"][name]["audit"]["checkpoint_checked"]
        for name in ("alice", "bob")
    )
    assert _child_pids() == before


def test_transfer_evidence_validator_matches_pending_and_mismatch_cases():
    validate = _simulation_module()._validate_transfer_evidence
    digest = "a" * 64
    expected = {
        "message_id": "message-1",
        "sha256": digest,
        "plaintext_bytes": 7,
        "text_matches": True,
    }
    receipt = {"message_id": "message-1", "plaintext_bytes": 7, "characters": 5}

    verified, mismatch = validate(
        digest, 7, "message-1", 5,
        outgoing=expected,
        incoming=expected,
        receipt=receipt,
    )
    assert verified is True
    assert mismatch is None

    verified, mismatch = validate(digest, 7, "message-1", 5, outgoing=expected)
    assert verified is False
    assert mismatch is None

    mismatch_cases = [
        ("receiver", expected, {**expected, "text_matches": False}, receipt),
        ("receiver", expected, {**expected, "plaintext_bytes": 8}, receipt),
        ("receiver", expected, {**expected, "sha256": "b" * 64}, receipt),
        ("sender", {**expected, "plaintext_bytes": 8}, expected, receipt),
        ("sender", {**expected, "sha256": "b" * 64}, expected, receipt),
        ("sender", expected, expected, {**receipt, "message_id": "message-2"}),
        ("sender", expected, expected, {**receipt, "plaintext_bytes": 8}),
        ("sender", expected, expected, {**receipt, "characters": 6}),
    ]
    for expected_side, outgoing, incoming, changed_receipt in mismatch_cases:
        verified, mismatch = validate(
            digest,
            7,
            "message-1",
            5,
            outgoing=outgoing,
            incoming=incoming,
            receipt=changed_receipt,
        )
        assert verified is False
        assert mismatch is not None
        assert mismatch[0] == expected_side


@pytest.mark.parametrize(
    ("incoming", "receipt", "side"),
    [
        (
            {"message_id": "message-1", "sha256": "a" * 64, "plaintext_bytes": 7, "text_matches": False},
            {"message_id": "message-1", "plaintext_bytes": 7, "characters": 5},
            "receiver",
        ),
        (
            {"message_id": "message-1", "sha256": "a" * 64, "plaintext_bytes": 7, "text_matches": True},
            {"message_id": "wrong-id", "plaintext_bytes": 7, "characters": 5},
            "sender",
        ),
    ],
)
def test_transfer_evidence_mismatch_stays_sticky_and_aborts_dispatch(incoming, receipt, side):
    module = _simulation_module()
    validate = module._validate_transfer_evidence
    advance = module._advance_transfer
    expected = {
        "message_id": "message-1",
        "sha256": "a" * 64,
        "plaintext_bytes": 7,
        "text_matches": True,
    }
    verified, mismatch = validate(
        "a" * 64,
        7,
        "message-1",
        5,
        outgoing=expected,
        incoming=incoming,
        receipt=receipt,
    )
    assert verified is False
    assert mismatch is not None and mismatch[0] == side
    failures = [{
        "peer": "bob" if side == "receiver" else "alice",
        "phase": "transfer",
        "code": "evidence_mismatch",
        "reason": mismatch[1],
    }]
    # A later duplicate event must not erase the failure or dispatch Bob's send.
    transfers = [{"verified": True}, {"verified": False}]
    begin_calls = []

    def forbidden_begin(index):
        begin_calls.append(index)
        raise AssertionError("a failed run dispatched another transfer")

    active = advance(0, transfers, {0}, failures, forbidden_begin)

    assert active == 0
    assert begin_calls == []
    assert failures[0]["code"] == "evidence_mismatch"
    assert module._can_finalize({"alice", "bob"}, failures) is False


def test_transfer_advance_dispatches_next_direction_only_after_verified_alice():
    module = _simulation_module()
    advance = module._advance_transfer
    transfers = [{"verified": True}, {"verified": False}]
    sent = {0}
    calls = []

    def begin(index):
        calls.append(index)
        sent.add(index)
        return True

    active = advance(0, transfers, sent, [], begin)

    assert active == 1
    assert calls == [1]
    assert sent == {0, 1}
    assert advance(1, [{"verified": True}, {"verified": False}], sent, [], begin) == 1
    assert calls == [1]
    assert advance(1, [{"verified": True}, {"verified": True}], sent, [], begin) is None
    assert calls == [1]


@pytest.mark.parametrize(
    ("state", "reason", "intentional", "verified", "failures", "ignored"),
    [
        ("error", "tcp_loss", False, True, [], False),
        ("error", "tcp_loss", True, False, [], False),
        ("error", "tcp_loss", True, True, [], True),
        ("error", "tcp_loss", True, True, [{"code": "earlier_error"}], False),
        ("error", "audit_storage_failed", True, True, [], False),
        ("error", "changed_identity", True, True, [], False),
        ("error", "signature_failed", True, True, [], False),
        ("stopped", "tcp_loss", True, True, [], False),
    ],
)
def test_shutdown_state_classifier_suppresses_only_expected_tcp_loss(
    state, reason, intentional, verified, failures, ignored
):
    classify = _simulation_module()._should_ignore_state_error
    rows = [{"verified": verified}, {"verified": verified}]
    assert classify(state, reason, intentional, rows, failures) is ignored


def test_finalization_requires_both_network_stopped_acknowledgements():
    can_finalize = _simulation_module()._can_finalize
    assert can_finalize({"alice"}, []) is False
    assert can_finalize({"alice", "bob"}, []) is True
    assert can_finalize({"alice", "bob"}, [{"code": "prior_error"}]) is False


def test_network_quiescence_requires_drained_terminal_state_for_both_ack_paths():
    module = _simulation_module()
    quiescent = module._network_quiescent
    accept_ack = module._accept_network_stopped_ack

    for state in ("stopped", "error"):
        assert quiescent(
            state=state,
            connected_peer=None,
            listener_stopped=True,
            lifecycle_events_drained=True,
        ) is True

    for state in ("connected", "connecting", "handshaking", "reconnecting", "listening", None):
        assert quiescent(
            state=state,
            connected_peer=None,
            listener_stopped=True,
            lifecycle_events_drained=True,
        ) is False

    # No connected peer alone is not enough: in-flight lifecycle events mean
    # the child has not reached a stable point for final audit export.
    assert quiescent(
        state="stopped",
        connected_peer=None,
        listener_stopped=True,
        lifecycle_events_drained=False,
    ) is False
    assert quiescent(
        state="stopped",
        connected_peer="peer-1",
        listener_stopped=True,
        lifecycle_events_drained=True,
    ) is False
    assert quiescent(
        state="stopped",
        connected_peer=None,
        listener_stopped=False,
        lifecycle_events_drained=True,
    ) is False

    stopped = set()
    rejected = {
        "kind": "NETWORK_STOPPED",
        "peer": "alice",
        "listener_stopped": True,
        "connected_peer": False,
        "state": "handshaking",
        "lifecycle_events_drained": True,
    }
    assert accept_ack("alice", rejected, stopped) is False
    assert stopped == set()
    assert module._can_finalize(stopped, []) is False

    accepted = {
        **rejected,
        "state": "stopped",
    }
    assert accept_ack("alice", accepted, stopped) is True
    assert stopped == {"alice"}
    assert module._can_finalize(stopped, []) is False


def test_child_nonzero_exit_after_final_preserves_evidence_but_fails_completion(
    tmp_path, monkeypatch
):
    module = _simulation_module()
    monkeypatch.setattr(module, "_child_main", _child_main_then_bob_exits_nonzero)
    root = tmp_path / "post-final-nonzero-exit"
    before = _child_pids()
    started = time.monotonic()

    report = module.run_simulation(root, text="Post-final exit check: café\n雪")

    elapsed = time.monotonic() - started
    assert elapsed < 30
    assert report["complete"] is False
    assert len(report["transfers"]) == 2
    assert {(item["from"], item["to"]) for item in report["transfers"]} == {
        ("alice", "bob"), ("bob", "alice")
    }
    assert all(item["verified"] and item["text_matches"] for item in report["transfers"])
    for name in ("alice", "bob"):
        peer = report["peers"][name]
        assert peer["audit"]["valid"] is True
        assert peer["audit"]["checkpoint_checked"] is True
        assert peer["audit"]["verified_records"] > 0
        identity = load_identity(Path(peer["data_dir"]))
        audited = verify_log(
            Path(peer["audit_path"]), identity.public_bytes, Path(peer["checkpoint_path"])
        )
        assert audited.valid is True
        assert audited.checkpoint_checked is True
        assert audited.verified_records == peer["audit"]["verified_records"]

    assert any(
        failure["peer"] == "bob"
        and failure["phase"] == "cleanup"
        and failure["code"] == "child_exit_failed"
        for failure in report["failures"]
    )
    assert report["cleanup"]["all_children_stopped"] is True
    assert report["cleanup"]["terminated"] == []
    assert report["cleanup"]["killed"] == []
    assert _child_pids() == before


def test_audit_finalization_rejects_a_moving_or_unverified_head():
    stable = _simulation_module()._audit_finalization_is_stable
    before = {
        "log_id": "log-1",
        "last_record_number": 7,
        "last_record_hash": "a" * 64,
        "identity_fingerprint": "b" * 64,
    }
    after = dict(before)
    valid_report = {"valid": True, "checkpoint_checked": True, "verified_records": 7}
    assert stable(before, after, valid_report) is True
    assert stable(before, {**after, "last_record_number": 8}, valid_report) is False
    assert stable(before, {**after, "last_record_hash": "c" * 64}, valid_report) is False
    assert stable(before, {**after, "log_id": "log-2"}, valid_report) is False
    assert stable(before, after, {**valid_report, "verified_records": 6}) is False
    assert stable(before, after, {**valid_report, "valid": False}) is False
    assert stable(before, after, {**valid_report, "checkpoint_checked": False}) is False


@pytest.mark.parametrize("origin", ["incoming", "outgoing"])
def test_message_event_projection_uses_utf8_text_bytes_without_forwarding_text(origin):
    project = _simulation_module()._project_message_event
    digest = "a" * 64
    inspection = SimpleNamespace(
        sha256=digest,
        computed_sha256=digest,
        plaintext_bytes=999,
    )
    event_data = {
        "message_id": "message-1",
        "origin": origin,
        "text": "雪\n",
        "inspection": inspection,
    }

    message = project("bob", event_data, "雪\n")

    assert message["kind"] == "MESSAGE"
    assert message["peer"] == "bob"
    assert message["message_id"] == "message-1"
    assert message["origin"] == origin
    assert message["sha256"] == digest
    assert message["plaintext_bytes"] == len("雪\n".encode("utf-8"))
    assert message["plaintext_bytes"] != inspection.plaintext_bytes
    assert message["text_matches"] is True
    assert "text" not in message


def test_module_import_is_inert_and_cli_writes_json_report(tmp_path):
    import_probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import multiprocessing.process; "
            "multiprocessing.process.BaseProcess.start = "
            "lambda self: (_ for _ in ()).throw(AssertionError('process started on import')); "
            "import scripts.simulate_peers",
        ],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert import_probe.returncode == 0, import_probe.stderr

    root = tmp_path / "cli-simulation"
    report_path = tmp_path / "simulation-report.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/simulate_peers.py",
            "--data-root",
            str(root),
            "--report",
            str(report_path),
        ],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=40,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    cli_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert cli_report["complete"] is True
    assert cli_report["evidence_mode"] == "simulation"
