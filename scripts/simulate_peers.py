"""Run two independent SPARC peers for a local secure-session demonstration."""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time
from typing import Any


_PEER_NAMES = ("alice", "bob")
_MAX_TEXT_BYTES = 16 * 1024
_RUN_DEADLINE_SECONDS = 30.0
_STARTUP_DEADLINE_SECONDS = 10.0
_GRACEFUL_JOIN_SECONDS = 3.0
_TERMINATE_JOIN_SECONDS = 1.0
_KILL_JOIN_SECONDS = 1.0
_POLL_SECONDS = 0.1


def _safe_failure(peer: str, phase: str, code: str, reason: str) -> dict[str, str]:
    clean_code = code if isinstance(code, str) and code else "simulation_error"
    clean_reason = " ".join(reason.split())[:240] if isinstance(reason, str) else "operation failed"
    return {
        "peer": peer if peer in (*_PEER_NAMES, "coordinator") else "coordinator",
        "phase": phase[:40],
        "code": clean_code[:48],
        "reason": clean_reason or "operation failed",
    }


def _exception_failure(peer: str, phase: str, error: BaseException) -> dict[str, str]:
    from sparc.models import SparcError

    if isinstance(error, SparcError):
        return _safe_failure(peer, phase, error.code, error.message)
    return _safe_failure(peer, phase, "simulation_error", "The simulation operation failed")


def _report_value(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    return value


def _validate_transfer_evidence(
    expected_sha256: str,
    expected_bytes: int,
    expected_message_id: str,
    expected_characters: int,
    outgoing: dict[str, Any] | None = None,
    incoming: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
) -> tuple[bool, tuple[str, str] | None]:
    """Validate available correlated observations, preserving missing evidence as pending."""
    for side, observation in (("sender", outgoing), ("receiver", incoming)):
        if observation is None:
            continue
        if (
            observation.get("message_id") != expected_message_id
            or observation.get("sha256") != expected_sha256
            or observation.get("plaintext_bytes") != expected_bytes
            or observation.get("text_matches") is not True
        ):
            return False, (side, f"{side}_observation_mismatch")
    if receipt is not None and (
        receipt.get("message_id") != expected_message_id
        or receipt.get("plaintext_bytes") != expected_bytes
        or receipt.get("characters") != expected_characters
    ):
        return False, ("sender", "delivery_receipt_mismatch")
    if outgoing is None or incoming is None or receipt is None:
        return False, None
    return True, None


def _should_ignore_state_error(
    state: str,
    reason: str,
    intentional_shutdown_started: bool,
    transfer_rows: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> bool:
    """Classify only the transport close caused after verified intentional shutdown."""
    return bool(
        state == "error"
        and reason == "tcp_loss"
        and intentional_shutdown_started
        and not failures
        and transfer_rows
        and all(row.get("verified") is True for row in transfer_rows)
    )


def _can_finalize(network_stopped_peers: set[str], failures: list[dict[str, Any]]) -> bool:
    """Require both children to acknowledge public network quiescence before finalizing."""
    return not failures and set(_PEER_NAMES).issubset(network_stopped_peers)


def _network_quiescent(
    *,
    state: Any,
    connected_peer: Any,
    listener_stopped: Any,
    lifecycle_events_drained: Any,
) -> bool:
    """Accept only a stopped/error service with no session and drained lifecycle events."""
    return bool(
        state in {"stopped", "error"}
        and connected_peer is None
        and listener_stopped is True
        and lifecycle_events_drained is True
    )


def _accept_network_stopped_ack(
    peer: str,
    message: dict[str, Any],
    network_stopped_peers: set[str],
) -> bool:
    """Validate an IPC quiescence acknowledgement before updating the barrier."""
    if peer not in _PEER_NAMES or message.get("kind") != "NETWORK_STOPPED":
        return False
    connected_peer = None if message.get("connected_peer") is False else object()
    if not _network_quiescent(
        state=message.get("state"),
        connected_peer=connected_peer,
        listener_stopped=message.get("listener_stopped"),
        lifecycle_events_drained=message.get("lifecycle_events_drained"),
    ):
        return False
    network_stopped_peers.add(peer)
    return True


def _audit_finalization_is_stable(before_head: dict[str, Any], after_head: dict[str, Any], audit_report: Any) -> bool:
    """Check that export and verification describe one unchanged committed audit head."""
    head_fields = ("log_id", "last_record_number", "last_record_hash", "identity_fingerprint")
    if any(before_head.get(key) != after_head.get(key) for key in head_fields):
        return False
    if isinstance(audit_report, dict):
        valid = audit_report.get("valid")
        checkpoint_checked = audit_report.get("checkpoint_checked")
        verified_records = audit_report.get("verified_records")
    else:
        valid = getattr(audit_report, "valid", None)
        checkpoint_checked = getattr(audit_report, "checkpoint_checked", None)
        verified_records = getattr(audit_report, "verified_records", None)
    return bool(
        valid is True
        and checkpoint_checked is True
        and verified_records == after_head.get("last_record_number")
    )


def _project_message_event(peer_name: str, event_data: dict[str, Any], expected_text: str) -> dict[str, Any]:
    """Project a service message into bounded evidence without forwarding plaintext."""
    inspection = event_data.get("inspection")
    actual_text = event_data.get("text")
    try:
        plaintext_bytes = len(actual_text.encode("utf-8", errors="strict"))
        text_matches = actual_text == expected_text
    except (AttributeError, UnicodeEncodeError):
        plaintext_bytes = None
        text_matches = False
    if inspection is None:
        digest = None
    elif event_data.get("origin") == "outgoing":
        digest = getattr(inspection, "sha256", None)
    else:
        digest = getattr(inspection, "computed_sha256", None)
    return {
        "kind": "MESSAGE",
        "peer": peer_name,
        "message_id": event_data.get("message_id"),
        "origin": event_data.get("origin"),
        "sha256": digest,
        "plaintext_bytes": plaintext_bytes,
        "text_matches": text_matches,
    }


def _advance_transfer(
    active_index: int | None,
    transfers: list[dict[str, Any]],
    sent_indices: set[int],
    failures: list[dict[str, Any]],
    begin_transfer,
) -> int | None:
    """Advance the sequential send only after verified evidence and no failure."""
    if active_index is None or failures or not 0 <= active_index < len(transfers):
        return active_index
    if transfers[active_index].get("verified") is not True:
        return active_index
    if active_index == 0 and len(transfers) > 1 and 1 not in sent_indices:
        if begin_transfer(1):
            return 1
        return active_index
    if active_index == 1:
        return None
    return None


def _send_message(connection, message: dict[str, Any]) -> bool:
    try:
        connection.send(message)
        return True
    except (BrokenPipeError, EOFError, OSError):
        return False


def _child_main(
    peer_name: str,
    data_dir_value: str,
    requested_port: int,
    expected_text: str,
    connection,
) -> None:
    """Spawn target: own one service, forward bounded evidence, and always close it."""
    service = None
    phase = "startup"
    pending_network_ack = False
    network_ack_deadline = 0.0
    network_listener_stopped = False
    try:
        from sparc.peer.service import PeerService

        data_dir = Path(data_dir_value)
        service = PeerService(data_dir)
        endpoint = service.start_listener("127.0.0.1", requested_port)
        _send_message(connection, {
            "kind": "READY",
            "peer": peer_name,
            "pid": multiprocessing.current_process().pid,
            "fingerprint": service.own_fingerprint,
            "endpoint": {"ip": endpoint.ip, "port": endpoint.port},
        })

        running = True
        while running:
            if connection.poll(_POLL_SECONDS):
                try:
                    command = connection.recv()
                except (EOFError, OSError):
                    break
                action = command.get("action") if isinstance(command, dict) else None
                try:
                    if action == "CONNECT":
                        phase = "connect"
                        from sparc.models import Endpoint

                        endpoint_data = command["endpoint"]
                        service.connect(Endpoint(endpoint_data["ip"], endpoint_data["port"]))
                        _send_message(connection, {"kind": "COMMAND_DONE", "action": action})
                    elif action == "APPROVE":
                        phase = "pairing"
                        service.respond_to_pairing(command["request_id"], command["approved"])
                        _send_message(connection, {"kind": "COMMAND_DONE", "action": action})
                    elif action == "SEND":
                        phase = "transfer"
                        message_id = service.send_text(command["text"])
                        _send_message(connection, {
                            "kind": "SEND_RESULT",
                            "peer": peer_name,
                            "message_id": message_id,
                        })
                    elif action == "STOP_NETWORK":
                        phase = "network_shutdown"
                        service.stop_listener()
                        network_listener_stopped = True
                        service.disconnect()
                        connected = service.connected_peer()
                        if connected is not None:
                            from sparc.models import SparcError

                            raise SparcError("invalid_state", "Peer session remained connected after shutdown")
                        pending_network_ack = True
                        network_ack_deadline = time.monotonic() + 3.0
                    elif action == "FINALIZE":
                        phase = "finalize"
                        checkpoint_path = data_dir / "simulation-checkpoint.json"
                        before_head = service.audit_head()
                        service.export_audit_checkpoint(checkpoint_path)
                        audit = service.verify_audit(checkpoint_path)
                        after_head = service.audit_head()
                        if not _audit_finalization_is_stable(before_head, after_head, audit):
                            from sparc.models import SparcError

                            raise SparcError("audit_changed", "Audit head changed or failed verification during finalization")
                        _send_message(connection, {
                            "kind": "FINAL",
                            "peer": peer_name,
                            "audit": _report_value(audit),
                        })
                        running = False
                    elif action == "STOP":
                        running = False
                    else:
                        raise ValueError("unknown child command")
                except BaseException as error:
                    if isinstance(error, (KeyboardInterrupt, SystemExit)):
                        raise
                    _send_message(connection, {
                        "kind": "ERROR",
                        **_exception_failure(peer_name, phase, error),
                    })
                    if action in {"FINALIZE", "STOP"}:
                        running = False

            if service is None:
                continue
            lifecycle_events_drained = False
            for _ in range(1025):
                try:
                    event = service.events.get_nowait()
                except Exception:
                    lifecycle_events_drained = True
                    break
                data = event.data
                if event.kind == "pairing_request":
                    _send_message(connection, {
                        "kind": "PAIRING",
                        "peer": peer_name,
                        "request_id": data.get("request_id"),
                        "own_fingerprint": data.get("own_fingerprint"),
                        "candidate_fingerprint": data.get("candidate_fingerprint"),
                    })
                elif event.kind == "message":
                    _send_message(connection, _project_message_event(peer_name, data, expected_text))
                elif event.kind == "delivery":
                    _send_message(connection, {
                        "kind": "DELIVERY",
                        "peer": peer_name,
                        "message_id": data.get("message_id"),
                        "receipt": _report_value(data.get("receipt")),
                    })
                elif event.kind == "state":
                    _send_message(connection, {
                        "kind": "STATE",
                        "peer": peer_name,
                        "state": data.get("state"),
                        "reason": data.get("reason"),
                    })

            if pending_network_ack:
                if _network_quiescent(
                    state=service.state,
                    connected_peer=service.connected_peer(),
                    listener_stopped=network_listener_stopped,
                    lifecycle_events_drained=lifecycle_events_drained,
                ):
                    _send_message(connection, {
                        "kind": "NETWORK_STOPPED",
                        "peer": peer_name,
                        "listener_stopped": True,
                        "connected_peer": False,
                        "state": service.state,
                        "lifecycle_events_drained": lifecycle_events_drained,
                    })
                    pending_network_ack = False
                elif time.monotonic() >= network_ack_deadline:
                    _send_message(connection, {
                        "kind": "ERROR",
                        "peer": peer_name,
                        "phase": "network_shutdown",
                        "code": "quiescence_timeout",
                        "reason": "Peer lifecycle events did not quiesce after shutdown",
                    })
                    running = False

    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        _send_message(connection, {
            "kind": "ERROR",
            **_exception_failure(peer_name, phase, error),
        })
    finally:
        if service is not None:
            try:
                service.close()
            except Exception:
                _send_message(connection, {
                    "kind": "ERROR",
                    "peer": peer_name,
                    "phase": "cleanup",
                    "code": "service_close_failed",
                    "reason": "Peer service cleanup failed",
                })
        try:
            connection.close()
        except OSError:
            pass


def _empty_peer(data_dir: Path) -> dict[str, Any]:
    return {
        "pid": None,
        "fingerprint": None,
        "data_dir": str(data_dir),
        "endpoint": None,
        "audit_path": str(data_dir / "audit.jsonl"),
        "checkpoint_path": str(data_dir / "simulation-checkpoint.json"),
        "audit": None,
    }


def _empty_transfer(source: str, destination: str, text: str, expected_sha256: str) -> dict[str, Any]:
    return {
        "from": source,
        "to": destination,
        "message_id": None,
        "plaintext_bytes": len(text.encode("utf-8")),
        "expected_sha256": expected_sha256,
        "sender_sha256": None,
        "receiver_sha256": None,
        "text_matches": False,
        "receipt": None,
        "verified": False,
    }


def _validate_inputs(data_root: Any, port_a: Any, port_b: Any, text: Any) -> tuple[Path, bytes]:
    from sparc.models import SparcError

    try:
        root = Path(data_root).expanduser().resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        raise SparcError("invalid_schema", "Simulation data root must be a valid path") from exc
    if root.exists() and not root.is_dir():
        raise SparcError("invalid_schema", "Simulation data root must be a directory")
    for port in (port_a, port_b):
        if type(port) is not int or not 0 <= port <= 65535:
            raise SparcError("invalid_port", "Simulation ports must be integers from 0 through 65535")
    if port_a != 0 and port_a == port_b:
        raise SparcError("invalid_port", "Peer listeners cannot use the same nonzero port")
    if not isinstance(text, str) or not text:
        raise SparcError("invalid_text", "Simulation text must be a nonempty string")
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SparcError("invalid_text", "Simulation text must be valid UTF-8") from exc
    if not 1 <= len(encoded) <= _MAX_TEXT_BYTES:
        raise SparcError("invalid_text", "Simulation text must contain 1 through 16384 UTF-8 bytes")
    return root, encoded


def run_simulation(
    data_root: Path,
    port_a: int = 0,
    port_b: int = 0,
    text: str = "SPARC ✓",
) -> dict:
    """Start two spawn-based local peers and return observed security evidence."""
    from sparc.models import SparcError

    root, encoded_text = _validate_inputs(data_root, port_a, port_b, text)
    started_ns = time.perf_counter_ns()
    deadline = time.monotonic() + _RUN_DEADLINE_SECONDS
    expected_sha256 = hashlib.sha256(encoded_text).hexdigest()
    peer_dirs = {name: (root / name).resolve() for name in _PEER_NAMES}
    peers = {name: _empty_peer(peer_dirs[name]) for name in _PEER_NAMES}
    transfers = [
        _empty_transfer("alice", "bob", text, expected_sha256),
        _empty_transfer("bob", "alice", text, expected_sha256),
    ]
    report: dict[str, Any] = {
        "evidence_mode": "simulation",
        "complete": False,
        "elapsed_ns": 0,
        "peers": peers,
        "pairing": [],
        "transfers": transfers,
        "failures": [],
        "cleanup": {"all_children_stopped": True, "terminated": [], "killed": []},
    }
    processes: dict[str, Any] = {}
    connections: dict[str, Any] = {}
    started_names: list[str] = []
    ready: dict[str, dict[str, Any]] = {}
    exited: set[str] = set()
    finalized: set[str] = set()
    network_stopped: set[str] = set()
    connected_peers: set[str] = set()
    intentional_network_shutdown_started = False
    sent_network_stop = False
    sent_finalize = False
    active_transfer_index: int | None = None
    sent_transfer_indices: set[int] = set()
    observed_messages: dict[tuple[str, str, str], dict[str, Any]] = {}
    observed_receipts: dict[tuple[str, str], dict[str, Any]] = {}
    phase = "startup"

    def fail(peer: str, current_phase: str, code: str, reason: str) -> None:
        entry = _safe_failure(peer, current_phase, code, reason)
        if entry not in report["failures"]:
            report["failures"].append(entry)

    def send_command(peer: str, action: str, **values: Any) -> bool:
        connection = connections.get(peer)
        if connection is None:
            return False
        return _send_message(connection, {"action": action, **values})

    def begin_transfer(index: int) -> bool:
        nonlocal active_transfer_index
        transfer = transfers[index]
        source = transfer["from"]
        if not send_command(source, "SEND", text=text):
            fail(source, "transfer", "ipc_failed", "Could not send the bounded transfer command")
            return False
        sent_transfer_indices.add(index)
        active_transfer_index = index
        return True

    def update_transfer(index: int) -> None:
        transfer = transfers[index]
        message_id = transfer["message_id"]
        if not message_id:
            return
        source = transfer["from"]
        destination = transfer["to"]
        outgoing = observed_messages.get((source, message_id, "outgoing"))
        incoming = observed_messages.get((destination, message_id, "incoming"))
        receipt = observed_receipts.get((source, message_id))
        if outgoing is not None:
            transfer["sender_sha256"] = outgoing.get("sha256")
        if incoming is not None:
            transfer["receiver_sha256"] = incoming.get("sha256")
        if receipt is not None:
            transfer["receipt"] = receipt
        text_matches = bool(
            incoming is not None
            and incoming.get("text_matches") is True
            and incoming.get("sha256") == expected_sha256
            and incoming.get("plaintext_bytes") == transfer["plaintext_bytes"]
        )
        transfer["text_matches"] = text_matches
        verified, mismatch = _validate_transfer_evidence(
            expected_sha256,
            transfer["plaintext_bytes"],
            message_id,
            len(text),
            outgoing=outgoing,
            incoming=incoming,
            receipt=receipt,
        )
        transfer["verified"] = verified
        if mismatch is not None:
            side, _reason = mismatch
            observer = source if side == "sender" else destination
            fail(observer, "transfer", "evidence_mismatch", f"{side.title()} transfer evidence did not match")

    def handle(message: dict[str, Any]) -> None:
        nonlocal phase, active_transfer_index, sent_finalize
        kind = message.get("kind")
        peer = message.get("peer")
        if kind == "READY" and peer in _PEER_NAMES:
            ready[peer] = message
            peers[peer]["pid"] = message.get("pid")
            peers[peer]["fingerprint"] = message.get("fingerprint")
            peers[peer]["endpoint"] = message.get("endpoint")
        elif kind == "ERROR":
            fail(
                message.get("peer", "coordinator"),
                message.get("phase", phase),
                message.get("code", "child_error"),
                message.get("reason", "Child operation failed"),
            )
        elif kind == "PAIRING" and peer in _PEER_NAMES:
            own_ready = ready.get(peer)
            other = "bob" if peer == "alice" else "alice"
            other_ready = ready.get(other)
            own_match = bool(own_ready and message.get("own_fingerprint") == own_ready.get("fingerprint"))
            candidate_match = bool(
                other_ready and message.get("candidate_fingerprint") == other_ready.get("fingerprint")
            )
            approved = own_match and candidate_match
            report["pairing"].append({
                "peer": peer,
                "request_id": message.get("request_id"),
                "own_fingerprint": message.get("own_fingerprint"),
                "candidate_fingerprint": message.get("candidate_fingerprint"),
                "expected_fingerprint": other_ready.get("fingerprint") if other_ready else None,
                "approved": approved,
            })
            if not approved:
                fail(peer, "pairing", "fingerprint_mismatch", "Pairing fingerprints did not match READY identities")
            if not send_command(peer, "APPROVE", request_id=message.get("request_id"), approved=approved):
                fail(peer, "pairing", "ipc_failed", "Could not return the pairing decision")
        elif kind == "STATE" and peer in _PEER_NAMES:
            if message.get("state") == "error":
                reason = str(message.get("reason") or "Peer service entered error state")
                intentional_tcp_loss = _should_ignore_state_error(
                    message.get("state"),
                    reason,
                    intentional_network_shutdown_started,
                    transfers,
                    report["failures"],
                )
                if not intentional_tcp_loss:
                    fail(peer, phase, "peer_service_error", reason)
            elif message.get("state") == "connected":
                connected_peers.add(peer)
        elif kind == "MESSAGE" and peer in _PEER_NAMES:
            message_id = message.get("message_id")
            origin = message.get("origin")
            if isinstance(message_id, str) and origin in {"incoming", "outgoing"}:
                observed_messages[(peer, message_id, origin)] = message
                for index in sent_transfer_indices:
                    if transfers[index]["message_id"] == message_id:
                        update_transfer(index)
        elif kind == "DELIVERY" and peer in _PEER_NAMES:
            message_id = message.get("message_id")
            receipt = message.get("receipt")
            if isinstance(message_id, str) and isinstance(receipt, dict):
                observed_receipts[(peer, message_id)] = receipt
                for index in sent_transfer_indices:
                    if transfers[index]["message_id"] == message_id:
                        update_transfer(index)
        elif kind == "SEND_RESULT" and peer in _PEER_NAMES:
            if active_transfer_index is None or transfers[active_transfer_index]["from"] != peer:
                fail(peer, "transfer", "unexpected_send_result", "A send result did not match the active transfer")
                return
            transfer = transfers[active_transfer_index]
            transfer["message_id"] = message.get("message_id")
            update_transfer(active_transfer_index)
        elif kind == "FINAL" and peer in _PEER_NAMES:
            peers[peer]["audit"] = message.get("audit")
            finalized.add(peer)
        elif kind == "NETWORK_STOPPED" and peer in _PEER_NAMES:
            if not _accept_network_stopped_ack(peer, message, network_stopped):
                fail(peer, "network_shutdown", "quiescence_failed", "Peer did not confirm stopped networking")
        elif kind == "COMMAND_DONE":
            return

    try:
        root.mkdir(parents=True, exist_ok=True)
        context = multiprocessing.get_context("spawn")
        for name, port in (("alice", port_a), ("bob", port_b)):
            parent_connection, child_connection = context.Pipe(duplex=True)
            process = context.Process(
                target=_child_main,
                args=(name, str(peer_dirs[name]), port, text, child_connection),
                name=f"sparc-simulation-{name}",
            )
            try:
                process.start()
            except BaseException:
                parent_connection.close()
                child_connection.close()
                raise
            child_connection.close()
            processes[name] = process
            connections[name] = parent_connection
            started_names.append(name)

        startup_deadline = min(deadline, time.monotonic() + _STARTUP_DEADLINE_SECONDS)
        phase = "startup"
        while len(ready) < 2 and not report["failures"] and time.monotonic() < startup_deadline:
            for name in started_names:
                connection = connections.get(name)
                if connection is not None and connection.poll(0):
                    try:
                        handle(connection.recv())
                    except (EOFError, OSError):
                        fail(name, "startup", "child_exited", "Child closed its coordinator channel before READY")
                process = processes[name]
                if not process.is_alive() and name not in ready:
                    fail(name, "startup", "child_exited", "Child exited before reporting READY")
            time.sleep(0.01)
        if len(ready) != 2 and not report["failures"]:
            fail("coordinator", "startup", "startup_timeout", "Peer startup exceeded its bounded deadline")

        if not report["failures"]:
            phase = "connect"
            endpoint = ready["bob"]["endpoint"]
            if not send_command("alice", "CONNECT", endpoint=endpoint):
                fail("alice", "connect", "ipc_failed", "Could not command Alice to connect to Bob")

        while not report["failures"] and time.monotonic() < deadline:
            for name in started_names:
                connection = connections.get(name)
                if connection is None:
                    continue
                for _ in range(64):
                    if not connection.poll(0):
                        break
                    try:
                        handle(connection.recv())
                    except (EOFError, OSError):
                        if name not in finalized and name not in exited:
                            fail(name, phase, "child_channel_closed", "Child coordinator channel closed unexpectedly")
                        break
                    if report["failures"]:
                        break
                if report["failures"]:
                    break
                process = processes[name]
                if not process.is_alive() and name not in finalized and name not in exited:
                    exited.add(name)
                    fail(name, phase, "child_exited", "Child exited before simulation evidence was complete")

            if report["failures"]:
                break

            if (
                len(ready) == 2
                and connected_peers == set(_PEER_NAMES)
                and all(item.get("approved") is True for item in report["pairing"])
                and active_transfer_index is None
                and not sent_transfer_indices
            ):
                phase = "transfer"
                if not begin_transfer(0):
                    break

            if active_transfer_index is not None:
                update_transfer(active_transfer_index)
                if report["failures"]:
                    break
                active_transfer_index = _advance_transfer(
                    active_transfer_index,
                    transfers,
                    sent_transfer_indices,
                    report["failures"],
                    begin_transfer,
                )

            if report["failures"]:
                break

            if (
                not report["failures"]
                and len(sent_transfer_indices) == 2
                and all(row["verified"] for row in transfers)
                and not sent_network_stop
            ):
                phase = "network_shutdown"
                intentional_network_shutdown_started = True
                sent_network_stop = True
                for name in _PEER_NAMES:
                    if not send_command(name, "STOP_NETWORK"):
                        fail(name, "network_shutdown", "ipc_failed", "Could not request network shutdown")
            if sent_network_stop and _can_finalize(network_stopped, report["failures"]) and not sent_finalize:
                phase = "finalize"
                sent_finalize = True
                for name in _PEER_NAMES:
                    if not send_command(name, "FINALIZE"):
                        fail(name, "finalize", "ipc_failed", "Could not request peer audit finalization")
            if sent_finalize and len(finalized) == 2:
                break
            if time.monotonic() >= deadline:
                fail("coordinator", phase, "run_timeout", "Simulation exceeded its shared 30-second deadline")
                break
            time.sleep(0.01)

        if not report["failures"] and not sent_finalize:
            fail("coordinator", phase, "run_incomplete", "Simulation ended before all transfer evidence was observed")

    except SparcError as error:
        fail("coordinator", phase, error.code, error.message)
    except Exception:
        fail("coordinator", phase, "simulation_error", "The coordinator encountered an unexpected runtime failure")
    finally:
        def drain_cleanup_messages() -> None:
            for name, connection in connections.items():
                for _ in range(64):
                    if not connection.poll(0):
                        break
                    try:
                        handle(connection.recv())
                    except (EOFError, OSError):
                        break

        for name in started_names:
            process = processes.get(name)
            connection = connections.get(name)
            if process is not None and process.is_alive() and connection is not None:
                _send_message(connection, {"action": "STOP"})

        graceful_deadline = time.monotonic() + _GRACEFUL_JOIN_SECONDS
        while time.monotonic() < graceful_deadline:
            drain_cleanup_messages()
            alive = [process for process in processes.values() if process.is_alive()]
            if not alive:
                break
            for process in alive:
                process.join(timeout=min(0.05, max(0.0, graceful_deadline - time.monotonic())))

        survivors = [name for name, process in processes.items() if process.is_alive()]
        for name in survivors:
            try:
                processes[name].terminate()
                report["cleanup"]["terminated"].append(name)
            except (OSError, AttributeError):
                pass
        terminate_deadline = time.monotonic() + _TERMINATE_JOIN_SECONDS
        while time.monotonic() < terminate_deadline:
            drain_cleanup_messages()
            alive = [process for process in processes.values() if process.is_alive()]
            if not alive:
                break
            for process in alive:
                process.join(timeout=min(0.05, max(0.0, terminate_deadline - time.monotonic())))

        survivors = [name for name, process in processes.items() if process.is_alive()]
        for name in survivors:
            kill = getattr(processes[name], "kill", None)
            if callable(kill):
                try:
                    kill()
                    report["cleanup"]["killed"].append(name)
                except OSError:
                    pass
        kill_deadline = time.monotonic() + _KILL_JOIN_SECONDS
        while time.monotonic() < kill_deadline:
            drain_cleanup_messages()
            alive = [process for process in processes.values() if process.is_alive()]
            if not alive:
                break
            for process in alive:
                process.join(timeout=min(0.05, max(0.0, kill_deadline - time.monotonic())))

        drain_cleanup_messages()

        all_stopped = True
        for name, process in processes.items():
            if process.is_alive():
                all_stopped = False
                fail(name, "cleanup", "child_alive", "Operating system did not stop the child process")
            elif name in started_names:
                try:
                    exitcode = process.exitcode
                except (AssertionError, OSError, ValueError):
                    exitcode = None
                if exitcode != 0:
                    fail(name, "cleanup", "child_exit_failed", "Child process exited with a nonzero status")
            try:
                process.join(timeout=0)
                process.close()
            except (AssertionError, OSError, ValueError):
                pass
        for connection in connections.values():
            try:
                connection.close()
            except OSError:
                pass
        report["cleanup"]["all_children_stopped"] = all_stopped
        if report["cleanup"]["terminated"] or report["cleanup"]["killed"]:
            fail("coordinator", "cleanup", "forced_cleanup", "One or more child processes required forced cleanup")

        report["complete"] = bool(
            not report["failures"]
            and report["cleanup"]["all_children_stopped"]
            and not report["cleanup"]["terminated"]
            and not report["cleanup"]["killed"]
            and len(ready) == 2
            and all(peers[name]["pid"] not in (None, os.getpid()) for name in _PEER_NAMES)
            and peers["alice"]["pid"] != peers["bob"]["pid"]
            and peers["alice"]["fingerprint"] != peers["bob"]["fingerprint"]
            and all(
                peers[name]["endpoint"] is not None
                and peers[name]["endpoint"].get("ip") == "127.0.0.1"
                and type(peers[name]["endpoint"].get("port")) is int
                and 1 <= peers[name]["endpoint"]["port"] <= 65535
                for name in _PEER_NAMES
            )
            and all(item.get("approved") is True for item in report["pairing"])
            and all(row["verified"] for row in transfers)
            and all(
                peers[name]["audit"] is not None
                and peers[name]["audit"].get("valid") is True
                and peers[name]["audit"].get("checkpoint_checked") is True
                for name in _PEER_NAMES
            )
        )
        report["elapsed_ns"] = max(0, time.perf_counter_ns() - started_ns)

    return report


def main(argv: list[str] | None = None) -> int:
    from sparc.models import SparcError

    parser = argparse.ArgumentParser(description="Run a local two-peer SPARC security simulation")
    parser.add_argument("--data-root", required=True, type=Path, help="parent directory for the two peer stores")
    parser.add_argument("--report", type=Path, help="write the JSON report to this UTF-8 file")
    args = parser.parse_args(argv)
    try:
        report = run_simulation(args.data_root)
        encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
        if args.report is not None:
            args.report.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return 0 if report["complete"] else 1
    except SparcError as error:
        print(f"SPARC simulation input error [{error.code}]: {error.message}", file=sys.stderr)
        return 2
    except OSError:
        print("SPARC simulation could not write the requested report", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
