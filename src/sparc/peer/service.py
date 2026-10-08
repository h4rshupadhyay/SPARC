"""Local peer service initialization, handshakes, and listener lifecycle."""

from __future__ import annotations

import ipaddress
import base64
import queue
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from ..audit import AuditLog, AuditReport
from ..identity import TrustStore, load_identity
from ..models import (
    DeliveryReceipt,
    Endpoint,
    Limits,
    ProtectedRecord,
    Role,
    ServiceEvent,
    SparcError,
)
from ..protocol.handshake import perform_handshake
from ..protocol.handshake_types import EstablishedSession, PeerCandidate
from ..protocol.messages import prepare_text, signing_projection
from .pairing import PairingRequests
from .policy import ConnectionLimiter, ReconnectPolicy
from .receipts import PendingMessage, ReceiptLedger
from .session import ActiveSession, SessionHooks

_MAX_AUDIT_COUNT = 2**64 - 1


def _endpoint_metadata(endpoint: Endpoint) -> str:
    return f"{endpoint.ip}:{endpoint.port}"


def _endpoint_event_data(endpoint: Endpoint) -> dict:
    return {"ip": endpoint.ip, "port": endpoint.port}


class _ServiceEventQueue(queue.Queue[ServiceEvent]):
    """Bounded FIFO for ordinary events with one retained terminal state."""

    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize)
        self._generation = 0
        self._pending_terminal: tuple[ServiceEvent, int] | None = None

    def _discard_pending_locked(self) -> None:
        if self._pending_terminal is None:
            return
        self._pending_terminal = None
        self.unfinished_tasks -= 1
        if self.unfinished_tasks == 0:
            self.all_tasks_done.notify_all()

    def advance_generation(self, generation: int) -> None:
        with self.mutex:
            if generation <= self._generation:
                return
            self._generation = generation
            if (self._pending_terminal is not None
                    and self._pending_terminal[1] < generation):
                self._discard_pending_locked()

    def publish_terminal(self, event: ServiceEvent, generation: int) -> None:
        if not isinstance(event, ServiceEvent) or event.kind != "state":
            return
        data = event.data
        if not isinstance(data, dict):
            return
        state = data.get("state")
        reason = data.get("reason")
        endpoint = data.get("endpoint")
        if not isinstance(state, str) or not isinstance(reason, str):
            return
        if endpoint is not None:
            if not isinstance(endpoint, dict):
                return
            ip, port = endpoint.get("ip"), endpoint.get("port")
            if not isinstance(ip, str) or type(port) is not int:
                return
            endpoint = {"ip": ip, "port": port}
        safe_event = ServiceEvent(
            "state", {"state": state, "reason": reason, "endpoint": endpoint}
        )
        with self.mutex:
            if generation < self._generation:
                return
            if generation > self._generation:
                self._generation = generation
                if (self._pending_terminal is not None
                        and self._pending_terminal[1] < generation):
                    self._discard_pending_locked()
            if self._pending_terminal is None:
                self.unfinished_tasks += 1
            self._pending_terminal = (safe_event, generation)
            self.not_empty.notify()

    def get(self, block: bool = True, timeout: float | None = None) -> ServiceEvent:
        if not block:
            deadline = None
        elif timeout is not None:
            if timeout < 0:
                raise ValueError("'timeout' must be a non-negative number")
            deadline = time.monotonic() + timeout
        else:
            deadline = None

        with self.not_empty:
            if not block:
                if self._qsize():
                    item = self._get()
                    self.not_full.notify()
                    return item
                if self._pending_terminal is not None:
                    item, _generation = self._pending_terminal
                    self._pending_terminal = None
                    return item
                raise queue.Empty

            while not self._qsize() and self._pending_terminal is None:
                if deadline is None:
                    self.not_empty.wait()
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise queue.Empty
                    self.not_empty.wait(remaining)
            if self._qsize():
                item = self._get()
                self.not_full.notify()
                return item
            item, _generation = self._pending_terminal
            self._pending_terminal = None
            return item

    def get_nowait(self) -> ServiceEvent:
        return self.get(block=False)


@dataclass(eq=False)
class _Attempt:
    generation: int
    role: Role
    endpoint: Endpoint
    cancel: threading.Event
    epoch: int = 0
    sock: socket.socket | None = None
    worker: threading.Thread | None = None
    session: ActiveSession | None = None
    benchmark_records: int = 0
    benchmark_bytes: int = 0
    received_benchmark_records: int = 0
    received_benchmark_bytes: int = 0
    approval_wait_included: bool = False
    peer_fingerprint: str | None = None
    retry_chain: _ReconnectChain | None = None
    retry_index: int = 0
    reconnect_outcome_attempted: bool = False


@dataclass(eq=False, frozen=True)
class _ReconnectChain:
    endpoint: Endpoint
    fingerprint: str
    started_ns: int
    delays: tuple[float, ...]
    cancel: threading.Event
    epoch: int


class PeerService:
    """Own persistent peer state, one connection attempt, and its active session."""

    def __init__(self, data_dir: Path, limits: Limits = Limits()) -> None:
        if not isinstance(limits, Limits):
            raise SparcError("invalid_schema", "Peer service limits are invalid")
        self.data_dir = Path(data_dir)
        self.limits = limits
        self._identity = load_identity(self.data_dir)
        self._trust = TrustStore(self.data_dir)
        self._audit = AuditLog(self.data_dir, self._identity)
        # Publish the retained head before creating or exposing any worker.
        self._audit.export_checkpoint(self._audit.checkpoint_path)

        self.events: queue.Queue[ServiceEvent] = _ServiceEventQueue(maxsize=limits.event_queue)
        self._state_lock = threading.RLock()
        self._connection_limiter = ConnectionLimiter(time.monotonic, limits=limits)
        self._rate_limit_lock = threading.Lock()
        self._rate_limit_connection_count = 0
        self._rate_limit_record_count = 0
        self._rate_limit_last_audit: float | None = None
        self._rate_limit_interval = 5.0
        self._state = "stopped"
        self._closed = False
        self._audit_failed = False
        self._cancel = threading.Event()
        self._listener_cancel = threading.Event()
        self._listener: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._listener_starting = False
        self._listener_starting_socket: socket.socket | None = None
        self._forget_owner: object | None = None
        self._listener_generation = 0
        self._slot: _Attempt | None = None
        self._generation = 0
        self._reconnect_epoch = 0
        self._reconnect_policy = ReconnectPolicy(time.monotonic, limits=limits)
        self._receipts = ReceiptLedger(
            limit=limits.pending_requests,
            delivery_timeout_seconds=limits.delivery_timeout_seconds,
        )
        self._hash_ns_by_id: dict[str, int] = {}
        self._workers: set[threading.Thread] = set()
        self._pairings = PairingRequests(self._emit_pairing, limits.cancel_poll_seconds)

    @property
    def own_fingerprint(self) -> str:
        return self._identity.fingerprint

    @property
    def state(self) -> str:
        with self._state_lock:
            return self._state

    def trusted_peers(self) -> list[dict]:
        return self._trust.snapshot()

    def _audit_cancel_predicate(self, cancel: threading.Event | None):
        return lambda: self._cancel.is_set() or (cancel is not None and cancel.is_set())

    def audit_head(self, *, cancel: threading.Event | None = None) -> dict:
        """Return a copied public snapshot of the durably committed audit head."""
        return self._audit.head_snapshot(cancelled=self._audit_cancel_predicate(cancel))

    def verify_audit(
        self,
        checkpoint: Path | None = None,
        *,
        cancel: threading.Event | None = None,
    ) -> AuditReport:
        """Verify the audit prefix captured by AuditLog for this operation."""
        return self._audit.verify(
            checkpoint,
            cancelled=self._audit_cancel_predicate(cancel),
        )

    def export_audit_checkpoint(
        self,
        path: Path,
        *,
        cancel: threading.Event | None = None,
    ) -> None:
        """Export a checkpoint unless sticky audit failure has latched."""
        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
        try:
            self._audit.export_checkpoint(
                Path(path),
                cancelled=self._audit_cancel_predicate(cancel),
            )
        except SparcError as exc:
            if exc.code == "audit_storage_failed":
                self._latch_audit_failure()
            raise

    def connected_peer(self) -> dict | None:
        """Return the authenticated peer bound to the current live session."""
        with self._state_lock:
            attempt = self._slot
            if (
                self._closed
                or self._audit_failed
                or self._state != "connected"
                or attempt is None
                or self._slot is not attempt
                or attempt.generation != self._generation
                or attempt.session is None
                or attempt.cancel.is_set()
                or not attempt.peer_fingerprint
            ):
                return None
            return {
                "fingerprint": attempt.peer_fingerprint,
                "endpoint": Endpoint(attempt.endpoint.ip, attempt.endpoint.port),
            }

    def forget_peer(self, fingerprint: str) -> None:
        """Explicitly and durably forget one idle, remembered peer identity."""
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise SparcError(
                "invalid_fingerprint",
                "Fingerprint must be lowercase 64-character hexadecimal",
            )

        token = object()
        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed:
                raise SparcError("operation_cancelled", "Peer service is closed")
            if self._slot is not None or self._forget_owner is not None or self._listener_starting:
                raise SparcError("busy", "Peer service is busy with another operation")
            self._forget_owner = token

        try:
            record = next(
                (peer for peer in self.trusted_peers() if peer.get("fingerprint") == fingerprint),
                None,
            )
            if record is None or not isinstance(record.get("endpoint"), Endpoint):
                raise SparcError("invalid_state", "Remembered peer was not found")
            endpoint = record["endpoint"]
            metadata = {
                "fingerprint": fingerprint,
                "endpoint": _endpoint_metadata(endpoint),
                "state": "forget_requested",
            }

            self._check_forget_owner(token)
            self._append_unowned_audit("trust_changed", metadata)

            # This recheck is the mutation authorization boundary. Once the
            # trust write begins, close cannot revoke or roll it back.
            self._check_forget_owner(token)
            self._trust.forget(fingerprint)

            self._append_unowned_audit("trust_changed", {
                **metadata,
                "state": "forgotten",
            })
        finally:
            with self._state_lock:
                if self._forget_owner is token:
                    self._forget_owner = None

    def _check_forget_owner(self, token: object) -> None:
        with self._state_lock:
            if self._forget_owner is not token:
                raise SparcError("operation_cancelled", "Forget operation no longer owns the reservation")
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed:
                raise SparcError("operation_cancelled", "Peer service is closed")

    def _append_unowned_audit(self, kind: str, metadata: dict) -> None:
        try:
            self._audit.append(kind, metadata)
        except Exception as exc:
            self._latch_audit_failure()
            raise SparcError("audit_storage_failed", "Audit storage failed closed") from exc

    def send_text(self, text: str, *, run_id: str | None = None) -> str:
        """Reserve, durably record, and enqueue one outbound application message."""
        started_ns = time.perf_counter_ns()
        with self._state_lock:
            attempt = self._slot
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed or self._state != "connected" or attempt is None or attempt.session is None:
                raise SparcError("invalid_state", "A connected peer session is required to send text")
            session = attempt.session

        message_id = secrets.token_hex(16)
        payload, hash_ns = prepare_text(text, message_id, run_id)
        byte_count = payload["byte_count"]
        pending = PendingMessage(
            message_id=message_id,
            sha256=payload["sha256"],
            started_ns=started_ns,
            plaintext_bytes=byte_count,
            characters=len(text),
            frame_bytes=0,
        )

        with self._state_lock:
            if (self._closed or self._state != "connected" or self._slot is not attempt
                    or attempt.session is not session or attempt.cancel.is_set()):
                raise SparcError("invalid_state", "The peer session is no longer connected")
            if run_id is not None and (
                attempt.benchmark_records >= self.limits.benchmark_records
                or attempt.benchmark_bytes + byte_count > self.limits.benchmark_bytes
            ):
                raise SparcError("benchmark_limit", "Benchmark send limit was reached for this connection")
            self._receipts.reserve(pending)
            self._hash_ns_by_id[message_id] = hash_ns
            if run_id is not None:
                attempt.benchmark_records += 1
                attempt.benchmark_bytes += byte_count

        metadata = {
            "message_id": message_id,
            "sha256": payload["sha256"],
            "byte_count": byte_count,
        }
        try:
            self._append_audit(attempt, "send_attempt", metadata)
        except SparcError as error:
            self._send_audit_failed(
                attempt, session, message_id,
                "Audit storage failed before the message could be sent",
            )
            session._terminate(error)
            raise
        except Exception as exc:
            error = SparcError("audit_storage_failed", "Send attempt could not be durably recorded")
            self._send_audit_failed(attempt, session, message_id, error.message)
            session._terminate(error)
            raise error from exc

        try:
            session.enqueue(payload)
        except SparcError as error:
            self._receipts.fail_one(message_id, error.message)
            with self._state_lock:
                self._hash_ns_by_id.pop(message_id, None)
            raise
        except Exception as exc:
            error = SparcError("session_unusable", "Could not queue the outbound message")
            self._receipts.fail_one(message_id, error.message)
            with self._state_lock:
                self._hash_ns_by_id.pop(message_id, None)
            raise error from exc
        return message_id

    def _send_audit_failed(self, attempt: _Attempt, session: ActiveSession,
                           message_id: str, reason: str) -> None:
        with self._state_lock:
            owns_slot = (
                self._slot is attempt
                and self._generation == attempt.generation
                and attempt.session is session
            )
            if owns_slot:
                self._receipts.fail_all(reason)
                self._hash_ns_by_id.clear()
            else:
                self._receipts.fail_one(message_id, reason)
                self._hash_ns_by_id.pop(message_id, None)

    def wait_for_receipt(self, message_id: str, timeout: float = 10,
                         cancel: threading.Event | None = None) -> DeliveryReceipt:
        return self._receipts.wait(message_id, timeout, cancel)

    def start_listener(self, bind_ip: str, port: int) -> Endpoint:
        if not isinstance(bind_ip, str):
            raise SparcError("invalid_ip", "Bind address must be a literal IPv4 address")
        try:
            address = ipaddress.IPv4Address(bind_ip)
        except ipaddress.AddressValueError as exc:
            raise SparcError("invalid_ip", "Bind address must be a literal IPv4 address") from exc
        if str(address) != bind_ip:
            raise SparcError("invalid_ip", "Bind address must use canonical IPv4 notation")
        if type(port) is not int or not 0 <= port <= 65535:
            raise SparcError("invalid_port", "Port must be an integer from 0 to 65535")

        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed:
                raise SparcError("operation_cancelled", "Peer service is closed")
            if self._forget_owner is not None:
                raise SparcError("busy", "A peer forget operation is in progress")
            if self._listener is not None or self._listener_starting:
                raise SparcError("busy", "A listener is already active")
            self._listener_generation += 1
            generation = self._listener_generation
            listener_cancel = threading.Event()
            self._listener_cancel = listener_cancel
            self._listener_starting = True
            self._listener_starting_socket = None

        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            with self._state_lock:
                if generation == self._listener_generation:
                    self._listener_starting = False
            raise SparcError("bind_failed", "Could not create the requested listener") from exc

        with self._state_lock:
            canceled = (self._closed or self._audit_failed or listener_cancel.is_set()
                        or generation != self._listener_generation)
            if not canceled:
                self._listener_starting_socket = listener
        if canceled:
            listener.close()
            with self._state_lock:
                if generation == self._listener_generation:
                    self._listener_starting = False
                    self._listener_starting_socket = None
            raise SparcError("operation_cancelled", "Listener startup was canceled")

        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((bind_ip, port))
            listener.listen()
            listener.settimeout(self.limits.cancel_poll_seconds)
            actual = listener.getsockname()
            endpoint = Endpoint(str(actual[0]), int(actual[1]))
        except OSError as exc:
            listener.close()
            with self._state_lock:
                if self._listener_starting_socket is listener:
                    self._listener_starting_socket = None
                    self._listener_starting = False
            if listener_cancel.is_set() or self._closed or self._audit_failed:
                raise SparcError("operation_cancelled", "Listener startup was canceled") from exc
            raise SparcError("bind_failed", "Could not start the requested listener") from exc

        worker = threading.Thread(
            target=self._accept_loop,
            args=(listener, listener_cancel),
            name="sparc-peer-listener",
            daemon=True,
        )
        canceled_during_bind = False
        try:
            with self._state_lock:
                if (self._closed or self._audit_failed or listener_cancel.is_set()
                        or generation != self._listener_generation):
                    if self._listener_starting_socket is listener:
                        self._listener_starting_socket = None
                        self._listener_starting = False
                    canceled_during_bind = True
                else:
                    self._listener = listener
                    self._listener_thread = worker
                    self._listener_starting = False
                    self._listener_starting_socket = None
                    if self._slot is None:
                        self._state = "listening"
                    listener_state = self._state
                    worker.start()
        except Exception as exc:
            with self._state_lock:
                if self._listener is listener:
                    self._listener = None
                    self._listener_thread = None
                if self._listener_starting_socket is listener:
                    self._listener_starting_socket = None
                    self._listener_starting = False
                if self._slot is None:
                    self._state = "stopped"
            listener.close()
            if isinstance(exc, SparcError):
                raise
            raise SparcError("listener_failed", "Could not start the listener worker") from exc
        if canceled_during_bind:
            listener.close()
            raise SparcError("operation_cancelled", "Listener startup was canceled")

        self._emit_state(listener_state, "listener_started", endpoint, listener_cancel)
        return endpoint

    def stop_listener(self) -> None:
        with self._state_lock:
            self._reconnect_epoch += 1
            listener = self._listener
            worker = self._listener_thread
            starting_socket = self._listener_starting_socket
            listener_cancel = self._listener_cancel
            starting = self._listener_starting
            retry_attempt = self._slot if (
                self._slot is not None and self._slot.retry_chain is not None
            ) else None
            retry_worker = retry_attempt.worker if retry_attempt is not None else None
            retry_sock = retry_attempt.sock if retry_attempt is not None else None
            if retry_attempt is not None:
                retry_attempt.retry_chain.cancel.set()
                retry_attempt.cancel.set()
            if listener is None and not starting:
                # An absent listener does not make an explicit Stop a no-op:
                # it still revokes a reserved retry chain above.
                pass
            else:
                listener_cancel.set()
            if listener is None and not starting and retry_attempt is None:
                return
            if listener is not None:
                self._listener = None
                self._listener_thread = None
                self._listener_generation += 1
                if self._slot is None:
                    self._state = "stopped"
            state = self._state
        for sock in (listener, starting_socket):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass
        if retry_sock is not None:
            self._close_socket(retry_sock)
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2)
        if (retry_worker is not None and retry_worker is not threading.current_thread()
                and retry_worker.is_alive()):
            retry_worker.join(timeout=2)
        if listener is not None and retry_attempt is None:
            self._emit_state(state, "listener_stopped", None, self._cancel)

    def connect(self, endpoint: Endpoint) -> None:
        if not isinstance(endpoint, Endpoint):
            raise SparcError("invalid_endpoint", "Peer endpoint is invalid")
        if not isinstance(endpoint.ip, str):
            raise SparcError("invalid_ip", "Peer address must be a literal IPv4 address")
        try:
            address = ipaddress.IPv4Address(endpoint.ip)
        except ipaddress.AddressValueError as exc:
            raise SparcError("invalid_ip", "Peer address must be a literal IPv4 address") from exc
        if str(address) != endpoint.ip:
            raise SparcError("invalid_ip", "Peer address must use canonical IPv4 notation")
        if type(endpoint.port) is not int or not 1 <= endpoint.port <= 65535:
            raise SparcError("invalid_port", "Peer port must be from 1 to 65535")

        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed:
                raise SparcError("operation_cancelled", "Peer service is closed")
            if self._forget_owner is not None:
                raise SparcError("busy", "A peer forget operation is in progress")
            if self._slot is not None:
                raise SparcError("busy", "A connection attempt or session is already active")
            self._reconnect_epoch += 1
            self._generation += 1
            self.events.advance_generation(self._generation)
            attempt = _Attempt(
                generation=self._generation,
                role=Role.INITIATOR,
                endpoint=endpoint,
                cancel=threading.Event(),
                epoch=self._reconnect_epoch,
            )
            self._slot = attempt
            self._state = "connecting"
        try:
            self._emit_state("connecting", "connection_started", endpoint, attempt.cancel)
            self._start_coordinator(attempt)
        except Exception:
            self._finish_attempt(attempt, SparcError("operation_cancelled", "Connection attempt was canceled"))
            raise

    def respond_to_pairing(self, request_id: str, approved: bool) -> None:
        with self._state_lock:
            generation = self._generation
        self._pairings.respond(request_id, approved, generation)

    def disconnect(self) -> None:
        """Cancel the current attempt or established session, retaining the listener."""
        with self._state_lock:
            self._reconnect_epoch += 1
            attempt = self._slot
            if attempt is None:
                return
            if attempt.retry_chain is not None:
                attempt.retry_chain.cancel.set()
            attempt.cancel.set()
            sock = attempt.sock
            session = attempt.session
            worker = attempt.worker
        if session is not None:
            session.close()
        elif sock is not None:
            self._close_socket(sock)
        deadline = time.monotonic() + 2.0
        if session is not None:
            session.join(timeout=max(0.0, deadline - time.monotonic()))
        if worker is not None and worker is not threading.current_thread() and worker.is_alive():
            worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._reconnect_epoch += 1
            self._cancel.set()
            self._listener_cancel.set()
            listener = self._listener
            listener_worker = self._listener_thread
            starting_socket = self._listener_starting_socket
            self._listener_starting_socket = None
            self._listener_starting = False
            self._listener_generation += 1
            attempt = self._slot
            workers = list(self._workers)
            self._listener = None
            self._listener_thread = None
            self._state = "stopped"
            self._receipts.fail_all("Peer service closed before delivery confirmation")
            if attempt is not None:
                if attempt.retry_chain is not None:
                    attempt.retry_chain.cancel.set()
                attempt.cancel.set()
                sock = attempt.sock
                session = attempt.session
            else:
                sock = None
                session = None
        self._pairings.cancel_all()
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if starting_socket is not None and starting_socket is not listener:
            try:
                starting_socket.close()
            except OSError:
                pass
        if session is not None:
            session.close()
        elif sock is not None:
            self._close_socket(sock)

        deadline = time.monotonic() + 2.0
        if session is not None:
            session.join(timeout=max(0.0, deadline - time.monotonic()))
        for worker in [listener_worker, *workers]:
            if worker is None or worker is threading.current_thread() or not worker.is_alive():
                continue
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(timeout=remaining)

    def _emit(self, event: ServiceEvent, cancel: threading.Event | None = None) -> None:
        if not isinstance(event, ServiceEvent):
            raise SparcError("invalid_schema", "Service event is invalid")
        while True:
            if self._cancel.is_set() or (cancel is not None and cancel.is_set()):
                raise SparcError("operation_cancelled", "Service event delivery was canceled")
            try:
                self.events.put(event, timeout=self.limits.cancel_poll_seconds)
                return
            except queue.Full:
                continue

    def _emit_pairing(self, event: ServiceEvent, cancel: threading.Event) -> None:
        self._emit(event, cancel)

    def _emit_state(self, state: str, reason: str, endpoint: Endpoint | None,
                    cancel: threading.Event | None = None) -> None:
        data = {"state": state, "reason": reason, "endpoint": (
            None if endpoint is None else _endpoint_event_data(endpoint)
        )}
        self._emit(ServiceEvent("state", data), cancel)

    def _publish_owned_state(self, attempt: _Attempt, state: str, reason: str,
                             endpoint: Endpoint | None) -> None:
        """Coalesce owned lifecycle state without waiting for ordinary capacity."""
        with self._state_lock:
            if (self._audit_failed or self._slot is not attempt
                    or self._generation != attempt.generation):
                return
            event = ServiceEvent("state", {
                "state": state,
                "reason": reason,
                "endpoint": None if endpoint is None else _endpoint_event_data(endpoint),
            })
            generation = attempt.generation
        publish = getattr(self.events, "publish_terminal", None)
        if callable(publish):
            publish(event, generation)

    def _emit_owned_metric(self, attempt: _Attempt, operation: str, started_ns: int,
                           success: bool, encoded_bytes: int | None, context: dict,
                           *, elapsed_ns: int | None = None,
                           allow_cancelled_owner: bool = False) -> None:
        """Insert an optional key-free diagnostic without queue backpressure."""
        data = {
            "operation": operation,
            "elapsed_ns": (max(0, time.perf_counter_ns() - started_ns)
                           if elapsed_ns is None else max(0, elapsed_ns)),
            "success": success,
            "context": dict(context),
        }
        if encoded_bytes is not None:
            data["encoded_bytes"] = encoded_bytes
        event = ServiceEvent("operation_metrics", data)
        with self._state_lock:
            if (self._slot is not attempt or self._generation != attempt.generation
                    or (attempt.cancel.is_set() and not allow_cancelled_owner)):
                return
            try:
                self.events.put_nowait(event)
            except queue.Full:
                pass

    def _latch_audit_failure(self, failed_attempt: _Attempt | None = None) -> bool:
        """Latch fail-closed state and close only the captured owner transport."""
        with self._state_lock:
            self._audit_failed = True
            self._reconnect_epoch += 1
            attempt = failed_attempt
            if attempt is None:
                attempt = self._slot
            owns_attempt = (
                attempt is not None
                and self._slot is attempt
                and self._generation == attempt.generation
            )
            attempt_socket = None
            session_socket = None
            if owns_attempt:
                if attempt.retry_chain is not None:
                    attempt.retry_chain.cancel.set()
                if attempt.session is None:
                    attempt.cancel.set()
                    attempt_socket = attempt.sock
                else:
                    # Do not set the session's shared cancellation event here.
                    # Closing transport lets its reader/owner win on_closed.
                    session_socket = attempt.session._sock

            listener = self._listener
            starting_socket = self._listener_starting_socket
            listener_cancel = self._listener_cancel
            self._listener = None
            self._listener_thread = None
            self._listener_starting_socket = None
            self._listener_starting = False
            self._listener_generation += 1
            listener_cancel.set()
            if self._slot is None:
                self._state = "error"

        for sock in {id(value): value for value in (
            listener, starting_socket, attempt_socket, session_socket
        ) if value is not None}.values():
            self._close_socket(sock)
        return owns_attempt

    def _start_coordinator(self, attempt: _Attempt) -> None:
        worker = threading.Thread(
            target=self._coordinate,
            args=(attempt,),
            name=f"sparc-handshake-{attempt.generation}",
            daemon=True,
        )
        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed or self._slot is not attempt or attempt.cancel.is_set():
                raise SparcError("operation_cancelled", "Connection attempt was canceled")
            attempt.worker = worker
            self._workers.add(worker)
            try:
                worker.start()
            except Exception as exc:
                self._workers.discard(worker)
                attempt.worker = None
                raise SparcError("session_unusable", "Could not start handshake worker") from exc

    def _accept_loop(self, listener: socket.socket, listener_cancel: threading.Event) -> None:
        while not listener_cancel.is_set() and not self._cancel.is_set():
            try:
                accepted, peer = listener.accept()
            except (socket.timeout, TimeoutError):
                self._flush_rate_limit_audit()
                continue
            except OSError:
                if listener_cancel.is_set() or self._cancel.is_set():
                    return
                return

            endpoint = Endpoint(str(peer[0]), int(peer[1]))
            if not self._connection_limiter.allow(endpoint.ip):
                self._close_socket(accepted)
                if not self._record_rate_limit_rejection("connection"):
                    return
                continue

            busy = False
            with self._state_lock:
                if (self._closed or self._audit_failed or listener_cancel.is_set()
                        or self._slot is not None or self._forget_owner is not None):
                    busy = True
                else:
                    self._generation += 1
                    self.events.advance_generation(self._generation)
                    attempt = _Attempt(
                        generation=self._generation,
                        role=Role.RESPONDER,
                        endpoint=endpoint,
                        cancel=threading.Event(),
                        epoch=self._reconnect_epoch,
                        sock=accepted,
                    )
                    self._slot = attempt
                    self._state = "handshaking"
            if busy:
                self._close_socket(accepted)
                try:
                    self._emit_state(self.state, "busy", endpoint, listener_cancel)
                except SparcError:
                    if self._cancel.is_set():
                        return
                continue

            try:
                self._emit_state("handshaking", "connection_accepted", endpoint, attempt.cancel)
                self._start_coordinator(attempt)
            except Exception as error:
                if isinstance(error, SparcError):
                    failure = error
                else:
                    failure = SparcError("session_unusable", "Could not start handshake worker")
                self._finish_attempt(attempt, failure)
                self._close_socket(accepted)

    def _record_rate_limit_rejection(self, kind: str) -> bool:
        with self._rate_limit_lock:
            if kind == "connection":
                self._rate_limit_connection_count = min(
                    _MAX_AUDIT_COUNT, self._rate_limit_connection_count + 1
                )
            elif kind == "record":
                self._rate_limit_record_count = min(
                    _MAX_AUDIT_COUNT, self._rate_limit_record_count + 1
                )
            else:
                raise ValueError("unknown rate-limit rejection kind")
        return self._flush_rate_limit_audit()

    def _flush_rate_limit_audit(self) -> bool:
        """Write one bounded rejection summary at most once per five seconds."""
        with self._rate_limit_lock:
            connection_count = self._rate_limit_connection_count
            record_count = self._rate_limit_record_count
            count = min(_MAX_AUDIT_COUNT, connection_count + record_count)
            if not count:
                return True
            now = time.monotonic()
            if (self._rate_limit_last_audit is not None
                    and now - self._rate_limit_last_audit < self._rate_limit_interval):
                return True
            if connection_count and record_count:
                code = "multiple_rate_limits"
                reason = "Connection and record rate limits were exceeded"
            elif connection_count:
                code = "connection_limit"
                reason = "Connection attempt rate limit was exceeded"
            else:
                code = "record_rate_limit"
                reason = "Application record rate limit was exceeded"
            metadata = {
                "code": code,
                "reason": reason,
                "count": count,
            }
            try:
                # Audit append may fsync. It is intentionally outside the
                # service state lock, while the aggregate lock preserves one
                # bounded summary and its five-second cadence.
                self._audit.append("rate_limit_rejected", metadata)
            except Exception:
                if self._rate_limit_last_audit is None:
                    self._rate_limit_last_audit = now
                audit_failed = True
            else:
                self._rate_limit_connection_count = 0
                self._rate_limit_record_count = 0
                # Start the cooldown after the durable append completes, so
                # audit timestamps remain at least one full interval apart.
                self._rate_limit_last_audit = time.monotonic()
                audit_failed = False
        if audit_failed:
            self._fail_closed_after_rate_audit_failure()
            return False
        return True

    def _fail_closed_after_rate_audit_failure(self) -> None:
        """Fail closed without stealing cleanup from the captured owner."""
        self._latch_audit_failure()

    def _approve(self, attempt: _Attempt, candidate: PeerCandidate) -> bool:
        if not self._is_current(attempt):
            raise SparcError("operation_cancelled", "Connection attempt is no longer active")
        chain = attempt.retry_chain
        if chain is not None:
            # Automatic recovery is reauthentication to an already pinned key,
            # never an implicit pairing or a way to restore forgotten trust.
            if candidate.fingerprint != chain.fingerprint:
                raise SparcError("changed_identity", "Automatic reconnect reached a different peer")
            try:
                trust_state = self._trust.check(candidate.public_key, candidate.endpoint)
            except SparcError as error:
                raise SparcError("changed_identity", "Automatic reconnect trust is unavailable") from error
            if trust_state != "known":
                raise SparcError("changed_identity", "Automatic reconnect peer is no longer trusted")
            return True
        with self._state_lock:
            if (self._slot is not attempt or attempt.cancel.is_set() or self._closed
                    or self._audit_failed):
                raise SparcError("operation_cancelled", "Connection attempt is no longer active")
            self._state = "awaiting approval"
            attempt.approval_wait_included = True
        self._emit_state("awaiting approval", "pairing_required", candidate.endpoint, attempt.cancel)
        return self._pairings.ask(
            candidate,
            self.own_fingerprint,
            attempt.generation,
            attempt.cancel,
            self.limits.pairing_timeout_seconds,
        )

    def _coordinate(self, attempt: _Attempt) -> None:
        failure: SparcError | None = None
        adopted = False
        try:
            chain = attempt.retry_chain
            retry_delay = None
            if not self._is_current(attempt):
                raise SparcError("operation_cancelled", "Connection attempt is no longer active")
            if chain is not None:
                if not self._retry_is_current(attempt):
                    raise SparcError("operation_cancelled", "Reconnect was canceled")
                retry_delay = chain.delays[attempt.retry_index]
                if chain.cancel.wait(retry_delay) or attempt.cancel.is_set():
                    raise SparcError("operation_cancelled", "Reconnect was canceled")
                if not self._retry_is_current(attempt):
                    raise SparcError("operation_cancelled", "Reconnect was canceled")
            sock = attempt.sock
            if sock is None:
                if not self._is_current(attempt):
                    raise SparcError("operation_cancelled", "Connection attempt was canceled")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                canceled = False
                with self._state_lock:
                    if (self._slot is not attempt or self._closed or self._audit_failed
                            or attempt.cancel.is_set()):
                        canceled = True
                    else:
                        attempt.sock = sock
                if canceled:
                    self._close_socket(sock)
                    raise SparcError("operation_cancelled", "Connection attempt was canceled")
                try:
                    sock.settimeout(min(1.0, self.limits.cancel_poll_seconds))
                    sock.connect((attempt.endpoint.ip, attempt.endpoint.port))
                except OSError as exc:
                    raise SparcError("tcp_loss", "Could not connect to the requested peer") from exc
                finally:
                    try:
                        sock.settimeout(None)
                    except OSError:
                        pass

            handshake_started = time.perf_counter_ns()
            if not self._is_current(attempt):
                raise SparcError("operation_cancelled", "Connection attempt is no longer active")
            try:
                established = perform_handshake(
                    sock,
                    attempt.role,
                    self._identity,
                    self._trust,
                    lambda candidate: self._approve(attempt, candidate),
                    attempt.cancel,
                    self.limits,
                )
            except Exception:
                self._emit_attempt_operation_metric(
                    attempt, "handshake", handshake_started, False, None,
                    {"endpoint": _endpoint_event_data(attempt.endpoint),
                     "approval_included": attempt.approval_wait_included},
                )
                raise
            self._emit_attempt_operation_metric(
                attempt, "handshake", handshake_started, True, None,
                {"endpoint": _endpoint_event_data(attempt.endpoint),
                 "approval_included": attempt.approval_wait_included},
            )
            if not self._is_current(attempt):
                raise SparcError("operation_cancelled", "Connection attempt was canceled")

            chain = attempt.retry_chain
            if chain is not None:
                if (established.peer.fingerprint != chain.fingerprint
                        or established.newly_approved
                        or not self._retry_is_current(attempt)):
                    raise SparcError("changed_identity", "Automatic reconnect identity changed")
                self._write_reconnect_outcome(attempt, "connected")
            attempt.peer_fingerprint = established.peer.fingerprint

            outcome = "approved" if established.newly_approved else "known"
            self._durable_append(
                attempt,
                "pairing_outcome",
                {
                    "fingerprint": established.peer.fingerprint,
                    "endpoint": _endpoint_metadata(established.peer.endpoint),
                    "state": outcome,
                },
            )
            self._durable_append(
                attempt,
                "session_established",
                {"endpoint": _endpoint_metadata(established.peer.endpoint), "state": "connected"},
            )
            if established.newly_approved:
                self._begin_durable_operation(attempt)
                self._trust.pin(established.peer.public_key, established.peer.endpoint)
                self._append_audit(
                    attempt,
                    "trust_changed",
                    {
                        "fingerprint": established.peer.fingerprint,
                        "endpoint": _endpoint_metadata(established.peer.endpoint),
                        "state": "pinned",
                    },
                )

            session = self._make_session(attempt, sock, established)
            with self._state_lock:
                if (self._slot is not attempt or self._closed or self._audit_failed
                        or attempt.cancel.is_set()):
                    raise SparcError("operation_cancelled", "Connection attempt was canceled")
                attempt.session = session
            session.start()
            with self._state_lock:
                if (
                    self._slot is not attempt
                    or self._closed
                    or self._audit_failed
                    or attempt.cancel.is_set()
                    or attempt.session is not session
                ):
                    raise SparcError("operation_cancelled", "Connection attempt was canceled")
                self._state = "connected"
                if attempt.retry_chain is not None:
                    elapsed_ns = max(0, time.perf_counter_ns() - attempt.retry_chain.started_ns)
                    attempt.retry_chain = None
            self._publish_owned_state(
                attempt, "connected", "session_established", established.peer.endpoint
            )
            if retry_delay is not None:
                self._emit_reconnect_metric(
                    attempt, "reconnect_attempt", True,
                    {"attempt": attempt.retry_index + 1, "delay_seconds": retry_delay},
                )
                self._emit_reconnect_metric(
                    attempt, "reconnect_recovery", True,
                    {"attempt": attempt.retry_index + 1, "elapsed_ns": elapsed_ns},
                )
            adopted = True
        except SparcError as error:
            with self._state_lock:
                audit_failed = self._audit_failed
            failure = (SparcError("audit_storage_failed", "Audit storage failed closed")
                       if audit_failed or error.code == "audit_storage_failed" else
                       SparcError("operation_cancelled", "Connection attempt was canceled")
                       if attempt.cancel.is_set() or self._closed else error)
        except Exception:
            failure = SparcError("session_unusable", "Connection attempt could not be completed")
        finally:
            if not adopted:
                with self._state_lock:
                    assigned_session = attempt.session is not None
                if not assigned_session:
                    attempt.cancel.set()
                if attempt.sock is not None:
                    self._close_socket(attempt.sock)
                if retry_delay is not None and failure is not None:
                    self._emit_reconnect_metric(
                        attempt, "reconnect_attempt", False,
                        {"attempt": attempt.retry_index + 1,
                         "delay_seconds": retry_delay, "outcome": failure.code},
                    )
                if not assigned_session:
                    self._finish_attempt(
                        attempt,
                        failure or SparcError("operation_cancelled", "Connection attempt was canceled"),
                    )
            with self._state_lock:
                if attempt.worker is not None:
                    self._workers.discard(attempt.worker)

    def _durable_append(self, attempt: _Attempt, kind: str, metadata: dict) -> None:
        self._begin_durable_operation(attempt)
        self._append_audit(attempt, kind, metadata)

    def _write_reconnect_outcome(self, attempt: _Attempt, state: str) -> None:
        """Durably record one retry result for its exact reserved chain owner."""
        chain = attempt.retry_chain
        if chain is None or attempt.reconnect_outcome_attempted:
            return
        with self._state_lock:
            if (
                self._closed
                or self._audit_failed
                or self._slot is not attempt
                or self._generation != attempt.generation
                or chain.cancel.is_set()
                or chain.epoch != self._reconnect_epoch
            ):
                raise SparcError("operation_cancelled", "Reconnect outcome owner is no longer active")
            attempt.reconnect_outcome_attempted = True
        try:
            self._append_audit(attempt, "reconnect_outcome", {
                "endpoint": _endpoint_metadata(chain.endpoint),
                "state": state,
                "attempt": attempt.retry_index + 1,
            })
        except Exception as exc:
            raise SparcError(
                "audit_storage_failed", "Reconnect outcome could not be durably recorded"
            ) from exc

    def _append_audit(self, attempt: _Attempt, kind: str, metadata: dict):
        started = time.perf_counter_ns()
        try:
            result = self._audit.append(kind, metadata)
        except Exception as exc:
            owns_attempt = self._latch_audit_failure(attempt)
            if owns_attempt:
                self._emit_owned_metric(
                    attempt, "audit", started, False, None, {"event": kind},
                    elapsed_ns=max(0, time.perf_counter_ns() - started),
                    allow_cancelled_owner=True,
                )
            raise SparcError("audit_storage_failed", "Audit storage failed closed") from exc
        if attempt.retry_chain is not None or kind == "session_closed":
            self._emit_owned_metric(
                attempt, "audit", started, True, getattr(result, "encoded_bytes", None),
                {"event": kind}, elapsed_ns=getattr(result, "elapsed_ns", None),
                allow_cancelled_owner=(kind == "session_closed"),
            )
        else:
            self._emit_operation_metric(
                "audit", started, True, getattr(result, "encoded_bytes", None),
                {"event": kind}, attempt.cancel,
                elapsed_ns=getattr(result, "elapsed_ns", None),
            )
        return result

    def _emit_attempt_operation_metric(self, attempt: _Attempt, operation: str,
                                       started_ns: int, success: bool,
                                       encoded_bytes: int | None, context: dict) -> None:
        if attempt.retry_chain is None:
            self._emit_operation_metric(
                operation, started_ns, success, encoded_bytes, context, attempt.cancel
            )
            return
        self._emit_owned_metric(
            attempt, operation, started_ns, success, encoded_bytes, context
        )

    def _emit_operation_metric(self, operation: str, started_ns: int, success: bool,
                               encoded_bytes: int | None, context: dict,
                               cancel: threading.Event | None = None,
                               *, elapsed_ns: int | None = None) -> None:
        data = {
            "operation": operation,
            "elapsed_ns": (max(0, time.perf_counter_ns() - started_ns)
                           if elapsed_ns is None else max(0, elapsed_ns)),
            "success": success,
            "context": context,
        }
        if encoded_bytes is not None:
            data["encoded_bytes"] = encoded_bytes
        try:
            self._emit(ServiceEvent("operation_metrics", data), cancel)
        except SparcError:
            pass

    def _emit_reconnect_metric(self, attempt: _Attempt, operation: str,
                               success: bool, context: dict) -> None:
        """Publish a key-free retry diagnostic only for its exact slot owner."""
        event = ServiceEvent("operation_metrics", {
            "operation": operation,
            "elapsed_ns": 0,
            "success": success,
            "context": dict(context),
        })
        with self._state_lock:
            if (self._closed or self._slot is not attempt
                    or self._generation != attempt.generation):
                return
            try:
                self.events.put_nowait(event)
            except queue.Full:
                pass

    def _poll_session(self, attempt: _Attempt, session: ActiveSession) -> None:
        with self._state_lock:
            if (self._closed or self._slot is not attempt or attempt.session is not session
                    or attempt.cancel.is_set()):
                return
            expired = self._receipts.expire(time.perf_counter_ns())
        self._flush_rate_limit_audit()
        if expired:
            session._terminate(
                SparcError("delivery_timeout", "Peer delivery confirmation deadline expired")
            )

    def _begin_durable_operation(self, attempt: _Attempt) -> None:
        with self._state_lock:
            if self._audit_failed:
                raise SparcError("audit_storage_failed", "Audit storage failed closed")
            if self._closed or self._slot is not attempt or attempt.cancel.is_set():
                raise SparcError("operation_cancelled", "Connection attempt was canceled")

    def _make_session(self, attempt: _Attempt, sock: socket.socket,
                      established: EstablishedSession) -> ActiveSession:
        owner: dict[str, ActiveSession] = {}
        session = ActiveSession(
            sock,
            established,
            SessionHooks(
                on_payload=lambda record: self._handle_payload(
                    attempt, owner["session"], established, record
                ),
                on_closed=lambda error: self._session_closed(attempt, error),
                emit=lambda event: self._emit_session_diagnostic(
                    attempt, owner["session"], event
                ),
                on_written=lambda payload, protected: self._on_written(attempt, payload, protected),
                on_poll=lambda: self._poll_session(attempt, owner["session"]),
            ),
            self.limits,
            cancel=attempt.cancel,
        )
        owner["session"] = session
        return session

    def _emit_session_diagnostic(self, attempt: _Attempt, session: ActiveSession,
                                 event: ServiceEvent) -> None:
        """Publish only the bounded inactivity diagnostic for its exact owner."""
        if not isinstance(event, ServiceEvent) or event.kind != "operation_metrics":
            return
        data = event.data
        if not isinstance(data, dict) or data.keys() != {
            "operation", "elapsed_ns", "success", "context"
        }:
            return
        context = data.get("context")
        elapsed_ns = data.get("elapsed_ns")
        if (
            data.get("operation") != "peer_inactivity_detection"
            or type(data.get("success")) is not bool
            or data["success"] is not False
            or type(elapsed_ns) is not int
            or not 0 <= elapsed_ns <= 2**64 - 1
            or not isinstance(context, dict)
            or context != {"reason": "peer_inactivity"}
        ):
            return
        safe_event = ServiceEvent("operation_metrics", {
            "operation": "peer_inactivity_detection",
            "elapsed_ns": elapsed_ns,
            "success": False,
            "context": {"reason": "peer_inactivity"},
        })
        with self._state_lock:
            if (
                self._closed
                or self._slot is not attempt
                or attempt.session is not session
                or self._generation != attempt.generation
            ):
                return
            try:
                self.events.put_nowait(safe_event)
            except queue.Full:
                pass

    def _handle_payload(self, attempt: _Attempt, session: ActiveSession,
                        established: EstablishedSession, record) -> None:
        payload = record.payload
        kind = payload.get("kind")
        if kind not in {"chat", "benchmark", "ack"}:
            return
        with self._state_lock:
            if (self._closed or self._slot is not attempt or attempt.session is not session
                    or self._generation != attempt.generation or attempt.cancel.is_set()):
                return

        if record.sequence is None or record.direction is None:
            raise SparcError("invalid_record", "Application record lacks authenticated coordinates")
        evidence = {
            "public_key": base64.b64encode(established.peer.public_key).decode("ascii"),
            "session_id": session.session_id.hex(),
            "direction": record.direction,
            "sequence": record.sequence,
            "projection": signing_projection(payload),
            "signature": payload["signature"],
        }

        if kind == "ack":
            pending = self._receipts.validate_ack(payload["message_id"], payload["sha256"])
            metadata = {
                "message_id": payload["message_id"],
                "sha256": payload["sha256"],
                "byte_count": pending.plaintext_bytes,
                "peer_evidence": evidence,
            }
            try:
                self._append_audit(attempt, "verified_delivery", metadata)
            except SparcError:
                self._delivery_audit_failed(
                    attempt, session, payload["message_id"],
                    "Delivery audit could not be durably stored",
                )
                raise
            except Exception as exc:
                self._delivery_audit_failed(
                    attempt, session, payload["message_id"],
                    "Delivery audit could not be durably stored",
                )
                raise SparcError("audit_storage_failed", "Delivery audit could not be durably stored") from exc
            with self._state_lock:
                if (self._closed or self._slot is not attempt or attempt.session is not session
                        or self._generation != attempt.generation or attempt.cancel.is_set()):
                    return
                receipt = self._receipts.confirm(
                    payload["message_id"], payload["sha256"], time.perf_counter_ns()
                )
            self._emit(ServiceEvent("delivery", {"message_id": payload["message_id"],
                                                  "receipt": receipt}), attempt.cancel)
            return

        if kind == "benchmark":
            with self._state_lock:
                if (self._closed or self._slot is not attempt or attempt.session is not session
                        or attempt.cancel.is_set()):
                    return
                if (attempt.received_benchmark_records >= self.limits.benchmark_records
                        or attempt.received_benchmark_bytes + payload["byte_count"]
                        > self.limits.benchmark_bytes):
                    raise SparcError("benchmark_limit", "Benchmark receive limit was reached for this connection")
                attempt.received_benchmark_records += 1
                attempt.received_benchmark_bytes += payload["byte_count"]

        metadata = {
            "message_id": payload["message_id"],
            "sha256": payload["sha256"],
            "byte_count": payload["byte_count"],
            "peer_evidence": evidence,
        }
        if kind == "benchmark":
            metadata["run_id"] = payload["run_id"]
        try:
            self._append_audit(attempt, "verified_receipt", metadata)
        except SparcError:
            raise
        except Exception as exc:
            raise SparcError("audit_storage_failed", "Receipt audit could not be durably stored") from exc

        with self._state_lock:
            if (self._closed or self._slot is not attempt or attempt.session is not session
                    or attempt.cancel.is_set()):
                return

        ack = {
            "kind": "ack",
            "message_id": payload["message_id"],
            "sha256": payload["sha256"],
            "status": "verified",
        }
        session.enqueue(ack, control=True)

        with self._state_lock:
            if (self._closed or self._slot is not attempt or attempt.session is not session
                    or attempt.cancel.is_set()):
                return
            if kind == "benchmark":
                event = ServiceEvent("benchmark_progress", {
                    "run_id": payload["run_id"],
                    "records": attempt.received_benchmark_records,
                    "bytes": attempt.received_benchmark_bytes,
                    "message_id": payload["message_id"],
                })
            else:
                event = ServiceEvent("message", {
                    "message_id": payload["message_id"],
                    "text": payload["text"],
                    "inspection": record.inspection,
                    "direction": record.direction,
                    "sequence": record.sequence,
                    "origin": "incoming",
                })
        self._emit(event, attempt.cancel)

    def _delivery_audit_failed(self, attempt: _Attempt, session: ActiveSession,
                               message_id: str, reason: str) -> None:
        with self._state_lock:
            if (self._slot is attempt and self._generation == attempt.generation
                    and attempt.session is session):
                self._receipts.fail_all(reason)
            else:
                self._receipts.fail_one(message_id, reason)

    def _session_closed(self, attempt: _Attempt, error: SparcError) -> None:
        loss_ns = time.perf_counter_ns()
        with self._state_lock:
            if self._slot is not attempt:
                return
            audit_already_failed = self._audit_failed
            attempt.cancel.set()
            self._receipts.fail_all("Session closed before delivery confirmation")
            self._hash_ns_by_id.clear()
            if self._closed:
                intended_state = "stopped"
            elif audit_already_failed:
                intended_state = "error"
            elif error.code == "operation_cancelled":
                intended_state = "listening" if self._listener is not None else "stopped"
            else:
                intended_state = "error"

        audit_error = None
        if (not audit_already_failed and error.code == "record_rate_limit"
                and not self._record_rate_limit_rejection("record")):
            audit_error = SparcError(
                "audit_storage_failed", "Rate-limit rejection could not be durably recorded"
            )
            audit_already_failed = True
        if not audit_already_failed:
            try:
                self._append_audit(attempt, "session_closed", {
                    "endpoint": _endpoint_metadata(attempt.endpoint),
                    "state": intended_state,
                    "code": error.code,
                    "reason": f"Session closed after {error.code}"[:120],
                })
            except SparcError as failure:
                audit_error = failure
            except Exception:
                audit_error = SparcError("audit_storage_failed", "Session closure could not be durably recorded")

        with self._state_lock:
            audit_latched = self._audit_failed

        if (
            audit_error is None
            and not audit_latched
            and attempt.role is Role.INITIATOR
            and attempt.retry_chain is None
            and attempt.peer_fingerprint is not None
            and error.code in {"tcp_loss", "delivery_timeout", "peer_inactivity"}
        ):
            delays = self._reconnect_policy.delays(error.code, explicit_stop=False)
            if delays:
                with self._state_lock:
                    epoch = attempt.epoch
                chain = _ReconnectChain(
                    endpoint=attempt.endpoint,
                    fingerprint=attempt.peer_fingerprint,
                    started_ns=loss_ns,
                    delays=delays,
                    cancel=threading.Event(),
                    epoch=epoch,
                )
                if self._reserve_retry(attempt, chain, 0):
                    with self._state_lock:
                        retry_owner = self._slot
                    if retry_owner is not None:
                        self._emit_reconnect_metric(
                            retry_owner, "reconnect_scheduled", True,
                            {"attempts": len(delays), "delays": list(delays)},
                        )
                    return

        with self._state_lock:
            if self._slot is not attempt:
                return
            audit_latched = self._audit_failed
            self._slot = None
            if audit_latched or audit_error is not None or error.code == "audit_storage_failed":
                self._audit_failed = True
            self._generation += 1
            self.events.advance_generation(self._generation)
            if self._closed:
                self._state = "stopped"
            elif audit_latched or audit_error is not None or error.code == "audit_storage_failed":
                self._state = "error"
            else:
                self._state = intended_state
            state = self._state
            terminal_generation = self._generation
        final_error = (audit_error or
                       (SparcError("audit_storage_failed", "Audit storage failed closed")
                        if audit_latched else error))
        if not self._closed:
            self.events.publish_terminal(
                ServiceEvent("state", {
                    "state": state,
                    "reason": final_error.code,
                    "endpoint": _endpoint_event_data(attempt.endpoint),
                }),
                terminal_generation,
            )

    def _finish_attempt(self, attempt: _Attempt, error: SparcError) -> None:
        with self._state_lock:
            if self._slot is not attempt:
                return
            audit_already_failed = self._audit_failed
            attempt.cancel.set()
            self._receipts.fail_all("Connection ended before delivery confirmation")
            self._hash_ns_by_id.clear()
            if self._closed:
                intended_state = "stopped"
            elif audit_already_failed:
                intended_state = "error"
            elif error.code == "operation_cancelled":
                intended_state = "listening" if self._listener is not None else "stopped"
            else:
                intended_state = "error"

        audit_error = None
        if not audit_already_failed and error.code not in {
            "operation_cancelled", "tcp_loss", "handshake_timeout", "pairing_timeout",
            "audit_storage_failed",
        }:
            try:
                self._append_audit(attempt, "security_rejected", {
                    "code": error.code,
                    "reason": "Handshake or peer security validation was rejected",
                })
            except SparcError as failure:
                audit_error = failure
            except Exception:
                audit_error = SparcError(
                    "audit_storage_failed",
                    "Security rejection could not be durably recorded",
                )

        chain = attempt.retry_chain
        if (
            chain is not None
            and not attempt.reconnect_outcome_attempted
            and audit_error is None
            and not audit_already_failed
            and error.code not in {"operation_cancelled", "audit_storage_failed"}
        ):
            try:
                self._write_reconnect_outcome(attempt, error.code)
            except SparcError as failure:
                audit_error = failure

        if (
            chain is not None
            and error.code == "tcp_loss"
            and audit_error is None
            and not audit_already_failed
            and attempt.retry_index + 1 < len(chain.delays)
        ):
            if self._reserve_retry(attempt, chain, attempt.retry_index + 1):
                with self._state_lock:
                    retry_owner = self._slot
                if retry_owner is not None:
                    self._emit_reconnect_metric(
                        retry_owner, "reconnect_scheduled", True,
                        {"attempts": len(chain.delays),
                         "next_attempt": attempt.retry_index + 2,
                         "delays": list(chain.delays)},
                    )
                return

        with self._state_lock:
            if self._slot is not attempt:
                return
            self._slot = None
            audit_latched = self._audit_failed
            if audit_latched or audit_error is not None or error.code == "audit_storage_failed":
                self._audit_failed = True
            self._generation += 1
            self.events.advance_generation(self._generation)
            if self._closed:
                self._state = "stopped"
            elif audit_latched or audit_error is not None or error.code == "audit_storage_failed":
                self._state = "error"
            else:
                self._state = intended_state
            state = self._state
            terminal_generation = self._generation
        final_error = (
            SparcError("audit_storage_failed", "Audit storage failed closed")
            if audit_latched or error.code == "audit_storage_failed"
            else audit_error or error
        )
        if not self._closed:
            self.events.publish_terminal(
                ServiceEvent("state", {
                    "state": state,
                    "reason": final_error.code,
                    "endpoint": _endpoint_event_data(attempt.endpoint),
                }),
                terminal_generation,
            )

    def _reserve_retry(self, owner: _Attempt, chain: _ReconnectChain, index: int) -> bool:
        """Atomically hand an owned terminal attempt to the next retry slot."""
        with self._state_lock:
            if (
                self._closed
                or self._audit_failed
                or self._slot is not owner
                or self._generation != owner.generation
                or owner.epoch != self._reconnect_epoch
                or chain.cancel.is_set()
                or chain.epoch != self._reconnect_epoch
                or index >= len(chain.delays)
            ):
                return False
            self._generation += 1
            self.events.advance_generation(self._generation)
            retry = _Attempt(
                generation=self._generation,
                role=Role.INITIATOR,
                endpoint=chain.endpoint,
                cancel=threading.Event(),
                epoch=chain.epoch,
                retry_chain=chain,
                retry_index=index,
            )
            self._slot = retry
            self._state = "connecting"
        try:
            self._publish_owned_state(
                retry, "connecting", "reconnect_scheduled", chain.endpoint
            )
            self._start_coordinator(retry)
        except Exception as exc:
            error = exc if isinstance(exc, SparcError) else SparcError(
                "session_unusable", "Could not start reconnect coordinator"
            )
            self._finish_attempt(retry, error)
            return False
        return True

    def _retry_is_current(self, attempt: _Attempt) -> bool:
        chain = attempt.retry_chain
        if chain is None:
            return self._is_current(attempt)
        with self._state_lock:
            return (
                not self._closed
                and not self._audit_failed
                and not attempt.cancel.is_set()
                and not chain.cancel.is_set()
                and chain.epoch == self._reconnect_epoch
                and self._slot is attempt
                and self._generation == attempt.generation
            )

    def _is_current(self, attempt: _Attempt) -> bool:
        with self._state_lock:
            current = (
                not self._closed
                and not self._audit_failed
                and not attempt.cancel.is_set()
                and self._slot is attempt
                and self._generation == attempt.generation
            )
            chain = attempt.retry_chain
            if chain is None:
                return current
            return (
                current
                and not chain.cancel.is_set()
                and chain.epoch == self._reconnect_epoch
            )

    def _on_written(self, attempt: _Attempt, payload: dict, protected: ProtectedRecord) -> None:
        message_id = payload.get("message_id")
        if payload.get("kind") not in {"chat", "benchmark"} or not isinstance(message_id, str):
            return
        with self._state_lock:
            if self._slot is not attempt or attempt.cancel.is_set():
                return
            hash_ns = self._hash_ns_by_id.pop(message_id, None)
        if hash_ns is None:
            return
        self._receipts.update_frame_bytes(message_id, len(protected.frame))
        inspection = protected.inspection
        if inspection is not None:
            inspection = replace(inspection, timings=replace(inspection.timings, hash_ns=hash_ns))
        if payload["kind"] == "benchmark":
            event = ServiceEvent("benchmark_progress", {
                "run_id": payload["run_id"],
                "records": attempt.benchmark_records,
                "bytes": attempt.benchmark_bytes,
                "message_id": message_id,
            })
        else:
            event = ServiceEvent("message", {
                "message_id": message_id,
                "text": payload["text"],
                "inspection": inspection,
                "direction": 0 if attempt.role is Role.INITIATOR else 1,
                "origin": "outgoing",
            })
        self._emit(event, attempt.cancel)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
