"""Bounded pending-message and delivery-receipt state."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from threading import Event

from ..models import DeliveryReceipt, SparcError


@dataclass(frozen=True)
class PendingMessage:
    message_id: str
    sha256: str
    started_ns: int
    plaintext_bytes: int
    characters: int
    frame_bytes: int


class ReceiptLedger:
    """Serialize pending, terminal, and waiter state under a private condition."""

    def __init__(self, limit: int = 100, *, delivery_timeout_seconds: float = 10.0) -> None:
        if type(limit) is not int or limit <= 0:
            raise SparcError("invalid_schema", "Receipt limit must be a positive integer")
        if isinstance(delivery_timeout_seconds, bool) or not isinstance(
            delivery_timeout_seconds, (int, float)
        ) or not math.isfinite(delivery_timeout_seconds) or delivery_timeout_seconds <= 0:
            raise SparcError("invalid_schema", "Delivery timeout must be a finite positive number")
        self._limit = limit
        self._delivery_timeout_ns = int(delivery_timeout_seconds * 1_000_000_000)
        self._pending: dict[str, PendingMessage] = {}
        self._terminal: OrderedDict[str, DeliveryReceipt | SparcError] = OrderedDict()
        self._condition = threading.Condition()

    def reserve(self, pending: PendingMessage) -> None:
        if not isinstance(pending, PendingMessage):
            raise SparcError("invalid_schema", "Pending message is invalid")
        with self._condition:
            if pending.message_id in self._pending or pending.message_id in self._terminal:
                raise SparcError("duplicate_message_id", "Message ID is already reserved")
            if len(self._pending) >= self._limit:
                raise SparcError("busy", "Pending delivery limit is full")
            self._pending[pending.message_id] = pending

    def validate_ack(self, message_id: str, digest: str) -> PendingMessage:
        with self._condition:
            pending = self._pending.get(message_id)
            if pending is None:
                raise SparcError("ack_unknown", "Acknowledgment does not match a pending message")
            if pending.sha256 != digest:
                raise SparcError("ack_mismatch", "Acknowledgment digest does not match")
            return pending

    def confirm(self, message_id: str, digest: str, finished_ns: int) -> DeliveryReceipt:
        with self._condition:
            pending = self._pending.get(message_id)
            if pending is None:
                if message_id in self._terminal:
                    raise SparcError("ack_unknown", "Message is already terminal")
                raise SparcError("ack_unknown", "Acknowledgment does not match a pending message")
            if pending.sha256 != digest:
                raise SparcError("ack_mismatch", "Acknowledgment digest does not match")
            if type(finished_ns) is not int or finished_ns < pending.started_ns:
                raise SparcError("invalid_schema", "Receipt finish time precedes its start")
            if finished_ns >= pending.started_ns + self._delivery_timeout_ns:
                error = SparcError("delivery_timeout", "Delivery confirmation deadline expired")
                self._finish_failure_locked(message_id, error)
                raise error

            receipt = DeliveryReceipt(
                message_id=pending.message_id,
                started_ns=pending.started_ns,
                finished_ns=finished_ns,
                plaintext_bytes=pending.plaintext_bytes,
                characters=pending.characters,
                frame_bytes=pending.frame_bytes,
            )
            del self._pending[message_id]
            self._remember_terminal_locked(message_id, receipt)
            self._condition.notify_all()
            return receipt

    def wait(self, message_id: str, timeout: float,
             cancel: Event | None = None) -> DeliveryReceipt:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
            raise SparcError("invalid_schema", "Receipt wait timeout must be finite")
        if timeout < 0:
            raise SparcError("invalid_schema", "Receipt wait timeout cannot be negative")
        if cancel is not None and not isinstance(cancel, Event):
            raise SparcError("invalid_schema", "Receipt wait cancellation event is invalid")
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                if cancel is not None and cancel.is_set():
                    raise SparcError("operation_cancelled", "Receipt wait was canceled")
                terminal = self._terminal.get(message_id)
                if isinstance(terminal, DeliveryReceipt):
                    return terminal
                if isinstance(terminal, SparcError):
                    raise SparcError(terminal.code, terminal.message)
                if message_id not in self._pending:
                    raise SparcError("receipt_unavailable", "Receipt is unknown or no longer retained")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SparcError("receipt_timeout", "Receipt wait timed out")
                self._condition.wait(timeout=min(remaining, 0.05))

    def fail_one(self, message_id: str, reason: str) -> None:
        with self._condition:
            if message_id not in self._pending:
                return
            error = SparcError("delivery_unconfirmed", self._safe_reason(reason))
            self._finish_failure_locked(message_id, error)

    def fail_all(self, reason: str) -> None:
        with self._condition:
            for message_id in list(self._pending):
                error = SparcError("delivery_unconfirmed", self._safe_reason(reason))
                self._finish_failure_locked(message_id, error)

    def expire(self, now_ns: int) -> list[str]:
        if type(now_ns) is not int:
            raise SparcError("invalid_schema", "Receipt expiry time must be an integer")
        expired: list[str] = []
        with self._condition:
            for message_id, pending in list(self._pending.items()):
                if now_ns >= pending.started_ns + self._delivery_timeout_ns:
                    error = SparcError("delivery_timeout", "Delivery confirmation deadline expired")
                    self._finish_failure_locked(message_id, error)
                    expired.append(message_id)
        return expired

    def update_frame_bytes(self, message_id: str, frame_bytes: int) -> None:
        if type(frame_bytes) is not int or frame_bytes < 0:
            raise SparcError("invalid_schema", "Encoded frame size must be a nonnegative integer")
        with self._condition:
            pending = self._pending.get(message_id)
            if pending is None:
                raise SparcError("receipt_unavailable", "Pending receipt is unavailable")
            self._pending[message_id] = replace(pending, frame_bytes=frame_bytes)

    @staticmethod
    def _safe_reason(reason: str) -> str:
        if not isinstance(reason, str):
            return "Delivery could not be confirmed"
        bounded = "".join(character if character.isprintable() else " " for character in reason)
        bounded = " ".join(bounded.split())[:120]
        return bounded or "Delivery could not be confirmed"

    def _finish_failure_locked(self, message_id: str, error: SparcError) -> None:
        del self._pending[message_id]
        self._remember_terminal_locked(message_id, error)
        self._condition.notify_all()

    def _remember_terminal_locked(self, message_id: str,
                                  result: DeliveryReceipt | SparcError) -> None:
        self._terminal[message_id] = result
        self._terminal.move_to_end(message_id)
        while len(self._terminal) > self._limit:
            self._terminal.popitem(last=False)
