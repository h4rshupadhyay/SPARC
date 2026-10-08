"""C5b bounded receipt state and confirmation ordering."""

import threading

import pytest

from sparc.models import DeliveryReceipt, SparcError
from sparc.peer.receipts import PendingMessage, ReceiptLedger


def _message(index, *, started_ns=1_000, frame_bytes=0):
    return PendingMessage(
        message_id=f"{index:032x}",
        sha256=f"{index:064x}",
        started_ns=started_ns,
        plaintext_bytes=17,
        characters=13,
        frame_bytes=frame_bytes,
    )


def _code(call, expected):
    with pytest.raises(SparcError) as raised:
        call()
    assert raised.value.code == expected


def test_pending_101_is_busy():
    ledger = ReceiptLedger()
    for index in range(100):
        ledger.reserve(_message(index))
    _code(lambda: ledger.reserve(_message(100)), "busy")


def test_receipt_must_match_id_and_digest():
    ledger = ReceiptLedger()
    pending = _message(1)
    ledger.reserve(pending)
    _code(lambda: ledger.validate_ack(pending.message_id, "0" * 64), "ack_mismatch")
    _code(lambda: ledger.validate_ack("f" * 32, pending.sha256), "ack_unknown")
    assert ledger.validate_ack(pending.message_id, pending.sha256) == pending
    receipt = ledger.confirm(pending.message_id, pending.sha256, pending.started_ns + 2)
    assert isinstance(receipt, DeliveryReceipt)
    assert receipt.message_id == pending.message_id


def test_expiry_and_caller_wait_timeout_or_cancel_have_distinct_results():
    ledger = ReceiptLedger()
    pending = _message(1, started_ns=0)
    ledger.reserve(pending)
    _code(lambda: ledger.wait(pending.message_id, timeout=0.001), "receipt_timeout")
    cancel = threading.Event()
    cancel.set()
    _code(lambda: ledger.wait(pending.message_id, timeout=0.1, cancel=cancel), "operation_cancelled")
    assert ledger.validate_ack(pending.message_id, pending.sha256) == pending
    assert ledger.expire(10_000_000_000) == [pending.message_id]
    _code(lambda: ledger.wait(pending.message_id, timeout=0.1), "delivery_timeout")
    assert ledger.expire(20_000_000_000) == []


def test_confirmation_at_delivery_deadline_expires_instead():
    ledger = ReceiptLedger()
    pending = _message(1, started_ns=5_000)
    ledger.reserve(pending)
    _code(
        lambda: ledger.confirm(pending.message_id, pending.sha256, pending.started_ns + 10_000_000_000),
        "delivery_timeout",
    )
    _code(lambda: ledger.confirm(pending.message_id, pending.sha256, pending.started_ns + 1), "ack_unknown")


def test_completed_success_and_failure_share_bounded_cache():
    ledger = ReceiptLedger(limit=2)
    first, second, third = (_message(i) for i in range(3))
    ledger.reserve(first)
    ledger.confirm(first.message_id, first.sha256, first.started_ns + 1)
    ledger.reserve(second)
    ledger.reserve(third)
    ledger.fail_one(second.message_id, "disconnected")
    ledger.fail_one(third.message_id, "disconnected")
    _code(lambda: ledger.wait(first.message_id, timeout=0), "receipt_unavailable")
    _code(lambda: ledger.wait(second.message_id, timeout=0), "delivery_unconfirmed")
    _code(lambda: ledger.wait(third.message_id, timeout=0), "delivery_unconfirmed")


def test_fail_one_preserves_other_pending_messages_and_terminal_ids_cannot_be_reused():
    ledger = ReceiptLedger()
    failed, live = _message(1), _message(2)
    ledger.reserve(failed)
    ledger.reserve(live)
    ledger.fail_one(failed.message_id, "enqueue failed")
    _code(lambda: ledger.wait(failed.message_id, timeout=0), "delivery_unconfirmed")
    assert ledger.validate_ack(live.message_id, live.sha256) == live
    receipt = ledger.confirm(live.message_id, live.sha256, live.started_ns + 1)
    assert receipt.message_id == live.message_id
    _code(lambda: ledger.reserve(failed), "duplicate_message_id")


def test_validate_ack_does_not_notify_success_waiter():
    ledger = ReceiptLedger()
    pending = _message(1)
    ledger.reserve(pending)
    started = threading.Event()
    completed = threading.Event()
    result = []

    def wait_for_receipt():
        started.set()
        try:
            result.append(ledger.wait(pending.message_id, timeout=1))
        except SparcError as error:
            result.append(error.code)
        finally:
            completed.set()

    waiter = threading.Thread(target=wait_for_receipt)
    waiter.start()
    assert started.wait(timeout=1)
    assert ledger.validate_ack(pending.message_id, pending.sha256) == pending
    assert not completed.is_set()
    assert waiter.is_alive()
    ledger.confirm(pending.message_id, pending.sha256, pending.started_ns + 1)
    waiter.join(timeout=1)
    assert not waiter.is_alive()
    assert len(result) == 1 and isinstance(result[0], DeliveryReceipt)


def test_frame_bytes_are_updated_before_fast_ack_confirmation():
    ledger = ReceiptLedger()
    pending = _message(1)
    ledger.reserve(pending)
    ledger.update_frame_bytes(pending.message_id, 123)
    assert ledger.validate_ack(pending.message_id, pending.sha256) == PendingMessage(
        **{**pending.__dict__, "frame_bytes": 123}
    )
    receipt = ledger.confirm(pending.message_id, pending.sha256, pending.started_ns + 1)
    assert receipt.frame_bytes == 123
    _code(lambda: ledger.update_frame_bytes(pending.message_id, 456), "receipt_unavailable")


def test_fail_all_and_terminal_failures_are_idempotent():
    ledger = ReceiptLedger()
    first, second = _message(1), _message(2)
    ledger.reserve(first)
    ledger.reserve(second)
    ledger.fail_one(first.message_id, "one failed")
    ledger.fail_all("session lost")
    ledger.fail_all("again")
    _code(lambda: ledger.wait(first.message_id, timeout=0), "delivery_unconfirmed")
    _code(lambda: ledger.wait(second.message_id, timeout=0), "delivery_unconfirmed")
