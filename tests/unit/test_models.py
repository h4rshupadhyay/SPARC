from dataclasses import FrozenInstanceError, fields
import math

import pytest


def test_limits_are_frozen_and_match_spec():
    from sparc.models import Limits

    limits = Limits()
    assert limits.text_bytes == 16384
    assert limits.handshake_json_bytes == 8192
    assert limits.frame_bytes == 131072
    assert limits.pending_requests == 100
    assert limits.event_queue == 1024
    assert limits.outbound_queue == 1024
    assert limits.control_queue == 100
    assert limits.completed_receipts == 100
    assert limits.chat_history == 500
    assert limits.cancel_poll_seconds == 1.0
    assert limits.hello_timeout_seconds == 20.0
    assert limits.client_auth_timeout_seconds == 150.0
    assert limits.responder_finished_timeout_seconds == 150.0
    assert limits.pairing_timeout_seconds == 120.0
    assert limits.handshake_timeout_seconds == 300.0
    assert limits.client_finished_timeout_seconds == 10.0
    assert limits.frame_timeout_seconds == 10.0
    assert limits.delivery_timeout_seconds == 10.0
    assert limits.connection_window_seconds == 60.0
    assert limits.connections_per_source == 20
    assert limits.connections_global == 60
    assert limits.source_buckets == 256
    assert limits.record_rate == 200.0
    assert limits.record_burst == 400
    assert limits.heartbeat_seconds == 5.0
    assert limits.peer_timeout_seconds == 15.0
    assert limits.reconnect_delays == (1.0, 2.0, 4.0)
    assert limits.audit_aggregate_seconds == 5.0
    assert limits.benchmark_records == 1000
    assert limits.benchmark_bytes == 16777216
    assert limits.resource_sample_seconds == 1.0

    with pytest.raises(FrozenInstanceError):
        limits.text_bytes = 1


def test_limits_reject_invalid_values_and_security_invariants():
    from sparc.models import Limits

    integer_limits = (
        "text_bytes", "handshake_json_bytes", "frame_bytes", "pending_requests",
        "event_queue", "outbound_queue", "control_queue", "completed_receipts",
        "chat_history", "connections_per_source", "connections_global",
        "source_buckets", "record_burst", "benchmark_records", "benchmark_bytes",
    )
    for name in integer_limits:
        with pytest.raises((TypeError, ValueError)):
            Limits(**{name: True})
        with pytest.raises((TypeError, ValueError)):
            Limits(**{name: 0})
        with pytest.raises((TypeError, ValueError)):
            Limits(**{name: 1.5})

    for name in (
        "cancel_poll_seconds", "hello_timeout_seconds", "client_auth_timeout_seconds",
        "responder_finished_timeout_seconds", "pairing_timeout_seconds",
        "handshake_timeout_seconds", "client_finished_timeout_seconds",
        "frame_timeout_seconds", "delivery_timeout_seconds", "connection_window_seconds",
        "record_rate", "heartbeat_seconds", "peer_timeout_seconds",
        "audit_aggregate_seconds", "resource_sample_seconds",
    ):
        for invalid in (True, 0, -1, math.inf, -math.inf, math.nan):
            with pytest.raises((TypeError, ValueError)):
                Limits(**{name: invalid})

    for invalid_delays in ([], (0.0,), (-1.0,), (1.0, math.inf), (1.0, 2.0, 3.0, 4.0)):
        with pytest.raises((TypeError, ValueError)):
            Limits(reconnect_delays=invalid_delays)

    with pytest.raises((TypeError, ValueError)):
        Limits(cancel_poll_seconds=1.01)
    with pytest.raises((TypeError, ValueError)):
        Limits(frame_bytes=57)
    with pytest.raises((TypeError, ValueError)):
        Limits(handshake_json_bytes=131072)
    with pytest.raises((TypeError, ValueError)):
        Limits(text_bytes=131072)
    with pytest.raises((TypeError, ValueError)):
        Limits(heartbeat_seconds=15.0)

    # Shortened, positive deadlines remain valid for tests and callers.
    assert Limits(hello_timeout_seconds=0.01).hello_timeout_seconds == 0.01


def test_event_and_inspection_have_no_secret_fields():
    from sparc.models import Inspection, ServiceEvent

    assert {field.name for field in fields(Inspection)} == {
        "message_id", "sequence", "sha256", "computed_sha256", "signature",
        "ciphertext", "nonce", "tag", "plaintext_bytes", "timings",
    }
    assert {field.name for field in fields(ServiceEvent)} == {"kind", "data"}


def test_sparc_error_exposes_stable_category_and_message():
    from sparc.models import SparcError

    error = SparcError("invalid_record", "Record rejected")
    assert error.code == "invalid_record"
    assert error.message == "Record rejected"
    assert str(error) == "Record rejected"
