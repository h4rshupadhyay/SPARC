"""Independent format and signature oracles for C4a audit records."""

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


AUDIT_DOMAIN = b"SPARC-v1 audit\x00"
AUDIT_SIGNATURE_DOMAIN = b"SPARC-v1 audit-signature\x00"
MESSAGE_DOMAIN = b"SPARC-v1 message\x00"
LOG_ID = "0123456789abcdef0123456789abcdef"
ZERO_HASH = "0" * 64
PEER_SESSION_ID = "a" * 64
MESSAGE_ID = "1234567890abcdef1234567890abcdef"
MESSAGE_HASH = hashlib.sha256(b"hello").hexdigest()


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _identity(seed=bytes(range(32))):
    from sparc.models import Identity

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())


def _body(identity, event="send_attempt", metadata=None, **changes):
    body = {
        "log_id": LOG_ID,
        "record_number": 1,
        "timestamp": "2026-10-08T12:34:56.123456Z",
        "event": event,
        "identity_fingerprint": identity.fingerprint,
        "metadata": metadata if metadata is not None else {
            "message_id": MESSAGE_ID,
            "sha256": MESSAGE_HASH,
            "byte_count": 5,
        },
        "previous_hash": ZERO_HASH,
    }
    body.update(changes)
    return body


def _signed_peer_evidence(kind="chat", *, direction=1, sequence=7, changes=None):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    session_id = bytes.fromhex(PEER_SESSION_ID)
    projection = {
        "kind": kind,
        "message_id": MESSAGE_ID,
        "byte_count": 5,
        "sha256": MESSAGE_HASH,
    }
    if kind == "benchmark":
        projection = {"kind": kind, "run_id": "fedcba9876543210fedcba9876543210", **projection}
    elif kind == "ack":
        projection = {"kind": kind, "message_id": MESSAGE_ID, "sha256": MESSAGE_HASH, "status": "verified"}
    elif kind in ("ping", "pong"):
        projection = {"kind": kind, "ping_id": MESSAGE_ID}
    if changes:
        projection.update(changes)
    context = (
        MESSAGE_DOMAIN
        + session_id
        + bytes((direction,))
        + sequence.to_bytes(8, "big")
        + _canonical(projection)
    )
    return {
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "session_id": PEER_SESSION_ID,
        "direction": direction,
        "sequence": sequence,
        "projection": projection,
        "signature": base64.b64encode(private_key.sign(context)).decode("ascii"),
    }


def _message_metadata(event="verified_receipt", evidence=None):
    result = {
        "message_id": MESSAGE_ID,
        "sha256": MESSAGE_HASH,
        "byte_count": 5,
    }
    if evidence is not None:
        result["peer_evidence"] = evidence
    return result


def _independently_signed_record(identity, body):
    digest = hashlib.sha256(AUDIT_DOMAIN + _canonical(body)).digest()
    return {
        "body": body,
        "record_hash": digest.hex(),
        "signature": base64.b64encode(
            identity.private_key.sign(AUDIT_SIGNATURE_DOMAIN + digest)
        ).decode("ascii"),
    }


def _expect_code(code, function, *args, **kwargs):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as raised:
        function(*args, **kwargs)
    assert raised.value.code == code


def test_exact_audit_hash_signature_domains():
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    body = _body(identity)
    record = build_audit_record(identity, body)
    expected_hash = hashlib.sha256(AUDIT_DOMAIN + _canonical(body)).hexdigest()
    assert record == {
        "body": body,
        "record_hash": expected_hash,
        "signature": base64.b64encode(
            identity.private_key.sign(AUDIT_SIGNATURE_DOMAIN + bytes.fromhex(expected_hash))
        ).decode("ascii"),
    }
    identity.private_key.public_key().verify(
        base64.b64decode(record["signature"], validate=True),
        AUDIT_SIGNATURE_DOMAIN + bytes.fromhex(expected_hash),
    )
    verify_audit_record(record, identity.public_bytes, ZERO_HASH, 1, LOG_ID)


@pytest.mark.parametrize("kind", ["chat", "benchmark", "ack", "ping", "pong"])
def test_peer_evidence_reconstructs_context(kind):
    from sparc.audit_format import verify_peer_evidence

    evidence = _signed_peer_evidence(kind)
    verify_peer_evidence({"peer_evidence": evidence})

    edited = copy.deepcopy(evidence)
    if kind in ("chat", "benchmark"):
        edited["projection"]["sha256"] = "b" * 64
    else:
        field = "message_id" if kind == "ack" else "ping_id"
        edited["projection"][field] = "0" * 32
    _expect_code("peer_evidence_failed", verify_peer_evidence, {"peer_evidence": edited})


def test_peer_evidence_context_includes_session_direction_and_sequence():
    from sparc.audit_format import verify_peer_evidence

    original = _signed_peer_evidence("chat")
    for key, value in (("session_id", "b" * 64), ("direction", 0), ("sequence", 8)):
        tampered = copy.deepcopy(original)
        tampered[key] = value
        _expect_code("peer_evidence_failed", verify_peer_evidence, {"peer_evidence": tampered})


@pytest.mark.parametrize("event,metadata", [
    ("pairing_outcome", {"fingerprint": "a" * 64, "endpoint": "127.0.0.1:47655", "state": "paired"}),
    ("trust_changed", {"fingerprint": "a" * 64, "endpoint": "127.0.0.1:47655", "state": "known"}),
    ("session_established", {"endpoint": "127.0.0.1:47655", "state": "established"}),
    ("session_closed", {"endpoint": "127.0.0.1:47655", "state": "closed", "code": "tcp_loss", "reason": "peer disconnected"}),
    ("send_attempt", _message_metadata("send_attempt")),
    ("verified_receipt", _message_metadata(evidence=_signed_peer_evidence("chat"))),
    ("verified_delivery", _message_metadata(evidence=_signed_peer_evidence("ack"))),
    ("security_rejected", {"code": "invalid_schema", "reason": "unsupported message"}),
    ("reconnect_outcome", {"endpoint": "127.0.0.1:47655", "state": "connected", "attempt": 1}),
    ("rate_limit_rejected", {"code": "rate_limited", "reason": "attempt limit", "count": 3}),
])
def test_each_persisted_event_schema_builds_and_verifies(event, metadata):
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    body = _body(identity, event=event, metadata=metadata)
    if event in ("pairing_outcome", "trust_changed"):
        body["peer_fingerprint"] = metadata["fingerprint"]
        body["endpoint"] = metadata["endpoint"]
    elif "endpoint" in metadata:
        body["endpoint"] = metadata["endpoint"]
    record = build_audit_record(identity, body)
    verify_audit_record(record, identity.public_bytes, ZERO_HASH, 1, LOG_ID)


def test_plaintext_or_secret_metadata_rejected():
    from sparc.audit_format import build_audit_record, verify_peer_evidence

    identity = _identity()
    for key, value in (("text", "hello"), ("private_key", "secret"), ("session_key", "secret"), ("arbitrary", "value")):
        body = _body(identity, metadata={"message_id": MESSAGE_ID, "sha256": MESSAGE_HASH, "byte_count": 5, key: value})
        _expect_code("invalid_schema", build_audit_record, identity, body)
    evidence = _signed_peer_evidence("chat", changes={"text": "hello"})
    _expect_code("invalid_schema", verify_peer_evidence, {"peer_evidence": evidence})


@pytest.mark.parametrize("change", [
    {"event_kind": "send_attempt"},
    {"record_number": True},
    {"record_number": 0},
    {"log_id": "A" * 32},
    {"identity_fingerprint": "x" * 64},
    {"timestamp": "2026-02-30T12:00:00Z"},
    {"timestamp": "2026-10-08T12:00:00+00:00"},
])
def test_body_schema_and_first_link_rejections(change):
    from sparc.audit_format import build_audit_record

    identity = _identity()
    _expect_code("invalid_schema", build_audit_record, identity, _body(identity, **change))


def test_first_record_requires_zero_previous_hash():
    from sparc.audit_format import build_audit_record

    identity = _identity()
    _expect_code(
        "audit_chain_mismatch",
        build_audit_record,
        identity,
        _body(identity, previous_hash="f" * 64),
    )


def test_outer_schema_and_expected_chain_coordinates():
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    record = build_audit_record(identity, _body(identity))
    for extra in ("extra",):
        malformed = {**record, extra: "x"}
        _expect_code("invalid_schema", verify_audit_record, malformed, identity.public_bytes, ZERO_HASH, 1, LOG_ID)
    for previous, number, log_id in (("f" * 64, 1, LOG_ID), (ZERO_HASH, 2, LOG_ID), (ZERO_HASH, 1, "f" * 32)):
        _expect_code("audit_chain_mismatch", verify_audit_record, record, identity.public_bytes, previous, number, log_id)


def test_record_hash_and_signature_failures_have_fixed_codes():
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    record = build_audit_record(identity, _body(identity))
    bad_hash = copy.deepcopy(record)
    bad_hash["record_hash"] = "f" * 64
    _expect_code("audit_hash_mismatch", verify_audit_record, bad_hash, identity.public_bytes, ZERO_HASH, 1, LOG_ID)
    changed_body = copy.deepcopy(record)
    changed_body["body"]["metadata"]["byte_count"] = 6
    _expect_code("audit_hash_mismatch", verify_audit_record, changed_body, identity.public_bytes, ZERO_HASH, 1, LOG_ID)
    bad_signature = copy.deepcopy(record)
    bad_signature["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    _expect_code("audit_signature_failed", verify_audit_record, bad_signature, identity.public_bytes, ZERO_HASH, 1, LOG_ID)


def test_peer_evidence_rejects_noncanonical_base64_and_wrong_projection_fields():
    from sparc.audit_format import verify_peer_evidence

    evidence = _signed_peer_evidence("chat")
    for key, value, code in (
        ("public_key", evidence["public_key"] + "\n", "invalid_base64"),
        ("signature", base64.b64encode(b"s" * 64).decode("ascii"), "peer_evidence_failed"),
    ):
        changed = copy.deepcopy(evidence)
        changed[key] = value
        _expect_code(code, verify_peer_evidence, {"peer_evidence": changed})
    changed = copy.deepcopy(evidence)
    changed["projection"]["extra"] = "x"
    _expect_code("invalid_schema", verify_peer_evidence, {"peer_evidence": changed})


def test_frozen_audit_dataclass_fields():
    from dataclasses import FrozenInstanceError, fields

    from sparc.audit_format import AuditAppend, AuditReport

    assert [field.name for field in fields(AuditAppend)] == ["record", "elapsed_ns", "encoded_bytes"]
    assert [field.name for field in fields(AuditReport)] == [
        "valid", "verified_records", "first_failed_record", "reason", "checkpoint_checked", "elapsed_ns"
    ]
    append = AuditAppend({}, 1, 2)
    with pytest.raises(FrozenInstanceError):
        append.elapsed_ns = 3
    report = AuditReport(True, 1, None, "", False, 1)
    with pytest.raises(FrozenInstanceError):
        report.valid = False


def test_checkpoint_schema_constants_are_fixed():
    from sparc.audit_format import CHECKPOINT_BODY_FIELDS, CHECKPOINT_DOMAIN, CHECKPOINT_OUTER_FIELDS

    assert CHECKPOINT_DOMAIN == b"SPARC-v1 checkpoint\x00"
    assert CHECKPOINT_OUTER_FIELDS == frozenset({"body", "signature"})
    assert CHECKPOINT_BODY_FIELDS == frozenset(
        {"log_id", "last_record_number", "last_record_hash", "identity_fingerprint"}
    )


@pytest.mark.parametrize("metadata", [
    {"message_id": "0" * 31, "sha256": MESSAGE_HASH, "byte_count": 5},
    {"message_id": MESSAGE_ID, "sha256": "b" * 63, "byte_count": 5},
    {"message_id": MESSAGE_ID, "sha256": MESSAGE_HASH, "byte_count": True},
    {"message_id": MESSAGE_ID, "sha256": MESSAGE_HASH, "byte_count": 5, "sequence": True},
])
def test_required_metadata_and_protocol_integer_types(metadata):
    from sparc.audit_format import build_audit_record

    identity = _identity()
    _expect_code("invalid_schema", build_audit_record, identity, _body(identity, metadata=metadata))


def test_evidence_and_repeated_metadata_values_must_agree():
    from sparc.audit_format import build_audit_record

    identity = _identity()
    evidence = _signed_peer_evidence("chat", sequence=7)
    metadata = _message_metadata(evidence=evidence)
    metadata["sequence"] = 8
    metadata["direction"] = evidence["direction"]
    _expect_code(
        "invalid_schema",
        build_audit_record,
        identity,
        _body(identity, event="verified_receipt", metadata=metadata),
    )


@pytest.mark.parametrize("kind", ["ack", "ping", "pong"])
def test_verified_receipt_rejects_nonchat_evidence_on_build_and_verify(kind):
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    evidence = _signed_peer_evidence(kind)
    metadata = _message_metadata(evidence=evidence)
    if kind == "ack":
        metadata["message_id"] = evidence["projection"]["message_id"]
        metadata["sha256"] = evidence["projection"]["sha256"]
    body = _body(identity, event="verified_receipt", metadata=metadata)
    _expect_code("invalid_schema", build_audit_record, identity, body)
    _expect_code(
        "invalid_schema",
        verify_audit_record,
        _independently_signed_record(identity, body),
        identity.public_bytes,
        ZERO_HASH,
        1,
        LOG_ID,
    )


@pytest.mark.parametrize("kind", ["chat", "benchmark", "ping", "pong"])
def test_verified_delivery_rejects_nonack_evidence_on_build_and_verify(kind):
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    evidence = _signed_peer_evidence(kind)
    metadata = _message_metadata(evidence=evidence)
    if kind == "benchmark":
        metadata["run_id"] = evidence["projection"]["run_id"]
    body = _body(identity, event="verified_delivery", metadata=metadata)
    _expect_code("invalid_schema", build_audit_record, identity, body)
    _expect_code(
        "invalid_schema",
        verify_audit_record,
        _independently_signed_record(identity, body),
        identity.public_bytes,
        ZERO_HASH,
        1,
        LOG_ID,
    )


@pytest.mark.parametrize("event,kind", [
    ("verified_receipt", "chat"),
    ("verified_receipt", "benchmark"),
    ("verified_delivery", "chat"),
    ("verified_delivery", "benchmark"),
])
def test_verified_text_event_requires_evidence_byte_count_match_on_build_and_verify(event, kind):
    from sparc.audit_format import build_audit_record, verify_audit_record

    identity = _identity()
    evidence = _signed_peer_evidence(kind)
    metadata = _message_metadata(evidence=evidence)
    if kind == "benchmark":
        metadata["run_id"] = evidence["projection"]["run_id"]
    metadata["byte_count"] = evidence["projection"]["byte_count"] + 1
    body = _body(identity, event=event, metadata=metadata)
    _expect_code("invalid_schema", build_audit_record, identity, body)
    _expect_code(
        "invalid_schema",
        verify_audit_record,
        _independently_signed_record(identity, body),
        identity.public_bytes,
        ZERO_HASH,
        1,
        LOG_ID,
    )
