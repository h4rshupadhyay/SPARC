"""Pure validation and cryptographic formatting for the SPARC audit log."""

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import hashlib
import ipaddress
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import message_context
from .encoding import canonical
from .models import Identity, SparcError


AUDIT_DOMAIN = b"SPARC-v1 audit\x00"
AUDIT_SIGNATURE_DOMAIN = b"SPARC-v1 audit-signature\x00"
CHECKPOINT_DOMAIN = b"SPARC-v1 checkpoint\x00"
CHECKPOINT_OUTER_FIELDS = frozenset({"body", "signature"})
CHECKPOINT_BODY_FIELDS = frozenset(
    {"log_id", "last_record_number", "last_record_hash", "identity_fingerprint"}
)

_BODY_FIELDS = frozenset(
    {"log_id", "record_number", "timestamp", "event", "identity_fingerprint", "metadata", "previous_hash"}
)
_OPTIONAL_BODY_FIELDS = frozenset({"peer_fingerprint", "endpoint"})
_OUTER_FIELDS = frozenset({"body", "record_hash", "signature"})
_STRING_METADATA = frozenset(
    {"code", "reason", "phase", "state", "message_id", "sha256", "run_id", "fingerprint",
     "endpoint", "approval_time_included", "evidence_mode"}
)
_INTEGER_METADATA = frozenset(
    {"sequence", "direction", "byte_count", "frame_bytes", "attempt", "count", "elapsed_ns",
     "record_count", "encoded_bytes"}
)
_METADATA_FIELDS = _STRING_METADATA | _INTEGER_METADATA | {"peer_evidence"}
_EVIDENCE_FIELDS = frozenset(
    {"public_key", "session_id", "direction", "sequence", "projection", "signature"}
)
_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_TIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
_ENDPOINT_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})\Z")
_UINT64_MAX = 2**64 - 1
_TEXT_MAX = 16 * 1024
_MAX_STRING_BYTES = 1024
_MAX_PROJECTION_BYTES = 8 * 1024


@dataclass(frozen=True)
class AuditAppend:
    record: dict
    elapsed_ns: int
    encoded_bytes: int


@dataclass(frozen=True)
class AuditReport:
    valid: bool
    verified_records: int
    first_failed_record: int | None
    reason: str
    checkpoint_checked: bool
    elapsed_ns: int


def _schema(message: str = "Audit value does not match its schema") -> None:
    raise SparcError("invalid_schema", message)


def _chain(message: str = "Audit record does not match the expected chain") -> None:
    raise SparcError("audit_chain_mismatch", message)


def _hex(value: object, pattern: re.Pattern, name: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _schema(f"{name} has an invalid hexadecimal value")


def _bounded_string(value: object, name: str, *, nonempty: bool = False) -> None:
    if not isinstance(value, str):
        _schema(f"{name} must be a string")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise SparcError("invalid_schema", f"{name} contains invalid Unicode") from exc
    if size > _MAX_STRING_BYTES or (nonempty and size == 0):
        _schema(f"{name} is empty or exceeds the string bound")


def _decode_b64(value: object, length: int) -> bytes:
    if not isinstance(value, str):
        raise SparcError("invalid_base64", "Binary field is not canonical Base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise SparcError("invalid_base64", "Binary field is not canonical Base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise SparcError("invalid_base64", "Binary field has the wrong length or Base64 spelling")
    return raw


def _endpoint(value: object) -> None:
    if not isinstance(value, str):
        _schema("endpoint must be an IPv4 address and port")
    match = _ENDPOINT_RE.fullmatch(value)
    if match is None:
        _schema("endpoint must be an IPv4 address and port")
    try:
        address = ipaddress.IPv4Address(match.group(1))
        port = int(match.group(2))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise SparcError("invalid_schema", "endpoint must be a canonical IPv4 address and port") from exc
    if str(address) != match.group(1) or not 1 <= port <= 65535:
        _schema("endpoint must be a canonical IPv4 address and port")


def _timestamp(value: object) -> None:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        _schema("timestamp must be UTC RFC3339 ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SparcError("invalid_schema", "timestamp is not a valid UTC date and time") from exc


def _depth(value: object, level: int = 1, limit: int = 5) -> None:
    if isinstance(value, dict):
        if level > limit:
            _schema("Audit object exceeds its structural depth bound")
        for key, child in value.items():
            if not isinstance(key, str):
                _schema("Audit object keys must be strings")
            _depth(child, level + 1, limit)
    elif isinstance(value, (list, tuple)):
        _schema("Arrays are not permitted in audit data")
    elif isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SparcError("invalid_schema", "Audit string contains invalid Unicode") from exc
    elif isinstance(value, bool) or value is None or isinstance(value, float):
        _schema("Audit values must be objects, strings or integers")
    elif not isinstance(value, int):
        _schema("Audit value has an unsupported type")


def _validate_projection(projection: object) -> str:
    if not isinstance(projection, dict):
        _schema("Peer signing projection must be an object")
    kind = projection.get("kind")
    if kind == "chat":
        expected = {"kind", "message_id", "byte_count", "sha256"}
    elif kind == "benchmark":
        expected = {"kind", "run_id", "message_id", "byte_count", "sha256"}
    elif kind == "ack":
        expected = {"kind", "message_id", "sha256", "status"}
    elif kind in ("ping", "pong"):
        expected = {"kind", "ping_id"}
    else:
        _schema("Peer signing projection kind is unsupported")
    if projection.keys() != expected:
        _schema("Peer signing projection fields are invalid")
    for key, value in projection.items():
        if not isinstance(value, str) and key != "byte_count":
            _schema("Peer signing projection has an invalid field type")
        if isinstance(value, str):
            _bounded_string(value, f"projection.{key}", nonempty=True)
    if kind in ("chat", "benchmark"):
        _hex(projection["message_id"], _ID_RE, "message_id")
        if kind == "benchmark":
            _hex(projection["run_id"], _ID_RE, "run_id")
        count = projection["byte_count"]
        if type(count) is not int or not 0 < count <= _TEXT_MAX:
            _schema("projection.byte_count is outside its permitted range")
        _hex(projection["sha256"], _HEX64_RE, "sha256")
    elif kind == "ack":
        _hex(projection["message_id"], _ID_RE, "message_id")
        _hex(projection["sha256"], _HEX64_RE, "sha256")
        if projection["status"] != "verified":
            _schema("Acknowledgment status is invalid")
    else:
        _hex(projection["ping_id"], _ID_RE, "ping_id")
    try:
        encoded = canonical(projection)
    except SparcError as exc:
        if exc.code == "invalid_json_value":
            raise SparcError("invalid_schema", "Peer signing projection contains invalid values") from exc
        raise
    if len(encoded) > _MAX_PROJECTION_BYTES:
        _schema("Peer signing projection exceeds its size bound")
    return kind


def _validate_evidence(evidence: object) -> tuple[dict, bytes]:
    if not isinstance(evidence, dict) or evidence.keys() != _EVIDENCE_FIELDS:
        _schema("peer_evidence fields do not match the fixed schema")
    public_key = _decode_b64(evidence["public_key"], 32)
    signature = _decode_b64(evidence["signature"], 64)
    _hex(evidence["session_id"], _HEX64_RE, "peer_evidence.session_id")
    if type(evidence["direction"]) is not int or evidence["direction"] not in (0, 1):
        _schema("peer_evidence.direction must be zero or one")
    if type(evidence["sequence"]) is not int or not 0 <= evidence["sequence"] <= _UINT64_MAX:
        _schema("peer_evidence.sequence is outside uint64")
    projection = evidence["projection"]
    _validate_projection(projection)
    return evidence, signature


def _verify_evidence(evidence: object) -> tuple[dict, bytes, bytes]:
    evidence, signature = _validate_evidence(evidence)
    public_key = base64.b64decode(evidence["public_key"], validate=True)
    context = message_context(
        bytes.fromhex(evidence["session_id"]),
        evidence["direction"],
        evidence["sequence"],
        evidence["projection"],
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, context)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SparcError("peer_evidence_failed", "Peer evidence signature does not verify") from exc
    return evidence, public_key, signature


def verify_peer_evidence(metadata: dict) -> None:
    """Verify the retained peer signing statement using its original C2 context."""
    if not isinstance(metadata, dict) or "peer_evidence" not in metadata:
        _schema("metadata must contain peer_evidence")
    _verify_evidence(metadata["peer_evidence"])


def _validate_metadata(metadata: object, event: str) -> None:
    if not isinstance(metadata, dict):
        _schema("metadata must be an object")
    if metadata.keys() - _METADATA_FIELDS:
        _schema("metadata contains fields outside the public allowlist")
    for key, value in metadata.items():
        if key == "peer_evidence":
            continue
        if key in _STRING_METADATA:
            _bounded_string(value, f"metadata.{key}", nonempty=True)
            if key in {"message_id", "run_id"}:
                _hex(value, _ID_RE, f"metadata.{key}")
            elif key in {"sha256", "fingerprint"}:
                _hex(value, _HEX64_RE, f"metadata.{key}")
            elif key == "endpoint":
                _endpoint(value)
        elif key in _INTEGER_METADATA:
            if type(value) is not int or value < 0:
                _schema(f"metadata.{key} must be a nonnegative integer")
            if key == "direction" and value not in (0, 1):
                _schema("metadata.direction must be zero or one")
            if key == "sequence" and value > _UINT64_MAX:
                _schema("metadata.sequence is outside uint64")
            if key == "byte_count" and not 0 < value <= _TEXT_MAX:
                _schema("metadata.byte_count is outside the message byte bound")
            if key == "attempt" and not 1 <= value <= 3:
                _schema("metadata.attempt is outside the reconnect attempt bound")
        else:
            _schema("metadata contains an unsupported field")
    required = {
        "pairing_outcome": {"fingerprint", "endpoint", "state"},
        "trust_changed": {"fingerprint", "endpoint", "state"},
        "session_established": {"endpoint", "state"},
        "session_closed": {"endpoint", "state", "code", "reason"},
        "send_attempt": {"message_id", "sha256", "byte_count"},
        "verified_receipt": {"message_id", "sha256", "byte_count", "peer_evidence"},
        "verified_delivery": {"message_id", "sha256", "byte_count", "peer_evidence"},
        "security_rejected": {"code", "reason"},
        "reconnect_outcome": {"endpoint", "state", "attempt"},
        "rate_limit_rejected": {"code", "reason", "count"},
    }
    if event not in required:
        _schema("event is not a supported persisted audit event")
    if not required[event].issubset(metadata):
        _schema("metadata is missing fields required by its event")
    evidence = metadata.get("peer_evidence")
    if evidence is not None:
        checked, public_key, _ = _verify_evidence(evidence)
        projection = checked["projection"]
        projection_kind = projection["kind"]
        if event == "verified_receipt" and projection_kind not in {"chat", "benchmark"}:
            _schema("verified_receipt requires signed chat or benchmark evidence")
        if event == "verified_delivery" and projection_kind != "ack":
            _schema("verified_delivery requires signed acknowledgment evidence")
        if projection_kind in {"chat", "benchmark"} and "byte_count" in metadata:
            if projection["byte_count"] != metadata["byte_count"]:
                _schema("metadata.byte_count disagrees with peer evidence")
        peer_fingerprint = hashlib.sha256(public_key).hexdigest()
        if "fingerprint" in metadata and metadata["fingerprint"] != peer_fingerprint:
            _schema("metadata fingerprint does not match peer evidence key")
        for key in ("message_id", "sha256", "run_id"):
            if key in projection and key in metadata and projection[key] != metadata[key]:
                _schema(f"metadata.{key} disagrees with peer evidence")
        for key in ("direction", "sequence"):
            if key in metadata and metadata[key] != checked[key]:
                _schema(f"metadata.{key} disagrees with peer evidence")
        if projection["kind"] == "benchmark" and "run_id" not in metadata:
            _schema("benchmark evidence requires metadata.run_id")
    if event in {"verified_receipt", "verified_delivery"} and evidence is None:
        _schema("verified message events require peer evidence")


def _validate_body(body: object) -> None:
    if not isinstance(body, dict):
        _schema("Audit body must be an object")
    if body.keys() - (_BODY_FIELDS | _OPTIONAL_BODY_FIELDS) or not _BODY_FIELDS.issubset(body):
        _schema("Audit body fields do not match the fixed schema")
    _depth(body)
    _hex(body["log_id"], _ID_RE, "log_id")
    if type(body["record_number"]) is not int or body["record_number"] < 1:
        _schema("record_number must be a positive integer")
    _timestamp(body["timestamp"])
    _bounded_string(body["event"], "event", nonempty=True)
    _hex(body["identity_fingerprint"], _HEX64_RE, "identity_fingerprint")
    _hex(body["previous_hash"], _HEX64_RE, "previous_hash")
    if "peer_fingerprint" in body:
        _hex(body["peer_fingerprint"], _HEX64_RE, "peer_fingerprint")
    if "endpoint" in body:
        _endpoint(body["endpoint"])
    _validate_metadata(body["metadata"], body["event"])
    metadata = body["metadata"]
    if "peer_fingerprint" in body and "fingerprint" in metadata and body["peer_fingerprint"] != metadata["fingerprint"]:
        _schema("body peer_fingerprint disagrees with metadata")
    if "endpoint" in body and "endpoint" in metadata and body["endpoint"] != metadata["endpoint"]:
        _schema("body endpoint disagrees with metadata")


def _identity_public(identity: Identity) -> bytes:
    if not isinstance(identity, Identity):
        _schema("identity must be an Identity")
    try:
        derived = identity.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise SparcError("audit_chain_mismatch", "Signing identity is inconsistent") from exc
    if derived != identity.public_bytes or hashlib.sha256(derived).hexdigest() != identity.fingerprint:
        _chain("Signing identity is inconsistent")
    return derived


def build_audit_record(identity: Identity, body: dict) -> dict:
    """Validate a body, hash its canonical bytes and sign the audit hash."""
    public_key = _identity_public(identity)
    _validate_body(body)
    if body["identity_fingerprint"] != hashlib.sha256(public_key).hexdigest():
        _chain("Audit body owner does not match the signing identity")
    if body["record_number"] == 1 and body["previous_hash"] != "0" * 64:
        _chain("First audit record must link to the zero hash")
    body_bytes = canonical(body)
    record_hash = hashlib.sha256(AUDIT_DOMAIN + body_bytes).digest()
    try:
        signature = identity.private_key.sign(AUDIT_SIGNATURE_DOMAIN + record_hash)
    except Exception as exc:
        raise SparcError("audit_signature_failed", "Audit record could not be signed") from exc
    return {
        "body": body,
        "record_hash": record_hash.hex(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_audit_record(
    record: dict,
    public_key: bytes,
    expected_previous: str,
    expected_number: int,
    expected_log_id: str,
) -> None:
    """Validate and verify one record against a trusted key and chain position."""
    if not isinstance(record, dict) or record.keys() != _OUTER_FIELDS:
        _schema("Audit outer fields do not match the fixed schema")
    _depth(record)
    body = record["body"]
    _validate_body(body)
    _hex(record["record_hash"], _HEX64_RE, "record_hash")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        _schema("Trusted public key must be exactly 32 bytes")
    _hex(expected_previous, _HEX64_RE, "expected_previous")
    _hex(expected_log_id, _ID_RE, "expected_log_id")
    if type(expected_number) is not int or expected_number < 1:
        _schema("expected_number must be a positive integer")
    if (
        body["previous_hash"] != expected_previous
        or body["record_number"] != expected_number
        or body["log_id"] != expected_log_id
        or body["identity_fingerprint"] != hashlib.sha256(public_key).hexdigest()
    ):
        _chain()
    raw_hash = hashlib.sha256(AUDIT_DOMAIN + canonical(body)).digest()
    if record["record_hash"] != raw_hash.hex():
        raise SparcError("audit_hash_mismatch", "Audit record hash does not match its body")
    signature = _decode_b64(record["signature"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, AUDIT_SIGNATURE_DOMAIN + raw_hash
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SparcError("audit_signature_failed", "Audit record signature does not verify") from exc
