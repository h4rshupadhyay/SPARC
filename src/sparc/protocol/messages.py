"""Validation and signing projections for SPARC application messages."""

import base64
import binascii
import hashlib
import re
import time

from ..models import SparcError


_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TEXT_LIMIT = 16 * 1024
_SIGNATURE_BYTES = 64

_UNSIGNED_FIELDS = {
    "chat": frozenset(("kind", "message_id", "text", "byte_count", "sha256")),
    "benchmark": frozenset(("kind", "run_id", "message_id", "text", "byte_count", "sha256")),
    "ack": frozenset(("kind", "message_id", "sha256", "status")),
    "ping": frozenset(("kind", "ping_id")),
    "pong": frozenset(("kind", "ping_id")),
}


def _require_id(value: object, name: str) -> None:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise SparcError("invalid_schema", f"{name} must be 32 lowercase hexadecimal characters")


def _require_digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise SparcError("invalid_schema", "sha256 must be 64 lowercase hexadecimal characters")


def decode_base64(value: str, length: int) -> bytes:
    """Decode standard padded Base64 and require its exact canonical spelling."""
    if not isinstance(value, str) or type(length) is not int or length < 0:
        raise SparcError("invalid_base64", "Binary field has an invalid encoding or length")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise SparcError("invalid_base64", "Binary field is not valid standard Base64") from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise SparcError("invalid_base64", "Binary field is not canonical Base64 of the required length")
    return decoded


def prepare_text(text: str, message_id: str, run_id: str | None = None) -> tuple[dict, int]:
    """Validate local text and return its unsigned envelope and hash duration."""
    if not isinstance(text, str) or not text:
        raise SparcError("invalid_text", "Text must be a nonempty string")
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SparcError("invalid_text", "Text contains invalid Unicode") from exc
    if not encoded or len(encoded) > _TEXT_LIMIT:
        raise SparcError("invalid_text", "Text exceeds the UTF-8 byte limit")
    _require_id(message_id, "message_id")
    if run_id is not None:
        _require_id(run_id, "run_id")

    started = time.perf_counter_ns()
    raw_digest = hashlib.sha256(encoded).digest()
    hash_ns = time.perf_counter_ns() - started
    payload = {
        "kind": "benchmark" if run_id is not None else "chat",
        **({"run_id": run_id} if run_id is not None else {}),
        "message_id": message_id,
        "text": text,
        "byte_count": len(encoded),
        "sha256": raw_digest.hex(),
    }
    return payload, hash_ns


def validate_application(payload: dict, signed: bool = True) -> None:
    """Validate one exact application schema without authenticating its content."""
    if not isinstance(payload, dict):
        raise SparcError("invalid_schema", "Application payload must be an object")
    kind = payload.get("kind")
    fields = _UNSIGNED_FIELDS.get(kind) if isinstance(kind, str) else None
    if fields is None:
        raise SparcError("invalid_schema", "Application kind is unsupported")
    if type(signed) is not bool:
        raise SparcError("invalid_schema", "Signed-mode selector must be a boolean")
    expected = fields | ({"signature"} if signed else set())
    if payload.keys() != expected:
        raise SparcError("invalid_schema", "Application fields do not match the required schema")

    if kind in ("chat", "benchmark"):
        _require_id(payload.get("message_id"), "message_id")
        if kind == "benchmark":
            _require_id(payload.get("run_id"), "run_id")
        text = payload.get("text")
        if not isinstance(text, str) or not text:
            raise SparcError("invalid_schema", "Text must be a nonempty string")
        try:
            encoded = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SparcError("invalid_schema", "Text contains invalid Unicode") from exc
        if len(encoded) > _TEXT_LIMIT:
            raise SparcError("invalid_schema", "Text exceeds the UTF-8 byte limit")
        byte_count = payload.get("byte_count")
        if type(byte_count) is not int or not 0 < byte_count <= _TEXT_LIMIT:
            raise SparcError("invalid_schema", "byte_count must be a positive bounded integer")
        _require_digest(payload.get("sha256"))
    elif kind == "ack":
        _require_id(payload.get("message_id"), "message_id")
        _require_digest(payload.get("sha256"))
        if payload.get("status") != "verified":
            raise SparcError("invalid_schema", "Acknowledgment status is unsupported")
    else:
        _require_id(payload.get("ping_id"), "ping_id")

    if signed:
        decode_base64(payload.get("signature"), _SIGNATURE_BYTES)


def signing_projection(payload: dict) -> dict:
    """Return a fresh unsigned signing view of an application payload."""
    if not isinstance(payload, dict):
        raise SparcError("invalid_schema", "Application payload must be an object")
    projection = dict(payload)
    projection.pop("signature", None)
    if projection.get("kind") in ("chat", "benchmark"):
        projection.pop("text", None)
    return projection
