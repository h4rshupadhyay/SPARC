"""Bounded verification for SPARC audit JSON-lines chains."""

import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import threading
import time
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit_format import (
    CHECKPOINT_BODY_FIELDS,
    CHECKPOINT_DOMAIN,
    CHECKPOINT_OUTER_FIELDS,
    AuditAppend,
    AuditReport,
    build_audit_record,
    verify_audit_record,
)
from .encoding import canonical, parse_object
from .models import SparcError
from .storage import _sync_parent_directory, atomic_write, secure_private_store


_LINE_LIMIT = 131072
_CHECKPOINT_LIMIT = 8192
_ZERO_HASH = "0" * 64
_LOCK_POLL_SECONDS = 0.1
_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_REASONS = {
    "invalid_schema": "audit record or checkpoint schema is invalid",
    "invalid_base64": "audit signature encoding is invalid",
    "invalid_json": "audit JSON syntax or values are invalid",
    "invalid_json_value": "audit JSON contains unsupported values",
    "duplicate_json_key": "audit JSON contains duplicate keys",
    "audit_hash_mismatch": "audit record hash does not match its body",
    "audit_signature_failed": "audit signature does not verify",
    "audit_chain_mismatch": "audit record or checkpoint does not match the expected chain",
    "peer_evidence_failed": "retained peer evidence does not verify",
}


def _reason(code: str, detail: str | None = None) -> str:
    return f"{code}: {detail or _SAFE_REASONS.get(code, 'audit verification failed')}"


def _check_cancelled(cancelled) -> None:
    if cancelled is not None and cancelled():
        raise SparcError("operation_cancelled", "Audit operation was cancelled")


@contextmanager
def _cancelable_lock(lock: threading.Lock, cancelled):
    acquired = False
    try:
        while not acquired:
            _check_cancelled(cancelled)
            acquired = lock.acquire(timeout=_LOCK_POLL_SECONDS)
        _check_cancelled(cancelled)
        yield
    finally:
        if acquired:
            lock.release()


def _report(
    started: int,
    *,
    valid: bool,
    verified_records: int,
    first_failed_record: int | None,
    reason: str,
    checkpoint_checked: bool,
) -> AuditReport:
    return AuditReport(
        valid=valid,
        verified_records=verified_records,
        first_failed_record=first_failed_record,
        reason=reason,
        checkpoint_checked=checkpoint_checked,
        elapsed_ns=max(0, time.perf_counter_ns() - started),
    )


def _fail_report(
    started: int,
    code: str,
    *,
    verified_records: int = 0,
    first_failed_record: int | None = None,
    checkpoint_checked: bool = False,
    detail: str | None = None,
) -> AuditReport:
    return _report(
        started,
        valid=False,
        verified_records=verified_records,
        first_failed_record=first_failed_record,
        reason=_reason(code, detail),
        checkpoint_checked=checkpoint_checked,
    )


def _object_depth(raw: bytes, maximum: int) -> None:
    """Count JSON object nesting without mistaking quoted braces for structure."""
    depth = 0
    in_string = False
    escaped = False
    for value in raw:
        if in_string:
            if escaped:
                escaped = False
            elif value == 0x5C:
                escaped = True
            elif value == 0x22:
                in_string = False
            continue
        if value == 0x22:
            in_string = True
        elif value == 0x7B:
            depth += 1
            if depth > maximum:
                raise SparcError("invalid_schema", "JSON object nesting exceeds its bound")
        elif value == 0x7D and depth:
            depth -= 1


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise SparcError("invalid_base64", "Checkpoint signature is not canonical Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise SparcError("invalid_base64", "Checkpoint signature is not canonical Base64") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise SparcError("invalid_base64", "Checkpoint signature has an invalid encoding")
    return decoded


def _validate_checkpoint(path: Path, public_key: bytes) -> dict:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_CHECKPOINT_LIMIT + 1)
            if len(raw) > _CHECKPOINT_LIMIT or stream.read(1):
                raise SparcError("invalid_schema", "Checkpoint exceeds its size bound")
    except OSError as exc:
        raise SparcError("invalid_schema", "Checkpoint is unavailable") from exc
    _object_depth(raw, 2)
    checkpoint = parse_object(raw)
    if checkpoint.keys() != CHECKPOINT_OUTER_FIELDS:
        raise SparcError("invalid_schema", "Checkpoint outer fields are invalid")
    body = checkpoint.get("body")
    if not isinstance(body, dict) or body.keys() != CHECKPOINT_BODY_FIELDS:
        raise SparcError("invalid_schema", "Checkpoint body fields are invalid")
    log_id = body.get("log_id")
    last_number = body.get("last_record_number")
    last_hash = body.get("last_record_hash")
    fingerprint = body.get("identity_fingerprint")
    if not isinstance(log_id, str) or _ID_RE.fullmatch(log_id) is None:
        raise SparcError("invalid_schema", "Checkpoint log_id is invalid")
    if type(last_number) is not int or last_number < 0:
        raise SparcError("invalid_schema", "Checkpoint record number is invalid")
    if not isinstance(last_hash, str) or _HEX64_RE.fullmatch(last_hash) is None:
        raise SparcError("invalid_schema", "Checkpoint record hash is invalid")
    if not isinstance(fingerprint, str) or _HEX64_RE.fullmatch(fingerprint) is None:
        raise SparcError("invalid_schema", "Checkpoint identity fingerprint is invalid")
    if last_number == 0 and last_hash != _ZERO_HASH:
        raise SparcError("invalid_schema", "Empty checkpoint must use the zero hash")
    trusted_fingerprint = hashlib.sha256(public_key).hexdigest()
    if fingerprint != trusted_fingerprint:
        raise SparcError("audit_chain_mismatch", "Checkpoint owner does not match trusted identity")
    signature = _decode_signature(checkpoint.get("signature"))
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, CHECKPOINT_DOMAIN + canonical(body)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SparcError("audit_signature_failed", "Checkpoint signature does not verify") from exc
    return body


def _verify_log_impl(
    path: Path,
    public_key: bytes,
    checkpoint: Path | None = None,
    *,
    cancelled=None,
    _prefix_bytes: int | None = None,
    _expected_head: tuple[str, int, str] | None = None,
) -> AuditReport:
    """Stream and verify an available audit chain and optional signed prefix anchor."""
    started = time.perf_counter_ns()
    _check_cancelled(cancelled)
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return _fail_report(started, "invalid_schema", detail="trusted public key is invalid")

    checkpoint_body = None
    if checkpoint is not None:
        try:
            checkpoint_body = _validate_checkpoint(Path(checkpoint), public_key)
        except SparcError as exc:
            return _fail_report(started, exc.code)
        except (OSError, TypeError, ValueError):
            return _fail_report(started, "invalid_schema", detail="checkpoint is unavailable")
        _check_cancelled(cancelled)

    verified = 0
    physical_line = 0
    previous_hash = _ZERO_HASH
    expected_log_id = None
    checkpoint_checked = False
    checkpoint_number = checkpoint_body["last_record_number"] if checkpoint_body is not None else None
    bytes_read = 0
    try:
        with Path(path).open("rb", buffering=0) as stream:
            if _prefix_bytes is not None and os.fstat(stream.fileno()).st_size < _prefix_bytes:
                return _fail_report(
                    started, "audit_verification_failed",
                    detail="captured audit prefix was truncated",
                )
            while True:
                _check_cancelled(cancelled)
                if _prefix_bytes is not None:
                    remaining = _prefix_bytes - bytes_read
                    if remaining <= 0:
                        break
                    raw_line = stream.readline(min(_LINE_LIMIT + 1, remaining))
                else:
                    raw_line = stream.readline(_LINE_LIMIT + 1)
                _check_cancelled(cancelled)
                if not raw_line:
                    if _prefix_bytes is not None and bytes_read < _prefix_bytes:
                        return _fail_report(
                            started, "audit_verification_failed", verified_records=verified,
                            detail="captured audit prefix ended before its committed boundary",
                        )
                    break
                bytes_read += len(raw_line)
                physical_line += 1
                if len(raw_line) > _LINE_LIMIT:
                    return _fail_report(
                        started, "invalid_schema", verified_records=verified,
                        first_failed_record=physical_line, checkpoint_checked=checkpoint_checked,
                        detail="audit record line exceeds its size bound",
                    )
                if not raw_line.endswith(b"\n"):
                    return _fail_report(
                        started, "invalid_json", verified_records=verified,
                        first_failed_record=physical_line, checkpoint_checked=checkpoint_checked,
                        detail="audit record line is not LF terminated",
                    )
                raw = raw_line[:-1]
                if not raw:
                    return _fail_report(
                        started, "invalid_json", verified_records=verified,
                        first_failed_record=physical_line, checkpoint_checked=checkpoint_checked,
                        detail="audit log contains a blank line",
                    )
                _check_cancelled(cancelled)
                try:
                    _object_depth(raw, 5)
                    record = parse_object(raw)
                    body = record.get("body") if isinstance(record, dict) else None
                    if expected_log_id is None:
                        expected_log_id = body.get("log_id") if isinstance(body, dict) else "0" * 32
                    verify_audit_record(
                        record,
                        public_key,
                        previous_hash,
                        verified + 1,
                        expected_log_id,
                    )
                except SparcError as exc:
                    _check_cancelled(cancelled)
                    return _fail_report(
                        started, exc.code, verified_records=verified,
                        first_failed_record=physical_line,
                        checkpoint_checked=checkpoint_checked,
                    )

                if checkpoint_body is not None:
                    if expected_log_id != checkpoint_body["log_id"]:
                        return _fail_report(
                            started, "audit_chain_mismatch", verified_records=verified,
                            checkpoint_checked=False,
                            detail="checkpoint log_id does not match the audit chain",
                        )
                    if checkpoint_number == verified + 1:
                        if record["record_hash"] != checkpoint_body["last_record_hash"]:
                            return _fail_report(
                                started,
                                "audit_chain_mismatch",
                                verified_records=verified,
                                checkpoint_checked=False,
                                detail="checkpoint hash does not match its numbered chain prefix",
                            )
                        checkpoint_checked = True
                    elif checkpoint_number == 0 and verified == 0:
                        checkpoint_checked = True

                previous_hash = record["record_hash"]
                verified += 1
                _check_cancelled(cancelled)

    except FileNotFoundError:
        return _fail_report(
            started, "audit_verification_failed", detail="audit log is missing"
        )
    except (OSError, TypeError, ValueError):
        return _fail_report(
            started,
            "audit_verification_failed",
            verified_records=verified,
            checkpoint_checked=checkpoint_checked,
            detail="audit log is unreadable",
        )

    _check_cancelled(cancelled)
    if _expected_head is not None:
        captured_log_id, expected_number, expected_hash = _expected_head
        if checkpoint_body is not None and checkpoint_body["log_id"] != captured_log_id:
            return _fail_report(
                started, "audit_chain_mismatch", verified_records=verified,
                checkpoint_checked=False,
                detail="checkpoint log_id does not match the captured audit log",
            )
        if (
            verified != expected_number
            or previous_hash != expected_hash
            or (verified > 0 and expected_log_id != captured_log_id)
        ):
            return _fail_report(
                started, "audit_chain_mismatch", verified_records=verified,
                checkpoint_checked=checkpoint_checked,
                detail="verified prefix does not match the captured committed head",
            )

    if checkpoint_body is not None:
        if checkpoint_number > verified:
            return _fail_report(
                started,
                "audit_chain_mismatch",
                verified_records=verified,
                detail="checkpoint is beyond the available audit tail",
            )
        if checkpoint_number == 0:
            if verified == 0:
                checkpoint_checked = True
            elif not checkpoint_checked:
                return _fail_report(
                    started,
                    "audit_chain_mismatch",
                    verified_records=verified,
                    detail="zero-head checkpoint does not match the audit log_id",
                )
        elif not checkpoint_checked:
            return _fail_report(
                started,
                "audit_chain_mismatch",
                verified_records=verified,
                detail="checkpoint prefix was not matched",
            )
    elif verified:
        return _report(
            started,
            valid=True,
            verified_records=verified,
            first_failed_record=None,
            reason="available chain only; deletion of the log tail cannot be disproved",
            checkpoint_checked=False,
        )
    else:
        return _report(
            started,
            valid=True,
            verified_records=0,
            first_failed_record=None,
            reason="available empty chain only; log_id and prior deletion cannot be disproved",
            checkpoint_checked=False,
        )

    return _report(
        started,
        valid=True,
        verified_records=verified,
        first_failed_record=None,
        reason="checkpoint verified against the audit chain prefix",
        checkpoint_checked=checkpoint_checked,
    )


class AuditLog:
    """Fail-closed durable writer for one local identity's audit chain."""

    def __init__(self, data_dir: Path, identity) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "audit.jsonl"
        self.checkpoint_path = self.data_dir / "audit-checkpoint.json"
        self.identity = identity
        self._lock = threading.Lock()
        self._poisoned = False
        self._record_number = 0
        self._head_hash = _ZERO_HASH
        self._log_id = None
        self._committed_bytes = 0

        try:
            secure_private_store(self.path)
            if self.path.exists():
                checkpoint_exists = self.checkpoint_path.exists()
                report = verify_log(
                    self.path,
                    identity.public_bytes,
                    self.checkpoint_path if checkpoint_exists else None,
                )
                if not report.valid:
                    raise SparcError(
                        "audit_verification_failed",
                        f"Existing audit chain failed verification: {report.reason}",
                    )
                if report.verified_records == 0 and not checkpoint_exists:
                    raise SparcError(
                        "audit_verification_failed",
                        "Existing empty audit log has no signed zero-head checkpoint",
                    )
                self._record_number, self._head_hash, self._log_id = self._read_head()
                self._committed_bytes = self.path.stat().st_size
                if self._record_number == 0:
                    with self.checkpoint_path.open("rb") as stream:
                        raw_checkpoint = stream.read(_CHECKPOINT_LIMIT + 1)
                    if len(raw_checkpoint) > _CHECKPOINT_LIMIT:
                        raise SparcError(
                            "audit_verification_failed",
                            "Verified checkpoint changed during startup",
                        )
                    checkpoint = parse_object(raw_checkpoint)
                    self._log_id = checkpoint["body"]["log_id"]
                return

            if self.checkpoint_path.exists():
                report = verify_log(self.path, identity.public_bytes, self.checkpoint_path)
                raise SparcError(
                    "audit_verification_failed",
                    f"Existing audit checkpoint has no expected log: {report.reason}",
                )

            self._log_id = secrets.token_hex(16)
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            _sync_parent_directory(self.path.parent)
            self._committed_bytes = 0
        except SparcError as exc:
            if exc.code == "audit_verification_failed":
                raise
            raise SparcError("audit_storage_failed", "Could not secure or initialize the audit store") from exc
        except OSError as exc:
            raise SparcError("audit_storage_failed", "Could not durably initialize the audit log") from exc

    def _read_head(self) -> tuple[int, str, str | None]:
        last_record = None
        try:
            with self.path.open("rb") as stream:
                while True:
                    line = stream.readline(_LINE_LIMIT + 1)
                    if not line:
                        break
                    if len(line) > _LINE_LIMIT or not line.endswith(b"\n"):
                        raise SparcError("audit_verification_failed", "Verified log changed during startup")
                    last_record = parse_object(line[:-1])
        except SparcError:
            raise
        except (OSError, ValueError) as exc:
            raise SparcError("audit_storage_failed", "Could not read the verified audit head") from exc
        if last_record is None:
            return 0, _ZERO_HASH, None
        body = last_record["body"]
        return body["record_number"], last_record["record_hash"], body["log_id"]

    def head_snapshot(self, *, cancelled=None) -> dict:
        """Return a copied public view of the durably committed writer head."""
        with _cancelable_lock(self._lock, cancelled):
            return {
                "log_id": self._log_id,
                "last_record_number": self._record_number,
                "last_record_hash": self._head_hash,
                "identity_fingerprint": self.identity.fingerprint,
            }

    def verify(self, checkpoint: Path | None = None, *, cancelled=None) -> AuditReport:
        """Verify the committed prefix captured under the append lock."""
        with _cancelable_lock(self._lock, cancelled):
            prefix_bytes = self._committed_bytes
            expected_head = (self._log_id, self._record_number, self._head_hash)
        return verify_log(
            self.path,
            self.identity.public_bytes,
            checkpoint,
            cancelled=cancelled,
            _prefix_bytes=prefix_bytes,
            _expected_head=expected_head,
        )

    def append(self, kind: str, metadata: dict) -> AuditAppend:
        """Validate, sign, append and fsync one record before advancing the head."""
        with self._lock:
            if self._poisoned:
                raise SparcError("audit_storage_failed", "Audit log is poisoned after a storage failure")
            started = time.perf_counter_ns()
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            body = {
                "log_id": self._log_id,
                "record_number": self._record_number + 1,
                "timestamp": timestamp,
                "event": kind,
                "identity_fingerprint": self.identity.fingerprint,
                "metadata": deepcopy(metadata),
                "previous_hash": self._head_hash,
            }
            record = build_audit_record(self.identity, body)
            line = canonical(record) + b"\n"
            try:
                with self.path.open("ab") as stream:
                    written = stream.write(line)
                    if written != len(line):
                        raise OSError("short audit append")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                self._poisoned = True
                raise SparcError("audit_storage_failed", "Audit append could not be durably stored") from exc
            elapsed = max(0, time.perf_counter_ns() - started)
            self._record_number = body["record_number"]
            self._head_hash = record["record_hash"]
            self._committed_bytes += len(line)
            return AuditAppend(record=record, elapsed_ns=elapsed, encoded_bytes=len(line))

    def export_checkpoint(self, path: Path, *, cancelled=None) -> None:
        """Sign and durably publish the current head as retained and selected copies."""
        with _cancelable_lock(self._lock, cancelled):
            if self._poisoned:
                raise SparcError("audit_storage_failed", "Audit log is poisoned after a storage failure")
            try:
                selected_input = Path(path)
                selected = selected_input.resolve()
                retained = self.checkpoint_path.absolute()
                retained_resolved = self.checkpoint_path.resolve()
                protected = {
                    (self.data_dir / name).resolve()
                    for name in ("audit.jsonl", "identity.json", "trusted_peers.json")
                }
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise SparcError("invalid_schema", "Selected checkpoint path is invalid") from exc
            if selected in protected or retained_resolved in protected:
                raise SparcError(
                    "invalid_schema",
                    "Checkpoint path aliases a protected SPARC data file",
                )
            same_retained = selected == retained_resolved or selected_input.absolute() == retained
            if selected.exists() and selected.is_dir():
                raise SparcError("invalid_schema", "Selected checkpoint path must name a file")
            if selected.parent.exists() and not selected.parent.is_dir():
                raise SparcError("invalid_schema", "Selected checkpoint parent must be a directory")

            body = {
                "log_id": self._log_id,
                "last_record_number": self._record_number,
                "last_record_hash": self._head_hash,
                "identity_fingerprint": self.identity.fingerprint,
            }
            _check_cancelled(cancelled)
            try:
                signature = self.identity.private_key.sign(CHECKPOINT_DOMAIN + canonical(body))
            except Exception as exc:
                self._poisoned = True
                raise SparcError("audit_storage_failed", "Checkpoint could not be signed") from exc
            encoded = canonical(
                {"body": body, "signature": base64.b64encode(signature).decode("ascii")}
            )

            try:
                _check_cancelled(cancelled)
                atomic_write(retained, encoded, private=True, secure_parent=True)
                if not same_retained:
                    _check_cancelled(cancelled)
                    atomic_write(selected, encoded, private=True, secure_parent=False)
            except SparcError as exc:
                if exc.code == "operation_cancelled":
                    raise
                self._poisoned = True
                raise SparcError(
                    "audit_storage_failed",
                    "Checkpoint publication failed; the audit log is poisoned",
                ) from exc
            except OSError as exc:
                self._poisoned = True
                raise SparcError(
                    "audit_storage_failed",
                    "Checkpoint publication failed; the audit log is poisoned",
                ) from exc
            _check_cancelled(cancelled)


def verify_log(
    path: Path,
    public_key: bytes,
    checkpoint: Path | None = None,
    *,
    cancelled=None,
    _prefix_bytes: int | None = None,
    _expected_head: tuple[str, int, str] | None = None,
) -> AuditReport:
    """Verify a chain and give cancellation precedence over every report path."""
    try:
        report = _verify_log_impl(
            path,
            public_key,
            checkpoint,
            cancelled=cancelled,
            _prefix_bytes=_prefix_bytes,
            _expected_head=_expected_head,
        )
    except SparcError as exc:
        if exc.code != "operation_cancelled":
            _check_cancelled(cancelled)
        raise
    _check_cancelled(cancelled)
    return report


__all__ = ["AuditAppend", "AuditLog", "AuditReport", "verify_log"]
