"""Signed checkpoint export, rollback and publication-boundary tests."""

import base64
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


CHECKPOINT_DOMAIN = b"SPARC-v1 checkpoint\x00"
LOG_ID = "0123456789abcdef0123456789abcdef"
ZERO_HASH = "0" * 64


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


def _metadata(number):
    return {
        "message_id": f"{number:032x}",
        "sha256": hashlib.sha256(f"message {number}".encode()).hexdigest(),
        "byte_count": 9,
    }


def _append(audit, count):
    results = []
    for number in range(1, count + 1):
        results.append(audit.append("send_attempt", _metadata(number)))
    return results


def _signed_checkpoint(identity, *, number=1, record_hash=ZERO_HASH, log_id=LOG_ID, owner=None):
    body = {
        "log_id": log_id,
        "last_record_number": number,
        "last_record_hash": record_hash,
        "identity_fingerprint": owner or identity.fingerprint,
    }
    signature = identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(body))
    return {"body": body, "signature": base64.b64encode(signature).decode("ascii")}


def _write_signed_checkpoint(path, identity, **kwargs):
    checkpoint = _signed_checkpoint(identity, **kwargs)
    path.write_bytes(_canonical(checkpoint))
    return checkpoint


def _load_checkpoint(path):
    return json.loads(path.read_bytes())


def _assert_checkpoint_number(path, expected_number):
    checkpoint = _load_checkpoint(path)
    assert checkpoint["body"]["last_record_number"] == expected_number


def _prepare_two_record_log(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    first = audit.append("send_attempt", _metadata(1))
    external = tmp_path / "selected-checkpoint.json"
    audit.export_checkpoint(external)
    old_retained = (tmp_path / "audit-checkpoint.json").read_bytes()
    old_external = external.read_bytes()
    second = audit.append("send_attempt", _metadata(2))
    return identity, audit, external, first, second, old_retained, old_external


def test_export_checkpoint_signs_exact_schema_and_publishes_retained_and_selected(tmp_path):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    result = audit.append("send_attempt", _metadata(1))
    selected = tmp_path / "exports" / "checkpoint.json"

    assert audit.export_checkpoint(selected) is None

    retained = tmp_path / "audit-checkpoint.json"
    retained_bytes = retained.read_bytes()
    selected_bytes = selected.read_bytes()
    checkpoint = json.loads(retained_bytes)
    assert retained_bytes == selected_bytes
    assert set(checkpoint) == {"body", "signature"}
    assert set(checkpoint["body"]) == {
        "log_id", "last_record_number", "last_record_hash", "identity_fingerprint"
    }
    assert checkpoint["body"] == {
        "log_id": result.record["body"]["log_id"],
        "last_record_number": 1,
        "last_record_hash": result.record["record_hash"],
        "identity_fingerprint": identity.fingerprint,
    }
    signature = base64.b64decode(checkpoint["signature"], validate=True)
    identity.private_key.public_key().verify(
        signature, CHECKPOINT_DOMAIN + _canonical(checkpoint["body"])
    )
    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, selected)
    assert report.valid and report.checkpoint_checked


def test_zero_head_checkpoint_retains_log_id_across_restart(tmp_path):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    log_id = audit._log_id
    selected = tmp_path / "zero-head.json"
    audit.export_checkpoint(selected)
    checkpoint = _load_checkpoint(selected)
    assert checkpoint["body"]["last_record_number"] == 0
    assert checkpoint["body"]["last_record_hash"] == ZERO_HASH
    assert checkpoint["body"]["log_id"] == log_id
    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, selected)
    assert report.valid and report.checkpoint_checked

    restarted = AuditLog(tmp_path, identity)
    appended = restarted.append("send_attempt", _metadata(1))
    assert appended.record["body"]["log_id"] == log_id
    assert appended.record["body"]["record_number"] == 1


def test_older_checkpoint_anchors_prefix_while_later_records_verify(tmp_path):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    first = audit.append("send_attempt", _metadata(1))
    older = tmp_path / "older-checkpoint.json"
    audit.export_checkpoint(older)
    second = audit.append("send_attempt", _metadata(2))
    third = audit.append("send_attempt", _metadata(3))
    checkpoint = _load_checkpoint(older)
    assert checkpoint["body"]["last_record_hash"] == first.record["record_hash"]
    assert second.record["body"]["previous_hash"] == first.record["record_hash"]
    assert third.record["body"]["previous_hash"] == second.record["record_hash"]
    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, older)
    assert report.valid and report.verified_records == 3 and report.checkpoint_checked


def test_tail_removal_fails_against_independent_checkpoint(tmp_path):
    from sparc.audit import verify_log

    identity, audit, external, _first, _second, *_ = _prepare_two_record_log(tmp_path)
    audit.export_checkpoint(external)
    assert _load_checkpoint(external)["body"]["last_record_number"] == 2
    log_path = tmp_path / "audit.jsonl"
    log_path.write_bytes(log_path.read_bytes().splitlines(keepends=True)[0])
    report = verify_log(log_path, identity.public_bytes, external)
    assert not report.valid
    assert report.first_failed_record is None
    assert "audit_chain_mismatch" in report.reason
    assert report.verified_records == 1


def test_unanchored_tail_removal_is_available_chain_only(tmp_path):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    _append(audit, 2)
    log_path = tmp_path / "audit.jsonl"
    log_path.write_bytes(log_path.read_bytes().splitlines(keepends=True)[0])
    report = verify_log(log_path, identity.public_bytes)
    assert report.valid
    assert report.verified_records == 1
    assert "available" in report.reason.lower()


@pytest.mark.parametrize(
    "mutation,expected_code",
    [
        ("signature", "audit_signature_failed"),
        ("owner", "audit_chain_mismatch"),
        ("log_id", "audit_chain_mismatch"),
        ("hash", "audit_chain_mismatch"),
    ],
    ids=["signature", "owner", "log-id", "prefix-hash"],
)
def test_checkpoint_signature_owner_log_id_and_hash_mismatch_fail(tmp_path, mutation, expected_code):
    from sparc.audit import AuditLog, verify_log

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    appended = audit.append("send_attempt", _metadata(1))
    checkpoint_path = tmp_path / "candidate-checkpoint.json"
    audit.export_checkpoint(checkpoint_path)
    checkpoint = _load_checkpoint(checkpoint_path)
    if mutation == "signature":
        checkpoint["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    elif mutation == "owner":
        checkpoint["body"]["identity_fingerprint"] = "b" * 64
        checkpoint["signature"] = base64.b64encode(
            identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(checkpoint["body"]))
        ).decode("ascii")
    elif mutation == "log_id":
        checkpoint["body"]["log_id"] = "f" * 32
        checkpoint["signature"] = base64.b64encode(
            identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(checkpoint["body"]))
        ).decode("ascii")
    else:
        checkpoint["body"]["last_record_hash"] = "f" * 64
        checkpoint["signature"] = base64.b64encode(
            identity.private_key.sign(CHECKPOINT_DOMAIN + _canonical(checkpoint["body"]))
        ).decode("ascii")
    checkpoint_path.write_bytes(_canonical(checkpoint))

    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, checkpoint_path)
    assert not report.valid
    assert report.first_failed_record is None
    assert expected_code in report.reason


def test_checkpoint_with_missing_log_fails(tmp_path):
    from sparc.audit import verify_log

    identity = _identity()
    checkpoint = tmp_path / "checkpoint.json"
    _write_signed_checkpoint(checkpoint, identity, number=0, record_hash=ZERO_HASH)
    report = verify_log(tmp_path / "missing-audit.jsonl", identity.public_bytes, checkpoint)
    assert not report.valid
    assert report.first_failed_record is None
    assert not report.checkpoint_checked


@pytest.mark.parametrize("protected_name", ["identity.json", "trusted_peers.json", "audit.jsonl"])
def test_protected_checkpoint_destination_rejected_before_publication(tmp_path, protected_name):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    audit.append("send_attempt", _metadata(1))
    protected = tmp_path / protected_name
    if protected_name != "audit.jsonl":
        protected.write_bytes(b"existing protected bytes")
    original_log = (tmp_path / "audit.jsonl").read_bytes()
    with pytest.raises(SparcError):
        audit.export_checkpoint(protected)
    assert protected.read_bytes() == (original_log if protected_name == "audit.jsonl" else b"existing protected bytes")
    assert not (tmp_path / "audit-checkpoint.json").exists()


@pytest.mark.parametrize(
    "protected_name",
    ["identity.json", "trusted_peers.json", "audit.jsonl"],
    ids=["identity-alias", "trust-alias", "audit-log-alias"],
)
def test_symlink_alias_to_protected_destination_is_rejected(tmp_path, protected_name):
    from sparc.audit import AuditLog
    from sparc.models import SparcError

    identity = _identity()
    audit = AuditLog(tmp_path, identity)
    audit.append("send_attempt", _metadata(1))
    protected = tmp_path / protected_name
    if protected_name != "audit.jsonl":
        protected.write_bytes(b"protected")
    before = protected.read_bytes()
    alias = tmp_path / "external-checkpoint.json"
    alias.symlink_to(protected)
    with pytest.raises(SparcError):
        audit.export_checkpoint(alias)
    assert protected.read_bytes() == before
    assert not (tmp_path / "audit-checkpoint.json").exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux parent modes are platform-specific")
def test_external_export_preserves_selected_parent_and_uses_private_file_mode(tmp_path):
    from sparc.audit import AuditLog

    identity = _identity()
    audit = AuditLog(tmp_path / "store", identity)
    audit.append("send_attempt", _metadata(1))
    parent = tmp_path / "selected" / "existing"
    parent.mkdir(parents=True, mode=0o750)
    os.chmod(parent, 0o750)
    selected = parent / "checkpoint.json"

    audit.export_checkpoint(selected)

    assert parent.stat().st_mode & 0o777 == 0o750
    assert selected.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "destination_kind,stage",
    [
        ("retained", "before"),
        ("retained", "after"),
        ("external", "before"),
        ("external", "after"),
    ],
    ids=["retained-pre-replace", "retained-post-replace", "external-pre-replace", "external-post-replace"],
)
def test_publication_replace_failures_poison_without_rollback(
    tmp_path, monkeypatch, destination_kind, stage
):
    import sparc.storage as storage
    from sparc.audit import AuditLog, verify_log
    from sparc.models import SparcError

    identity, audit, external, _first, _second, old_retained, old_external = _prepare_two_record_log(tmp_path)
    retained = tmp_path / "audit-checkpoint.json"
    target = retained if destination_kind == "retained" else external
    original_replace = storage.os.replace

    def faulty_replace(source, destination):
        if Path(destination) == target:
            if stage == "before":
                raise OSError("injected pre-replace failure")
            original_replace(source, destination)
            raise OSError("injected post-replace failure")
        return original_replace(source, destination)

    monkeypatch.setattr(storage.os, "replace", faulty_replace)
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(external)
    assert raised.value.code == "audit_storage_failed"

    retained_now = retained.read_bytes()
    external_now = external.read_bytes()
    if destination_kind == "retained":
        if stage == "before":
            assert retained_now == old_retained
            _assert_checkpoint_number(retained, 1)
        else:
            assert retained_now != old_retained
            _assert_checkpoint_number(retained, 2)
        assert external_now == old_external
        _assert_checkpoint_number(external, 1)
    else:
        assert retained_now != old_retained
        _assert_checkpoint_number(retained, 2)
        if stage == "before":
            assert external_now == old_external
            _assert_checkpoint_number(external, 1)
        else:
            assert external_now != old_external
            _assert_checkpoint_number(external, 2)
    anchored = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, retained)
    assert anchored.valid and anchored.checkpoint_checked
    with pytest.raises(SparcError) as poisoned_append:
        audit.append("send_attempt", _metadata(3))
    assert poisoned_append.value.code == "audit_storage_failed"
    with pytest.raises(SparcError) as poisoned_export:
        audit.export_checkpoint(external)
    assert poisoned_export.value.code == "audit_storage_failed"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux temporary descriptor paths are used")
@pytest.mark.parametrize("destination_kind", ["retained", "external"], ids=["retained-fsync", "external-fsync"])
def test_publication_fsync_failure_preserves_retained_anchor_and_poisons(tmp_path, monkeypatch, destination_kind):
    import sparc.storage as storage
    from sparc.audit import AuditLog, verify_log
    from sparc.models import SparcError

    identity, audit, external, _first, _second, old_retained, old_external = _prepare_two_record_log(tmp_path)
    retained = tmp_path / "audit-checkpoint.json"
    target = retained if destination_kind == "retained" else external
    original_fsync = storage.os.fsync
    injected = []

    def faulty_fsync(fd):
        descriptor_path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        is_target_temp = (
            descriptor_path.parent == target.parent
            and descriptor_path.name.startswith(f".{target.name}.")
            and descriptor_path.name.endswith(".tmp")
        )
        if is_target_temp and not injected:
            injected.append(True)
            raise OSError("injected checkpoint fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(storage.os, "fsync", faulty_fsync)
    with pytest.raises(SparcError) as raised:
        audit.export_checkpoint(external)
    assert raised.value.code == "audit_storage_failed"
    assert injected
    if destination_kind == "retained":
        assert retained.read_bytes() == old_retained
        assert external.read_bytes() == old_external
        _assert_checkpoint_number(retained, 1)
        _assert_checkpoint_number(external, 1)
    else:
        assert retained.read_bytes() != old_retained
        assert external.read_bytes() == old_external
        _assert_checkpoint_number(retained, 2)
        _assert_checkpoint_number(external, 1)
    report = verify_log(tmp_path / "audit.jsonl", identity.public_bytes, retained)
    assert report.valid and report.checkpoint_checked
    with pytest.raises(SparcError) as poisoned:
        audit.append("send_attempt", _metadata(3))
    assert poisoned.value.code == "audit_storage_failed"
    with pytest.raises(SparcError) as poisoned_export:
        audit.export_checkpoint(external)
    assert poisoned_export.value.code == "audit_storage_failed"
