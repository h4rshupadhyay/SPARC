"""F1c lifecycle, migration continuity and opaque startup handoff contracts."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import threading

import pytest


def _identity_api():
    try:
        module = importlib.import_module("sparc.identity")
    except ModuleNotFoundError as error:
        if error.name == "sparc.identity":
            pytest.fail("the F1c identity lifecycle API must be implemented")
        raise
    required = (
        "inspect_identity",
        "load_identity",
        "_unlock_store",
        "_consume_unlocked_store",
        "IdentityCredentials",
        "IdentityUnlockRequest",
    )
    missing = [name for name in required if not hasattr(module, name)]
    assert not missing, f"identity lifecycle is missing its prescribed API: {missing}"
    return module


def _raise_code(code, call):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as raised:
        call()
    assert raised.value.code == code
    return raised.value


def _provider(identity_module, phrase=b"test phrase with enough entropy"):
    calls = []

    def provide(request):
        calls.append(request)
        confirmation = phrase if request.purpose in {"create", "migrate"} else None
        return identity_module.IdentityCredentials(phrase, confirmation)

    return provide, calls


def _watch_generation(identity_module, monkeypatch):
    generated = []
    key_type = identity_module.Ed25519PrivateKey
    real_generate = key_type.generate

    def generate(cls, *args, **kwargs):
        generated.append(True)
        return real_generate(*args, **kwargs)

    monkeypatch.setattr(key_type, "generate", classmethod(generate))
    return generated


def _other_identity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.models import Identity
    import hashlib

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def test_missing_provider_and_cancel_do_not_create(tmp_path):
    identity = _identity_api()
    absent_dir = tmp_path / "missing-provider"
    _raise_code(
        "identity_credentials_required",
        lambda: identity.load_identity(absent_dir),
    )
    assert not absent_dir.exists()

    canceled_dir = tmp_path / "canceled"
    provider, calls = _provider(identity)
    _raise_code(
        "identity_unlock_cancelled",
        lambda: identity.load_identity(
            canceled_dir, credential_provider=provider, cancelled=lambda: True
        ),
    )
    assert calls == []
    assert not canceled_dir.exists()


def test_migrate_preserves_key_trust_and_audit_bytes(
    tmp_path, legacy_identity_store, credential_provider, monkeypatch
):
    identity = _identity_api()
    from sparc.audit import AuditLog, verify_log
    from sparc.identity import TrustStore
    from sparc.models import Endpoint
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    data_dir = tmp_path / "continuity"
    old = legacy_identity_store(data_dir)
    trust = TrustStore(data_dir)
    peer = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust.pin(peer, Endpoint("127.0.0.1", 23911), "continuity peer")
    trust_path = data_dir / "trusted_peers.json"
    trust_before = trust_path.read_bytes()

    audit = AuditLog(data_dir, old)
    audit.append(
        "send_attempt",
        {
            "message_id": "a" * 32,
            "sha256": hashlib.sha256(b"a").hexdigest(),
            "byte_count": 1,
        },
    )
    audit.export_checkpoint(audit.checkpoint_path)
    audit_path = data_dir / "audit.jsonl"
    checkpoint_path = audit.checkpoint_path
    audit_before = audit_path.read_bytes()
    checkpoint_before = checkpoint_path.read_bytes()
    generated = _watch_generation(identity, monkeypatch)

    migrated = identity.load_identity(data_dir, credential_provider=credential_provider)
    assert migrated.public_bytes == old.public_bytes
    assert migrated.fingerprint == old.fingerprint
    assert migrated.private_key.sign(b"continuity") == old.private_key.sign(b"continuity")
    assert trust_path.read_bytes() == trust_before
    assert audit_path.read_bytes() == audit_before
    assert checkpoint_path.read_bytes() == checkpoint_before
    assert verify_log(audit_path, old.public_bytes, checkpoint_path).valid is True
    assert identity.inspect_identity(data_dir).private_key_verified is False
    assert generated == []


def test_v1_mismatch_rejected_before_prompt(
    tmp_path, legacy_identity_store, monkeypatch
):
    identity = _identity_api()
    data_dir = tmp_path / "mismatched-v1"
    old = legacy_identity_store(data_dir)
    path = data_dir / "identity.json"
    document = json.loads(path.read_bytes())
    document["public_key"] = base64.b64encode(_other_identity().public_bytes).decode("ascii")
    path.write_text(json.dumps(document), encoding="utf-8")
    original = path.read_bytes()
    provider, calls = _provider(identity)
    generated = _watch_generation(identity, monkeypatch)

    info = identity.inspect_identity(data_dir)
    assert info.private_key_verified is False
    _raise_code(
        "invalid_identity",
        lambda: identity.load_identity(data_dir, credential_provider=provider),
    )
    assert calls == []
    assert generated == []
    assert path.read_bytes() == original
    assert old.public_bytes != base64.b64decode(document["public_key"])


@pytest.mark.parametrize(
    "history_name",
    [
        "trusted_peers.json",
        "audit.jsonl",
        "audit-checkpoint.json",
        "simulation-checkpoint.json",
    ],
)
def test_history_without_identity_never_regenerates(tmp_path, history_name, monkeypatch):
    identity = _identity_api()
    data_dir = tmp_path / f"history-{history_name}"
    data_dir.mkdir()
    history = data_dir / history_name
    history.write_bytes(b"retained history bytes")
    provider, calls = _provider(identity)
    generated = _watch_generation(identity, monkeypatch)
    _raise_code(
        "identity_missing",
        lambda: identity.load_identity(data_dir, credential_provider=provider),
    )
    assert calls == []
    assert generated == []
    assert not (data_dir / "identity.json").exists()
    assert history.read_bytes() == b"retained history bytes"


def test_v2_wrong_password_and_corruption_preserve_file(
    tmp_path, credential_provider
):
    identity = _identity_api()
    data_dir = tmp_path / "encrypted"
    identity.load_identity(data_dir, credential_provider=credential_provider)
    path = data_dir / "identity.json"
    original = path.read_bytes()
    wrong_provider, _calls = _provider(identity, b"a different long wrong phrase")
    _raise_code(
        "identity_unlock_failed",
        lambda: identity.load_identity(data_dir, credential_provider=wrong_provider),
    )
    assert path.read_bytes() == original

    document = json.loads(original)
    token = document["encrypted_private_key"]
    changed = "A" if token[24] != "A" else "B"
    document["encrypted_private_key"] = token[:24] + changed + token[25:]
    path.write_text(json.dumps(document), encoding="utf-8")
    corrupted = path.read_bytes()
    _raise_code(
        "identity_unlock_failed",
        lambda: identity.load_identity(data_dir, credential_provider=credential_provider),
    )
    assert path.read_bytes() == corrupted

    path.write_bytes(original)
    identity.load_identity(data_dir, credential_provider=credential_provider)
    assert path.read_bytes() == original


def test_handle_issuer_snapshot_and_single_use(
    tmp_path, credential_provider
):
    identity = _identity_api()
    data_dir = tmp_path / "handle"
    original_identity = identity.load_identity(
        data_dir, credential_provider=credential_provider
    )
    handle = identity._unlock_store(
        data_dir, credential_provider=credential_provider
    )
    consumed_dir, consumed_identity = identity._consume_unlocked_store(handle)
    assert consumed_dir == data_dir.resolve()
    assert consumed_identity.public_bytes == original_identity.public_bytes
    _raise_code("invalid_identity", lambda: identity._consume_unlocked_store(handle))

    forged = object.__new__(type(handle))
    _raise_code("invalid_identity", lambda: identity._consume_unlocked_store(forged))

    snapshot_handle = identity._unlock_store(
        data_dir, credential_provider=credential_provider
    )
    path = data_dir / "identity.json"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    _raise_code("identity_changed", lambda: identity._consume_unlocked_store(snapshot_handle))
    path.write_bytes(original)


def test_direct_handle_construction_cannot_issue_arbitrary_identity(
    tmp_path, credential_provider
):
    identity = _identity_api()
    from sparc.models import SparcError

    data_dir = tmp_path / "direct-handle"
    identity.load_identity(data_dir, credential_provider=credential_provider)
    path = data_dir / "identity.json"
    snapshot = path.read_bytes()
    arbitrary_identity = _other_identity()
    try:
        forged = identity._UnlockedStore(
            data_dir.resolve(), path, snapshot, arbitrary_identity
        )
    except (TypeError, SparcError):
        return
    _raise_code("invalid_identity", lambda: identity._consume_unlocked_store(forged))


def test_concurrent_handle_consumption_succeeds_exactly_once(
    tmp_path, credential_provider, monkeypatch
):
    identity = _identity_api()
    from sparc.models import SparcError

    data_dir = tmp_path / "concurrent-handle"
    handle = identity._unlock_store(
        data_dir, credential_provider=credential_provider
    )
    barrier = threading.Barrier(2)
    per_thread = threading.local()

    def synchronize_first_check(_cancelled):
        if not getattr(per_thread, "synchronized", False):
            per_thread.synchronized = True
            barrier.wait(timeout=10)
        return None

    monkeypatch.setattr(identity, "_check_cancelled", synchronize_first_check)

    def consume():
        try:
            identity._consume_unlocked_store(handle)
            return "success"
        except SparcError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: consume(), range(2)))
    assert results.count("success") == 1
    assert results.count("invalid_identity") == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory-fd swap contract")
def test_handle_snapshot_read_stays_bound_to_locked_directory(
    tmp_path, credential_provider, monkeypatch
):
    identity = _identity_api()
    storage = importlib.import_module("sparc.identity_storage")
    data_dir = tmp_path / "store"
    replacement = tmp_path / "replacement"
    data_dir.mkdir()
    replacement.mkdir()
    identity.load_identity(data_dir, credential_provider=credential_provider)
    original = (data_dir / "identity.json").read_bytes()
    (replacement / "identity.json").write_bytes(original)
    handle = identity._unlock_store(
        data_dir, credential_provider=credential_provider
    )
    real_lock = storage.identity_lock
    held_name = tmp_path / "store-held"
    replacement_name = tmp_path / "replacement-held"

    @contextmanager
    def swap_after_lock(path, *, cancelled=None, _directory_fd=None):
        with real_lock(path, cancelled=cancelled, _directory_fd=_directory_fd):
            data_dir.rename(held_name)
            replacement.rename(data_dir)
            try:
                yield
            finally:
                data_dir.rename(replacement_name)
                held_name.rename(data_dir)
                replacement_name.rename(replacement)

    monkeypatch.setattr(storage, "identity_lock", swap_after_lock)
    from sparc.models import SparcError

    with pytest.raises(SparcError) as raised:
        identity._consume_unlocked_store(handle)
    assert raised.value.code in {"identity_changed", "data_permissions_failed"}
    assert (data_dir / "identity.json").read_bytes() == original


def test_literal_parent_component_is_rejected_before_credentials_or_storage(tmp_path):
    identity = _identity_api()
    parent = tmp_path / "parent"
    parent.mkdir()
    supplied = parent / ".." / "unsafe-store"
    normalized = tmp_path / "unsafe-store"
    calls = []

    def provider(request):
        calls.append(request)
        return identity.IdentityCredentials(b"a sufficiently long phrase", b"a sufficiently long phrase")

    _raise_code(
        "data_permissions_failed",
        lambda: identity.load_identity(supplied, credential_provider=provider),
    )
    assert calls == []
    assert not normalized.exists()


def test_migration_failure_injection_preserves_legacy_before_commit(
    tmp_path, legacy_identity_store, monkeypatch
):
    identity = _identity_api()
    codec = importlib.import_module("sparc.identity_codec")
    storage = importlib.import_module("sparc.identity_storage")
    data_dir = tmp_path / "migration-failure"
    legacy_identity_store(data_dir)
    path = data_dir / "identity.json"
    original = path.read_bytes()
    provider, _calls = _provider(identity)

    for target, name in (
        (codec, "encode_identity"),
        (codec, "decode_identity"),
        (storage, "publish_identity"),
    ):
        saved = getattr(target, name)

        def fail(*_args, **_kwargs):
            raise RuntimeError("injected migration stage failure")

        monkeypatch.setattr(target, name, fail)
        with pytest.raises(Exception):
            identity.load_identity(data_dir, credential_provider=provider)
        assert path.read_bytes() == original
        monkeypatch.setattr(target, name, saved)


def test_migration_commit_uncertain_keeps_published_ciphertext(
    tmp_path, legacy_identity_store, monkeypatch
):
    identity = _identity_api()
    storage = importlib.import_module("sparc.identity_storage")
    data_dir = tmp_path / "migration-commit-uncertain"
    legacy_identity_store(data_dir)
    path = data_dir / "identity.json"
    provider, _calls = _provider(identity)

    def fail_directory_sync(_directory):
        raise OSError("injected post-replace directory sync failure")

    monkeypatch.setattr(storage, "_sync_directory", fail_directory_sync)
    _raise_code(
        "identity_commit_uncertain",
        lambda: identity.load_identity(data_dir, credential_provider=provider),
    )
    committed = path.read_bytes()
    assert committed != b""
    assert identity.inspect_identity(data_dir).status == "encrypted_locked"


def test_cancellation_after_kdf_preserves_legacy_before_publication(
    tmp_path, legacy_identity_store, monkeypatch
):
    identity = _identity_api()
    codec = importlib.import_module("sparc.identity_codec")
    data_dir = tmp_path / "cancel-after-kdf"
    legacy_identity_store(data_dir)
    path = data_dir / "identity.json"
    original = path.read_bytes()
    provider, _calls = _provider(identity)
    cancelled = threading.Event()
    real_derive = codec._derive_key

    def derive_then_cancel(passphrase, salt):
        value = real_derive(passphrase, salt)
        cancelled.set()
        return value

    monkeypatch.setattr(codec, "_derive_key", derive_then_cancel)
    _raise_code(
        "identity_unlock_cancelled",
        lambda: identity.load_identity(
            data_dir, credential_provider=provider, cancelled=cancelled.is_set
        ),
    )
    assert path.read_bytes() == original


def test_cancellation_after_publication_keeps_encrypted_same_key(
    tmp_path, legacy_identity_store, monkeypatch
):
    identity = _identity_api()
    storage = importlib.import_module("sparc.identity_storage")
    data_dir = tmp_path / "cancel-after-publication"
    old = legacy_identity_store(data_dir)
    path = data_dir / "identity.json"
    provider, _calls = _provider(identity)
    cancelled = threading.Event()
    real_publish = storage.publish_identity

    def publish_then_cancel(*args, **kwargs):
        result = real_publish(*args, **kwargs)
        cancelled.set()
        return result

    monkeypatch.setattr(storage, "publish_identity", publish_then_cancel)
    _raise_code(
        "identity_unlock_cancelled",
        lambda: identity.load_identity(
            data_dir, credential_provider=provider, cancelled=cancelled.is_set
        ),
    )
    encrypted = path.read_bytes()
    assert identity.inspect_identity(data_dir).status == "encrypted_locked"
    monkeypatch.setattr(storage, "publish_identity", real_publish)
    unlocked = identity.load_identity(data_dir, credential_provider=provider)
    assert unlocked.private_key.sign(b"continuity") == old.private_key.sign(b"continuity")
    assert path.read_bytes() == encrypted
