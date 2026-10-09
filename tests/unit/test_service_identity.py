"""F1d service startup credential and unlocked-handoff contracts."""

from __future__ import annotations

import importlib
import inspect
import socket
import threading

import pytest


def _service_api():
    try:
        module = importlib.import_module("sparc.peer.service")
    except ModuleNotFoundError as error:
        if error.name == "sparc.peer.service":
            pytest.fail("PeerService startup identity API must be implemented")
        raise
    constructor = inspect.signature(module.PeerService.__init__).parameters
    assert "credential_provider" in constructor, "PeerService must accept explicit credentials"
    assert "cancelled" in constructor, "PeerService must accept startup cancellation"
    assert constructor["credential_provider"].kind is inspect.Parameter.KEYWORD_ONLY
    assert constructor["cancelled"].kind is inspect.Parameter.KEYWORD_ONLY
    factory = getattr(module.PeerService, "_from_unlocked_store", None)
    assert callable(factory), "PeerService must consume an unlocked identity handle"
    factory_parameters = inspect.signature(factory).parameters
    assert {"handle", "limits", "cancelled"} <= factory_parameters.keys()
    assert callable(getattr(module.PeerService, "_initialize", None))
    return module


def _watch_preinitialization(module, monkeypatch):
    calls = []
    real_trust = module.TrustStore
    real_audit = module.AuditLog
    real_socket = socket.socket
    real_start = threading.Thread.start

    def trust(*args, **kwargs):
        calls.append("trust")
        return real_trust(*args, **kwargs)

    def audit(*args, **kwargs):
        calls.append("audit")
        return real_audit(*args, **kwargs)

    def create_socket(*args, **kwargs):
        calls.append("socket")
        return real_socket(*args, **kwargs)

    def start_thread(thread, *args, **kwargs):
        calls.append("thread")
        return real_start(thread, *args, **kwargs)

    monkeypatch.setattr(module, "TrustStore", trust)
    monkeypatch.setattr(module, "AuditLog", audit)
    monkeypatch.setattr(socket, "socket", create_socket)
    monkeypatch.setattr(threading.Thread, "start", start_thread)
    return calls


def _wrong_provider(identity_module):
    def provide(_request):
        return identity_module.IdentityCredentials(b"a different but long phrase", None)

    return provide


def test_unlock_failure_precedes_all_service_persistence(
    tmp_path, credential_provider, monkeypatch
):
    service_module = _service_api()
    identity = importlib.import_module("sparc.identity")
    from sparc.models import SparcError

    data_dir = tmp_path / "wrong-credentials"
    identity.load_identity(data_dir, credential_provider=credential_provider)
    identity_path = data_dir / "identity.json"
    original = identity_path.read_bytes()
    calls = _watch_preinitialization(service_module, monkeypatch)

    with pytest.raises(SparcError) as raised:
        service_module.PeerService(
            data_dir, credential_provider=_wrong_provider(identity)
        )
    assert raised.value.code == "identity_unlock_failed"
    assert calls == []
    assert identity_path.read_bytes() == original
    assert not (data_dir / "trusted_peers.json").exists()
    assert not (data_dir / "audit.jsonl").exists()


def test_startup_cancellation_precedes_trust_audit_socket_and_thread(
    tmp_path, credential_provider, monkeypatch
):
    service_module = _service_api()
    identity = importlib.import_module("sparc.identity")
    calls = _watch_preinitialization(service_module, monkeypatch)
    data_dir = tmp_path / "canceled-startup"

    with pytest.raises(Exception) as raised:
        service_module.PeerService(
            data_dir,
            credential_provider=credential_provider,
            cancelled=lambda: True,
        )
    assert getattr(raised.value, "code", None) == "identity_unlock_cancelled"
    assert calls == []
    assert not data_dir.exists()
    assert not (data_dir / "identity.json").exists()
    assert identity.inspect_identity(data_dir).status == "absent"


def test_unlocked_factory_avoids_second_kdf(
    tmp_path, credential_provider, monkeypatch
):
    service_module = _service_api()
    identity = importlib.import_module("sparc.identity")
    codec = importlib.import_module("sparc.identity_codec")
    data_dir = tmp_path / "unlocked-factory"
    expected = identity.load_identity(data_dir, credential_provider=credential_provider)
    calls = []
    original_derive = codec._derive_key

    def count_derive(passphrase, salt):
        calls.append(True)
        return original_derive(passphrase, salt)

    monkeypatch.setattr(codec, "_derive_key", count_derive)
    handle = identity._unlock_store(data_dir, credential_provider=credential_provider)
    assert len(calls) == 1
    service = service_module.PeerService._from_unlocked_store(handle)
    try:
        assert service.own_fingerprint == expected.fingerprint
        assert len(calls) == 1
        assert not hasattr(service, "credential_provider")
    finally:
        service.close()


def test_changed_or_reused_handle_cannot_start_service(
    tmp_path, credential_provider, monkeypatch
):
    service_module = _service_api()
    identity = importlib.import_module("sparc.identity")
    from sparc.models import SparcError

    changed_dir = tmp_path / "changed-handle"
    identity.load_identity(changed_dir, credential_provider=credential_provider)
    changed_path = changed_dir / "identity.json"
    original = changed_path.read_bytes()
    changed_handle = identity._unlock_store(
        changed_dir, credential_provider=credential_provider
    )
    changed_path.write_bytes(original + b" ")
    calls = _watch_preinitialization(service_module, monkeypatch)
    with pytest.raises(SparcError) as raised:
        service_module.PeerService._from_unlocked_store(changed_handle)
    assert raised.value.code in {"identity_changed", "invalid_identity"}
    assert calls == []
    changed_path.write_bytes(original)

    reused_dir = tmp_path / "reused-handle"
    identity.load_identity(reused_dir, credential_provider=credential_provider)
    handle = identity._unlock_store(reused_dir, credential_provider=credential_provider)
    service = service_module.PeerService._from_unlocked_store(handle)
    try:
        initialized = list(calls)
        with pytest.raises(SparcError) as reused:
            service_module.PeerService._from_unlocked_store(handle)
        assert reused.value.code == "invalid_identity"
        assert calls == initialized
    finally:
        service.close()
