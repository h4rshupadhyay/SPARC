import base64
import hashlib
import json
import sys

import pytest


def _key(seed):
    return bytes([seed]) * 32


def _fingerprint(public_key):
    return hashlib.sha256(public_key).hexdigest()


def test_unknown_then_pin_is_known_and_persists_across_reload(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint

    public_key = _key(11)
    endpoint = Endpoint("192.0.2.10", 47655)
    store = TrustStore(tmp_path)
    assert store.check(public_key, endpoint) == "unknown"

    store.pin(public_key, endpoint, label="lab peer")
    assert store.check(public_key, endpoint) == "known"
    assert TrustStore(tmp_path).check(public_key, endpoint) == "known"


def test_changed_endpoint_key_is_blocked_until_explicit_forget(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    first_key = _key(12)
    replacement_key = _key(13)
    remembered = Endpoint("192.0.2.20", 47655)
    store = TrustStore(tmp_path)
    assert store.check(first_key, remembered) == "unknown"
    store.pin(first_key, remembered)
    assert store.check(first_key, Endpoint("192.0.2.21", 47655)) == "known"

    before = (tmp_path / "trusted_peers.json").read_bytes()
    assert store.check(replacement_key, remembered) == "changed"
    assert (tmp_path / "trusted_peers.json").read_bytes() == before
    with pytest.raises(SparcError):
        store.pin(replacement_key, remembered)
    assert (tmp_path / "trusted_peers.json").read_bytes() == before

    store.forget(_fingerprint(first_key))
    assert store.check(replacement_key, remembered) == "unknown"
    store.pin(replacement_key, remembered)
    assert store.check(replacement_key, remembered) == "known"


def test_remembered_endpoint_conflict_overrides_key_recognition(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint

    first_key = _key(14)
    second_key = _key(15)
    first_endpoint = Endpoint("198.51.100.1", 47655)
    second_endpoint = Endpoint("198.51.100.2", 47655)
    store = TrustStore(tmp_path)
    store.pin(first_key, first_endpoint)
    store.pin(second_key, second_endpoint)

    assert store.check(first_key, Endpoint("198.51.100.3", 47655)) == "known"
    assert store.check(first_key, second_endpoint) == "changed"


def test_forget_unknown_valid_fingerprint_is_noop(tmp_path):
    from sparc.identity import TrustStore

    store = TrustStore(tmp_path)
    store.forget("f" * 64)
    assert not (tmp_path / "trusted_peers.json").exists()


def test_corrupt_trust_is_not_empty_or_rewritten(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    path = tmp_path / "trusted_peers.json"
    original = b"{broken trust bytes"
    path.write_bytes(original)
    with pytest.raises(SparcError):
        TrustStore(tmp_path).check(_key(16), Endpoint("203.0.113.1", 47655))
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "document",
    [
        {"version": True, "peers": {}},
        {"version": 2, "peers": {}},
        {"version": 1, "peers": []},
        {"version": 1, "peers": {}, "extra": "field"},
        {"version": 1, "peers": {"A" * 64: {}}},
    ],
)
def test_corrupt_trust_schema_is_preserved(tmp_path, document):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    path = tmp_path / "trusted_peers.json"
    original = json.dumps(document).encode("utf-8")
    path.write_bytes(original)
    with pytest.raises(SparcError):
        TrustStore(tmp_path).check(_key(17), Endpoint("203.0.113.2", 47655))
    assert path.read_bytes() == original


def test_trust_schema_requires_fingerprint_key_and_entry_key_to_match(tmp_path):
    from sparc.encoding import canonical
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    public_key = _key(18)
    wrong_public_key = _key(19)
    fingerprint = _fingerprint(public_key)
    document = {
        "version": 1,
        "peers": {
            fingerprint: {
                "public_key": base64.b64encode(wrong_public_key).decode("ascii"),
                "label": "peer",
                "ip": "203.0.113.3",
                "port": 47655,
            }
        },
    }
    path = tmp_path / "trusted_peers.json"
    original = canonical(document)
    path.write_bytes(original)

    with pytest.raises(SparcError):
        TrustStore(tmp_path).check(public_key, Endpoint("203.0.113.3", 47655))
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "endpoint",
    [
        ("localhost", 47655),
        ("2001:db8::1", 47655),
        ("192.0.2.1", True),
        ("192.0.2.1", 0),
        ("192.0.2.1", 65536),
    ],
)
def test_trust_rejects_nonliteral_or_invalid_endpoints(tmp_path, endpoint):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    with pytest.raises(SparcError):
        TrustStore(tmp_path).check(_key(20), Endpoint(*endpoint))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner-mode policy")
def test_loading_existing_trust_restricts_directory_and_file_without_rewriting(tmp_path):
    import stat
    from sparc.identity import TrustStore
    from sparc.models import Endpoint

    store = TrustStore(tmp_path)
    store.pin(_key(21), Endpoint("192.0.2.40", 47655))
    path = tmp_path / "trusted_peers.json"
    original = path.read_bytes()
    path.chmod(0o644)
    tmp_path.chmod(0o755)

    loaded = TrustStore(tmp_path)

    assert loaded.check(_key(21), Endpoint("192.0.2.40", 47655)) == "known"
    assert path.read_bytes() == original
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner-mode policy")
def test_trust_permission_restriction_failure_is_a_domain_error(tmp_path, monkeypatch):
    import sparc.storage as storage
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    endpoint = Endpoint("192.0.2.41", 47655)
    store = TrustStore(tmp_path)
    store.pin(_key(22), endpoint)
    path = tmp_path / "trusted_peers.json"
    original = path.read_bytes()
    path.chmod(0o644)
    tmp_path.chmod(0o755)

    def fail_chmod(*_args, **_kwargs):
        raise PermissionError("simulated chmod failure")

    monkeypatch.setattr(storage.os, "chmod", fail_chmod)
    with pytest.raises(SparcError):
        TrustStore(tmp_path)
    assert path.read_bytes() == original


@pytest.mark.parametrize("stage", ["replace", "directory_sync"])
@pytest.mark.parametrize("operation", ["pin", "forget"])
def test_trust_write_failure_blocks_instance_and_fresh_reload_matches_disk(
    tmp_path, monkeypatch, stage, operation
):
    import sparc.storage as storage
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    old_key = _key(23)
    new_key = _key(24)
    old_endpoint = Endpoint("198.51.100.40", 47655)
    new_endpoint = Endpoint("198.51.100.41", 47655)
    store = TrustStore(tmp_path)
    store.pin(old_key, old_endpoint)
    path = tmp_path / "trusted_peers.json"
    original = path.read_bytes()

    if stage == "replace":
        def fail_replace(_source, _target):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(storage.os, "replace", fail_replace)
    else:
        def fail_directory_sync(_parent):
            raise OSError("simulated directory fsync failure")

        monkeypatch.setattr(storage, "_sync_parent_directory", fail_directory_sync)

    with pytest.raises(SparcError) as error:
        if operation == "pin":
            store.pin(new_key, new_endpoint)
        else:
            store.forget(hashlib.sha256(old_key).hexdigest())
    assert error.value.code == "trust_write_failed"

    on_disk = path.read_bytes()
    if stage == "replace":
        assert on_disk == original
    else:
        assert on_disk != original

    for attempt in (
        lambda: store.check(old_key, old_endpoint),
        lambda: store.pin(new_key, new_endpoint),
        lambda: store.forget(hashlib.sha256(old_key).hexdigest()),
    ):
        with pytest.raises(SparcError) as blocked_error:
            attempt()
        assert blocked_error.value.code == "trust_write_failed"

    fresh = TrustStore(tmp_path)
    if stage == "replace" or operation == "pin":
        assert fresh.check(old_key, old_endpoint) == "known"
    else:
        assert fresh.check(old_key, old_endpoint) == "unknown"
    assert fresh.check(new_key, new_endpoint) == ("known" if stage == "directory_sync" and operation == "pin" else "unknown")


def test_snapshot_returns_sorted_public_copies_and_tracks_pin_forget(tmp_path):
    from dataclasses import FrozenInstanceError

    from sparc.identity import TrustStore
    from sparc.models import Endpoint

    store = TrustStore(tmp_path)
    key_a, key_b = _key(31), _key(32)
    endpoint_a = Endpoint("192.0.2.31", 47655)
    endpoint_b = Endpoint("192.0.2.32", 47655)
    store.pin(key_b, endpoint_b, label="second")
    store.pin(key_a, endpoint_a, label="first")

    snapshot = store.snapshot()
    assert [entry["fingerprint"] for entry in snapshot] == sorted(
        (_fingerprint(key_a), _fingerprint(key_b))
    )
    assert all(set(entry) == {"fingerprint", "label", "endpoint"} for entry in snapshot)
    assert {entry["endpoint"] for entry in snapshot} == {endpoint_a, endpoint_b}
    assert {entry["label"] for entry in snapshot} == {"first", "second"}
    with pytest.raises(FrozenInstanceError):
        snapshot[0]["endpoint"].port = 1

    snapshot[0]["label"] = "mutated copy"
    snapshot.append({"fingerprint": "extra"})
    fresh = store.snapshot()
    assert len(fresh) == 2
    assert "mutated copy" not in {entry["label"] for entry in fresh}

    store.forget(_fingerprint(key_a))
    remaining = store.snapshot()
    assert remaining == [{
        "fingerprint": _fingerprint(key_b),
        "label": "second",
        "endpoint": endpoint_b,
    }]


def test_snapshot_rejects_poisoned_trust_write(tmp_path, monkeypatch):
    import sparc.identity as identity
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError

    store = TrustStore(tmp_path)

    def fail_write(*_args, **_kwargs):
        raise OSError("injected persistence failure")

    monkeypatch.setattr(identity, "atomic_write", fail_write)
    with pytest.raises(SparcError) as failed_pin:
        store.pin(_key(33), Endpoint("192.0.2.33", 47655))
    assert failed_pin.value.code == "trust_write_failed"
    with pytest.raises(SparcError) as blocked_snapshot:
        store.snapshot()
    assert blocked_snapshot.value.code == "trust_write_failed"
