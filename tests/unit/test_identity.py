import base64
import hashlib
import json
from pathlib import Path
import stat
import sys

import pytest


def _valid_identity_document():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.encoding import canonical

    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return canonical(
        {
            "version": 1,
            "private_key": base64.b64encode(private_raw).decode("ascii"),
            "public_key": base64.b64encode(public_raw).decode("ascii"),
        }
    )


def test_identity_is_persistent(tmp_path):
    from sparc.identity import load_identity

    first = load_identity(tmp_path)
    second = load_identity(tmp_path)
    assert first.public_bytes == second.public_bytes
    assert len(first.public_bytes) == 32
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == hashlib.sha256(first.public_bytes).hexdigest()
    assert len(first.fingerprint) == 64
    assert all(character in "0123456789abcdef" for character in first.fingerprint)


def test_corrupt_identity_is_not_replaced(tmp_path):
    from sparc.identity import load_identity
    from sparc.models import SparcError

    path = tmp_path / "identity.json"
    original = b"{invalid existing identity"
    path.write_bytes(original)

    with pytest.raises(SparcError):
        load_identity(tmp_path)
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.update(version=True),
        lambda document: document.update(version=2),
        lambda document: document.update(extra="field"),
        lambda document: document.update(private_key="not canonical base64!"),
        lambda document: document.update(private_key=base64.b64encode(b"short").decode("ascii")),
    ],
)
def test_identity_rejects_invalid_schema_or_key_encoding_without_rewriting(tmp_path, mutate):
    from sparc.identity import load_identity
    from sparc.models import SparcError

    document = json.loads(_valid_identity_document())
    mutate(document)
    original = json.dumps(document).encode("utf-8")
    path = tmp_path / "identity.json"
    path.write_bytes(original)

    with pytest.raises(SparcError):
        load_identity(tmp_path)
    assert path.read_bytes() == original


def test_identity_rejects_mismatched_private_and_public_keys(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.encoding import canonical
    from sparc.identity import load_identity
    from sparc.models import SparcError

    document = json.loads(_valid_identity_document())
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    document["public_key"] = base64.b64encode(other).decode("ascii")
    original = canonical(document)
    path = tmp_path / "identity.json"
    path.write_bytes(original)

    with pytest.raises(SparcError):
        load_identity(tmp_path)
    assert path.read_bytes() == original


def test_platform_paths_and_owner_modes(tmp_path, monkeypatch):
    import sparc.storage as storage
    from sparc.identity import load_identity
    from sparc.storage import resolve_data_dir

    override = tmp_path / "explicit" / "store"
    assert resolve_data_dir(override) == override

    windows_root = tmp_path / "profile" / "AppData" / "Local"
    monkeypatch.setattr(storage.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(windows_root))
    assert resolve_data_dir(override) == override
    assert resolve_data_dir(None) == windows_root / "SPARC"

    monkeypatch.delenv("LOCALAPPDATA")
    from sparc.models import SparcError

    with pytest.raises(SparcError):
        resolve_data_dir(None)

    monkeypatch.setattr(storage.sys, "platform", "linux")
    xdg_root = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_root))
    assert resolve_data_dir(None) == xdg_root / "sparc"

    monkeypatch.setenv("XDG_CONFIG_HOME", "relative-config")
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home)
    assert resolve_data_dir(None) == home / ".config" / "sparc"

    data_dir = tmp_path / "private-store"
    load_identity(data_dir)
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((data_dir / "identity.json").stat().st_mode) == 0o600


def test_atomic_write_failure_preserves_existing_file(tmp_path, monkeypatch):
    import sparc.storage as storage
    from sparc.storage import atomic_write

    destination = tmp_path / "store.json"
    destination.write_bytes(b"existing")

    def fail_replace(source, target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    with pytest.raises(OSError):
        atomic_write(destination, b"replacement")
    assert destination.read_bytes() == b"existing"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner-mode policy")
def test_loading_existing_identity_restricts_directory_and_file_without_rewriting(tmp_path):
    from sparc.identity import load_identity

    data_dir = tmp_path / "identity-dir"
    original_identity = load_identity(data_dir)
    path = data_dir / "identity.json"
    original = path.read_bytes()
    path.chmod(0o644)
    data_dir.chmod(0o755)

    loaded = load_identity(data_dir)

    assert loaded.public_bytes == original_identity.public_bytes
    assert path.read_bytes() == original
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner-mode policy")
def test_identity_permission_restriction_failure_is_a_domain_error(tmp_path, monkeypatch):
    import sparc.storage as storage
    from sparc.identity import load_identity
    from sparc.models import SparcError

    data_dir = tmp_path / "identity-dir"
    load_identity(data_dir)
    path = data_dir / "identity.json"
    original = path.read_bytes()
    path.chmod(0o644)
    data_dir.chmod(0o755)

    def fail_chmod(*_args, **_kwargs):
        raise PermissionError("simulated chmod failure")

    monkeypatch.setattr(storage.os, "chmod", fail_chmod)
    with pytest.raises(SparcError):
        load_identity(data_dir)
    assert path.read_bytes() == original
