"""F1a contracts for explicit credentials and the bounded encrypted identity codec."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import secrets

import pytest


def _codec():
    from importlib import import_module

    try:
        module = import_module("sparc.identity_codec")
    except ModuleNotFoundError as error:
        if error.name != "sparc.identity_codec":
            raise
        pytest.fail("the F1a identity codec API must be implemented")
    required = (
        "IdentityUnlockRequest",
        "IdentityCredentials",
        "IdentityInfo",
        "validate_credentials",
        "inspect_document",
        "encode_identity",
        "decode_identity",
    )
    missing = [name for name in required if not hasattr(module, name)]
    assert not missing, f"identity codec is missing its prescribed API: {missing}"
    return module


def _identity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.models import Identity

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())


def _private_der(identity):
    from cryptography.hazmat.primitives import serialization

    return identity.private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_b64(public_bytes):
    return base64.b64encode(public_bytes).decode("ascii")


def _passphrase():
    return secrets.token_hex(32).encode("ascii")


@pytest.fixture(scope="module")
def encrypted_case():
    codec = _codec()
    identity = _identity()
    passphrase = _passphrase()
    encoded = codec.encode_identity(identity, passphrase)
    return identity, passphrase, encoded, json.loads(encoded)


def _expect_code(code, call):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as error:
        call()
    assert error.value.code == code
    return error.value


def _install_derive_spy(monkeypatch, *, value=None, error=None, callback=None):
    """Replace only Argon2's final derive call to keep boundary tests fast."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    calls = []

    def derive(_self, material):
        calls.append(material)
        if callback is not None:
            callback()
        if error is not None:
            raise error
        return value if value is not None else b"T" * 32

    monkeypatch.setattr(Argon2id, "derive", derive)
    return calls


def test_codec_roundtrip_preserves_key_and_authenticates_header(encrypted_case):
    codec = _codec()
    original, passphrase, encoded, document = encrypted_case
    private_der = _private_der(original)

    assert set(document) == {
        "version", "public_key", "encryption", "kdf", "encrypted_private_key"
    }
    assert document["version"] == 2 and type(document["version"]) is int
    assert document["encryption"] == "fernet"
    assert set(document["kdf"]) == {
        "name", "salt", "memory_cost", "iterations", "lanes", "length"
    }
    assert document["kdf"]["name"] == "argon2id"
    assert len(base64.b64decode(document["kdf"]["salt"], validate=True)) == 16
    assert document["kdf"]["memory_cost"] == 65536
    assert document["kdf"]["iterations"] == 3
    assert document["kdf"]["lanes"] == 4
    assert document["kdf"]["length"] == 32
    assert private_der not in encoded
    assert base64.b64encode(private_der) not in encoded
    assert passphrase not in encoded

    info = codec.inspect_document(encoded)
    assert info.status == "encrypted_locked"
    assert info.public_bytes == original.public_bytes
    assert info.fingerprint == original.fingerprint
    assert info.private_key_verified is False

    recovered = codec.decode_identity(encoded, passphrase)
    assert recovered.public_bytes == original.public_bytes
    assert recovered.fingerprint == original.fingerprint
    message = b"F1 continuity"
    assert recovered.private_key.sign(message) == original.private_key.sign(message)

    second = json.loads(codec.encode_identity(original, passphrase))
    assert second["kdf"]["salt"] != document["kdf"]["salt"]

    changed_public = deepcopy(document)
    other_identity = _identity()
    changed_public["public_key"] = _public_b64(other_identity.public_bytes)
    error = _expect_code(
        "invalid_identity",
        lambda: codec.decode_identity(
            json.dumps(changed_public, separators=(",", ":")).encode(), passphrase
        ),
    )
    assert "F1 continuity" not in str(error)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda doc: doc.update(version=True), id="boolean-version"),
        pytest.param(lambda doc: doc.update(version=3), id="unsupported-version"),
        pytest.param(lambda doc: doc.update(extra="field"), id="extra-outer-field"),
        pytest.param(lambda doc: doc["kdf"].update(memory_cost=65537), id="oversized-cost"),
        pytest.param(lambda doc: doc["kdf"].update(memory_cost=True), id="boolean-cost"),
        pytest.param(lambda doc: doc["kdf"].update(iterations=4), id="wrong-iterations"),
        pytest.param(lambda doc: doc["kdf"].update(lanes=0), id="invalid-lanes"),
        pytest.param(lambda doc: doc["kdf"].update(length=64), id="wrong-key-length"),
        pytest.param(lambda doc: doc["kdf"].update(extra="field"), id="extra-kdf-field"),
        pytest.param(lambda doc: doc.update(public_key=doc["public_key"] + "="), id="noncanonical-public"),
        pytest.param(lambda doc: doc["kdf"].update(salt=doc["kdf"]["salt"] + "="), id="noncanonical-salt"),
        pytest.param(lambda doc: doc.update(encrypted_private_key=doc["encrypted_private_key"] + "="), id="noncanonical-token"),
        pytest.param(lambda doc: doc.update(encrypted_private_key="A" * 2049), id="token-over-bound"),
    ],
)
def test_codec_rejects_bounded_schema_before_kdf(encrypted_case, monkeypatch, mutate):
    codec = _codec()
    _identity_value, _passphrase_value, _encoded, valid = encrypted_case
    document = deepcopy(valid)
    mutate(document)
    raw = json.dumps(document, separators=(",", ":")).encode("ascii")
    calls = _install_derive_spy(monkeypatch)

    _expect_code("invalid_identity", lambda: codec.inspect_document(raw))
    _expect_code("invalid_identity", lambda: codec.decode_identity(raw, _passphrase()))
    assert calls == []


def test_codec_rejects_file_bound_and_duplicate_json_before_kdf(encrypted_case, monkeypatch):
    codec = _codec()
    _identity_value, _passphrase_value, encoded, _document = encrypted_case
    calls = _install_derive_spy(monkeypatch)

    oversized = b"{" + b" " * 4095 + b"}"
    _expect_code("invalid_identity", lambda: codec.inspect_document(oversized))
    _expect_code("invalid_identity", lambda: codec.decode_identity(oversized, _passphrase()))

    duplicate_version = encoded[:-1] + b',"version":2}'
    _expect_code("invalid_identity", lambda: codec.inspect_document(duplicate_version))
    _expect_code(
        "invalid_identity", lambda: codec.decode_identity(duplicate_version, _passphrase())
    )
    assert calls == []


def test_inspection_reports_v1_metadata_as_unverified():
    codec = _codec()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.encoding import canonical

    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    private_raw = first.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = second.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw = canonical({
        "version": 1,
        "private_key": base64.b64encode(private_raw).decode("ascii"),
        "public_key": _public_b64(public_raw),
    })

    info = codec.inspect_document(raw)
    assert info.status == "legacy_unencrypted"
    assert info.public_bytes == public_raw
    assert info.fingerprint == hashlib.sha256(public_raw).hexdigest()
    assert info.private_key_verified is False


def test_wrong_credentials_and_tampered_ciphertext_fail_closed(encrypted_case):
    codec = _codec()
    _identity_value, passphrase, encoded, document = encrypted_case
    wrong = _passphrase()
    wrong_error = _expect_code(
        "identity_unlock_failed", lambda: codec.decode_identity(encoded, wrong)
    )

    tampered = deepcopy(document)
    token = tampered["encrypted_private_key"]
    tampered["encrypted_private_key"] = token[:20] + ("A" if token[20] != "A" else "B") + token[21:]
    tampered_raw = json.dumps(tampered, separators=(",", ":")).encode("ascii")
    tamper_error = _expect_code(
        "identity_unlock_failed", lambda: codec.decode_identity(tampered_raw, passphrase)
    )
    tampered_salt = deepcopy(document)
    salt = bytearray(base64.b64decode(tampered_salt["kdf"]["salt"], validate=True))
    salt[0] ^= 1
    tampered_salt["kdf"]["salt"] = base64.b64encode(salt).decode("ascii")
    salt_raw = json.dumps(tampered_salt, separators=(",", ":")).encode("ascii")
    salt_error = _expect_code(
        "identity_unlock_failed", lambda: codec.decode_identity(salt_raw, passphrase)
    )
    assert str(wrong_error) == str(tamper_error)
    assert str(wrong_error) == str(salt_error)
    assert "private" not in str(wrong_error).lower()


def test_credential_confirmation_policy_types_and_repr():
    codec = _codec()
    credentials_type = codec.IdentityCredentials
    valid_phrase = "correct horse battery staple".encode("utf-8")
    credentials = credentials_type(valid_phrase, valid_phrase)
    assert codec.validate_credentials(credentials, "create") == valid_phrase
    assert valid_phrase.decode("ascii") not in repr(credentials)

    _expect_code(
        "identity_credentials_invalid",
        lambda: codec.validate_credentials(
            credentials_type(valid_phrase, b"different phrase"), "create"
        ),
    )
    _expect_code(
        "identity_credentials_invalid",
        lambda: codec.validate_credentials(credentials_type(b"short", b"short"), "create"),
    )
    _expect_code(
        "identity_credentials_invalid",
        lambda: codec.validate_credentials(credentials_type(valid_phrase, valid_phrase), "unlock"),
    )
    _expect_code(
        "identity_credentials_invalid",
        lambda: codec.validate_credentials(credentials_type(b"x" * 1025, b"x" * 1025), "create"),
    )

    binary = secrets.token_bytes(24)
    assert codec.validate_credentials(credentials_type(binary), "unlock") == binary
    _expect_code(
        "identity_credentials_invalid",
        lambda: codec.validate_credentials(credentials_type("not bytes"), "unlock"),
    )


def test_unlock_request_exposes_only_public_metadata_and_is_immutable(tmp_path):
    codec = _codec()
    request = codec.IdentityUnlockRequest(
        purpose="unlock",
        data_dir=tmp_path,
        fingerprint="a" * 64,
    )
    assert request.purpose == "unlock"
    assert request.data_dir == tmp_path
    assert request.fingerprint == "a" * 64
    assert "passphrase" not in repr(request).lower()
    with pytest.raises((AttributeError, TypeError)):
        request.purpose = "create"


def test_backend_failure_has_no_fallback(encrypted_case, monkeypatch):
    codec = _codec()
    identity, _passphrase_value, _encoded, _document = encrypted_case
    from cryptography.exceptions import UnsupportedAlgorithm

    calls = _install_derive_spy(monkeypatch, error=UnsupportedAlgorithm("backend unavailable"))
    error = _expect_code(
        "identity_crypto_unavailable",
        lambda: codec.encode_identity(identity, _passphrase()),
    )
    assert len(calls) == 1
    assert "backend unavailable" not in str(error)
    assert "-----BEGIN" not in str(error)


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param("unsupported", id="fernet-backend-unsupported"),
        pytest.param("memory", id="fernet-memory-failure"),
    ],
)
def test_fernet_decrypt_backend_and_memory_failures_are_not_wrong_password(
    encrypted_case, monkeypatch, failure
):
    codec = _codec()
    _identity_value, passphrase, encoded, _document = encrypted_case
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.fernet import Fernet

    error = (
        UnsupportedAlgorithm("provider unavailable")
        if failure == "unsupported"
        else MemoryError("allocation failed")
    )

    def fail_decrypt(_self, _token, ttl=None, current_time=None):
        raise error

    monkeypatch.setattr(Fernet, "decrypt", fail_decrypt)
    _install_derive_spy(monkeypatch, value=b"K" * 32)
    result = _expect_code(
        "identity_crypto_unavailable",
        lambda: codec.decode_identity(encoded, passphrase),
    )
    assert "provider unavailable" not in str(result)
    assert "allocation failed" not in str(result)


def test_missing_fernet_backend_is_crypto_unavailable(encrypted_case, monkeypatch):
    codec = _codec()
    _identity_value, passphrase, encoded, _document = encrypted_case
    import builtins

    _install_derive_spy(monkeypatch, value=b"K" * 32)
    real_import = builtins.__import__

    def fail_fernet_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "cryptography.fernet":
            raise ImportError("Fernet provider unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_fernet_import)
    error = _expect_code(
        "identity_crypto_unavailable",
        lambda: codec.decode_identity(encoded, passphrase),
    )
    assert "Fernet provider unavailable" not in str(error)


def test_cancel_before_and_after_kdf(encrypted_case, monkeypatch):
    codec = _codec()
    identity, _passphrase_value, _encoded, _document = encrypted_case
    calls = _install_derive_spy(monkeypatch)
    _expect_code(
        "identity_unlock_cancelled",
        lambda: codec.encode_identity(identity, _passphrase(), cancelled=lambda: True),
    )
    assert calls == []

    state = {"cancelled": False}

    def cancel_after_derive():
        state["cancelled"] = True

    calls = _install_derive_spy(monkeypatch, callback=cancel_after_derive)
    _expect_code(
        "identity_unlock_cancelled",
        lambda: codec.encode_identity(
            identity, _passphrase(), cancelled=lambda: state["cancelled"]
        ),
    )
    assert len(calls) == 1


def _authenticated_document(passphrase, *, plaintext=None, private_der=None, public_bytes=None):
    """Make a correctly authenticated envelope for post-KDF payload-boundary tests."""
    import base64 as b64
    from cryptography.fernet import Fernet
    from sparc.encoding import canonical

    public_bytes = secrets.token_bytes(32) if public_bytes is None else public_bytes
    salt = secrets.token_bytes(16)
    header = {
        "version": 2,
        "public_key": b64.b64encode(public_bytes).decode("ascii"),
        "encryption": "fernet",
        "kdf": {
            "name": "argon2id",
            "salt": b64.b64encode(salt).decode("ascii"),
            "memory_cost": 65536,
            "iterations": 3,
            "lanes": 4,
            "length": 32,
        },
    }
    if plaintext is None:
        plaintext = canonical({
            "domain": "SPARC identity at rest v2",
            "header": header,
            "private_key_pkcs8": b64.b64encode(private_der or b"x").decode("ascii"),
        })
    key = b"F" * 32
    fernet = Fernet(b64.urlsafe_b64encode(key))
    token = fernet.encrypt(plaintext).decode("ascii")
    outer = {
        **header,
        "encrypted_private_key": token,
    }
    return canonical(outer), key


@pytest.mark.parametrize("payload_kind", ["decrypted-json-over-bound", "der-over-bound"])
def test_authenticated_decrypted_payload_bounds_precede_key_loading(
    monkeypatch, payload_kind
):
    codec = _codec()
    from cryptography.hazmat.primitives import serialization

    if payload_kind == "decrypted-json-over-bound":
        raw, key = _authenticated_document(
            _passphrase(), plaintext=b"{" + b" " * 1023 + b"}"
        )
    else:
        raw, key = _authenticated_document(_passphrase(), private_der=b"D" * 129)
    _install_derive_spy(monkeypatch, value=key)
    loader_calls = []

    def unexpected_key_load(*args, **kwargs):
        loader_calls.append((args, kwargs))
        raise AssertionError("oversized payload reached the DER key loader")

    monkeypatch.setattr(serialization, "load_der_private_key", unexpected_key_load)
    _expect_code(
        "invalid_identity",
        lambda: codec.decode_identity(raw, _passphrase()),
    )
    assert loader_calls == []


def test_authenticated_non_ed25519_private_key_is_rejected(monkeypatch):
    codec = _codec()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    x25519 = X25519PrivateKey.generate()
    private = x25519.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = x25519.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw, key = _authenticated_document(
        _passphrase(), private_der=private, public_bytes=public_bytes
    )
    _install_derive_spy(monkeypatch, value=key)
    _expect_code(
        "invalid_identity",
        lambda: codec.decode_identity(raw, _passphrase()),
    )


def test_authenticated_ed25519_key_must_match_public_header(monkeypatch):
    codec = _codec()
    original = _identity()
    different = _identity()
    raw, key = _authenticated_document(
        _passphrase(),
        private_der=_private_der(original),
        public_bytes=different.public_bytes,
    )
    _install_derive_spy(monkeypatch, value=key)
    _expect_code(
        "invalid_identity",
        lambda: codec.decode_identity(raw, _passphrase()),
    )
