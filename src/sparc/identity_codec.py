"""Bounded Argon2id/Fernet encoding for persistent Ed25519 identities."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
from pathlib import Path
import secrets
from typing import Callable, Literal

from .encoding import canonical, parse_object
from .models import Identity, SparcError


_MAX_DOCUMENT_BYTES = 4096
_MAX_TOKEN_ASCII_BYTES = 2048
_MAX_PLAINTEXT_BYTES = 1024
_MAX_PRIVATE_DER_BYTES = 128
_PROFILE = {
    "name": "argon2id",
    "memory_cost": 65536,
    "iterations": 3,
    "lanes": 4,
    "length": 32,
}
_V1_FIELDS = {"version", "private_key", "public_key"}
_V2_FIELDS = {"version", "public_key", "encryption", "kdf", "encrypted_private_key"}
_KDF_FIELDS = {"name", "salt", "memory_cost", "iterations", "lanes", "length"}
_INNER_FIELDS = {"domain", "header", "private_key_pkcs8"}
_DOMAIN = "SPARC identity at rest v2"


@dataclass(frozen=True)
class IdentityUnlockRequest:
    purpose: Literal["create", "migrate", "unlock"]
    data_dir: Path
    fingerprint: str | None = None


@dataclass(frozen=True)
class IdentityCredentials:
    passphrase: bytes = field(repr=False)
    confirmation: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class IdentityInfo:
    status: Literal["absent", "legacy_unencrypted", "encrypted_locked"]
    public_bytes: bytes | None
    fingerprint: str | None
    private_key_verified: bool = False


CredentialProvider = Callable[[IdentityUnlockRequest], IdentityCredentials | None]
CancelPredicate = Callable[[], bool]


def _error(code: str, message: str) -> SparcError:
    return SparcError(code, message)


def _invalid_identity() -> SparcError:
    return _error("invalid_identity", "Identity store is malformed or unsupported")


def _validate_credentials(value: IdentityCredentials, purpose: str) -> bytes:
    if purpose not in ("create", "migrate", "unlock"):
        raise _error("identity_credentials_invalid", "Identity credentials are invalid")
    if not isinstance(value, IdentityCredentials) or type(value.passphrase) is not bytes:
        raise _error("identity_credentials_invalid", "Identity credentials are invalid")
    phrase = value.passphrase
    if not phrase or len(phrase) > 1024:
        raise _error("identity_credentials_invalid", "Identity credentials are invalid")
    if purpose in ("create", "migrate"):
        if len(phrase) < 15 or type(value.confirmation) is not bytes:
            raise _error("identity_credentials_invalid", "Identity credentials are invalid")
        if not hmac.compare_digest(phrase, value.confirmation):
            raise _error("identity_credentials_invalid", "Identity credentials do not match")
    elif value.confirmation is not None:
        raise _error("identity_credentials_invalid", "Identity credentials are invalid")
    return phrase


def validate_credentials(value: IdentityCredentials, purpose: str) -> bytes:
    """Validate byte credentials according to create/migrate/unlock policy."""
    return _validate_credentials(value, purpose)


def _check_cancelled(cancelled: CancelPredicate | None) -> None:
    if cancelled is None:
        return
    try:
        is_cancelled = cancelled()
    except Exception as error:
        raise _error("identity_unlock_cancelled", "Identity operation was canceled") from error
    if is_cancelled:
        raise _error("identity_unlock_cancelled", "Identity operation was canceled")


def _decode_base64(value: object, *, expected_length: int, urlsafe: bool = False) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64 value is not a string")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(
            encoded,
            altchars=b"-_" if urlsafe else None,
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise ValueError("base64 value is invalid") from error
    canonical_value = (
        base64.urlsafe_b64encode(decoded) if urlsafe else base64.b64encode(decoded)
    )
    if canonical_value != encoded or len(decoded) != expected_length:
        raise ValueError("base64 value is noncanonical or has the wrong size")
    return decoded


def _document(raw: bytes) -> tuple[IdentityInfo, dict]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise _invalid_identity()
    try:
        document = parse_object(raw)
    except (SparcError, RecursionError, ValueError, TypeError) as error:
        raise _invalid_identity() from error

    version = document.get("version")
    if type(version) is not int:
        raise _invalid_identity()

    try:
        if version == 1:
            if set(document) != _V1_FIELDS:
                raise _invalid_identity()
            public_bytes = _decode_base64(document["public_key"], expected_length=32)
            # Validate legacy private-field encoding/size only. Public inspection
            # does not parse the key or verify its correspondence with metadata.
            _decode_base64(document["private_key"], expected_length=32)
            info = IdentityInfo(
                status="legacy_unencrypted",
                public_bytes=public_bytes,
                fingerprint=hashlib.sha256(public_bytes).hexdigest(),
                private_key_verified=False,
            )
            return info, document

        if version != 2 or set(document) != _V2_FIELDS:
            raise _invalid_identity()
        public_bytes = _decode_base64(document["public_key"], expected_length=32)
        if document["encryption"] != "fernet" or type(document["encryption"]) is not str:
            raise _invalid_identity()
        kdf = document["kdf"]
        if not isinstance(kdf, dict) or set(kdf) != _KDF_FIELDS:
            raise _invalid_identity()
        if kdf["name"] != _PROFILE["name"] or type(kdf["name"]) is not str:
            raise _invalid_identity()
        for field_name in ("memory_cost", "iterations", "lanes", "length"):
            field_value = kdf[field_name]
            if type(field_value) is not int or field_value != _PROFILE[field_name]:
                raise _invalid_identity()
        _decode_base64(kdf["salt"], expected_length=16)

        token = document["encrypted_private_key"]
        if type(token) is not str:
            raise _invalid_identity()
        token_bytes = token.encode("ascii", errors="strict")
        if not 100 <= len(token_bytes) <= _MAX_TOKEN_ASCII_BYTES:
            raise _invalid_identity()
        token_raw = base64.b64decode(token_bytes, altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(token_raw) != token_bytes or not token_raw.startswith(b"\x80"):
            raise _invalid_identity()
        if len(token_raw) < 73 or (len(token_raw) - 57) % 16 != 0:
            raise _invalid_identity()
    except (ValueError, TypeError, KeyError, UnicodeEncodeError) as error:
        raise _invalid_identity() from error

    info = IdentityInfo(
        status="encrypted_locked",
        public_bytes=public_bytes,
        fingerprint=hashlib.sha256(public_bytes).hexdigest(),
        private_key_verified=False,
    )
    return info, document


def inspect_document(raw: bytes) -> IdentityInfo:
    """Validate bounded public identity metadata without key parsing or KDF."""
    info, _document_value = _document(raw)
    return info


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        derivation = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        )
        key = derivation.derive(passphrase)
        if type(key) is not bytes or len(key) != 32:
            raise MemoryError("Argon2id returned an unusable key")
        return key
    except Exception as error:
        # The public error intentionally hides provider, memory and credential
        # details; callers can ask the user to use a supported backend.
        raise _error(
            "identity_crypto_unavailable",
            "The required identity encryption backend is unavailable",
        ) from error


def _fernet_key(key: bytes) -> bytes:
    return base64.urlsafe_b64encode(key)


def _header(document: dict) -> dict:
    return {name: document[name] for name in ("version", "public_key", "encryption", "kdf")}


def encode_identity(
    identity: Identity,
    passphrase: bytes,
    *,
    cancelled: CancelPredicate | None = None,
) -> bytes:
    """Encrypt one existing Ed25519 identity into its canonical v2 envelope."""
    phrase = _validate_credentials(
        IdentityCredentials(passphrase, passphrase), "create"
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not isinstance(identity, Identity) or not isinstance(identity.private_key, Ed25519PrivateKey):
        raise _invalid_identity()
    try:
        public_bytes = identity.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if (
            type(identity.public_bytes) is not bytes
            or len(identity.public_bytes) != 32
            or not hmac.compare_digest(public_bytes, identity.public_bytes)
            or identity.fingerprint != hashlib.sha256(public_bytes).hexdigest()
        ):
            raise _invalid_identity()
        _check_cancelled(cancelled)
        private_der = identity.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except SparcError:
        raise
    except Exception as error:
        raise _invalid_identity() from error
    _check_cancelled(cancelled)
    if len(private_der) > _MAX_PRIVATE_DER_BYTES:
        raise _invalid_identity()

    salt = secrets.token_bytes(16)
    public_token = base64.b64encode(public_bytes).decode("ascii")
    header = {
        "version": 2,
        "public_key": public_token,
        "encryption": "fernet",
        "kdf": {
            "name": "argon2id",
            "salt": base64.b64encode(salt).decode("ascii"),
            "memory_cost": 65536,
            "iterations": 3,
            "lanes": 4,
            "length": 32,
        },
    }

    try:
        plaintext = canonical({
            "domain": _DOMAIN,
            "header": header,
            "private_key_pkcs8": base64.b64encode(private_der).decode("ascii"),
        })
    except SparcError as error:
        raise _invalid_identity() from error
    if len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise _invalid_identity()

    _check_cancelled(cancelled)
    key = _derive_key(phrase, salt)
    _check_cancelled(cancelled)
    try:
        from cryptography.fernet import Fernet

        token = Fernet(_fernet_key(key)).encrypt(plaintext).decode("ascii")
    except Exception as error:
        raise _error(
            "identity_crypto_unavailable",
            "The required identity encryption backend is unavailable",
        ) from error
    _check_cancelled(cancelled)

    document = {
        **header,
        "encrypted_private_key": token,
    }
    try:
        encoded = canonical(document)
    except SparcError as error:
        raise _invalid_identity() from error
    if len(encoded) > _MAX_DOCUMENT_BYTES:
        raise _invalid_identity()
    return encoded


def decode_identity(
    raw: bytes,
    passphrase: bytes,
    *,
    cancelled: CancelPredicate | None = None,
) -> Identity:
    """Authenticate and decrypt a v2 identity without mutating storage."""
    phrase = _validate_credentials(IdentityCredentials(passphrase), "unlock")
    info, document = _document(raw)
    if info.status != "encrypted_locked":
        raise _invalid_identity()

    salt = _decode_base64(document["kdf"]["salt"], expected_length=16)
    _check_cancelled(cancelled)
    key = _derive_key(phrase, salt)
    _check_cancelled(cancelled)
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except (ImportError, AttributeError) as error:
        raise _error(
            "identity_crypto_unavailable",
            "The required identity encryption backend is unavailable",
        ) from None
    try:
        plaintext = Fernet(_fernet_key(key)).decrypt(
            document["encrypted_private_key"].encode("ascii")
        )
    except InvalidToken:
        # Wrong phrase and authenticated-data corruption intentionally share
        # one fixed outcome. Never return or include decrypted bytes here.
        raise _error("identity_unlock_failed", "Could not unlock identity") from None
    except Exception:
        raise _error(
            "identity_crypto_unavailable",
            "The required identity encryption backend is unavailable",
        ) from None
    _check_cancelled(cancelled)
    if len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise _invalid_identity()

    try:
        inner = parse_object(plaintext)
        if set(inner) != _INNER_FIELDS or inner["domain"] != _DOMAIN:
            raise _invalid_identity()
        if type(inner["domain"]) is not str or type(inner["header"]) is not dict:
            raise _invalid_identity()
        outer_header = _header(document)
        if inner["header"] != outer_header:
            raise _invalid_identity()
        if canonical(inner) != plaintext:
            raise _invalid_identity()
        private_der = _decode_base64(
            inner["private_key_pkcs8"],
            expected_length=len(base64.b64decode(inner["private_key_pkcs8"], validate=True)),
        )
    except SparcError as error:
        if error.code == "invalid_identity":
            raise
        raise _invalid_identity() from error
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise _invalid_identity() from error
    if len(private_der) > _MAX_PRIVATE_DER_BYTES:
        raise _invalid_identity()

    _check_cancelled(cancelled)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = serialization.load_der_private_key(private_der, password=None)
    except Exception as error:
        raise _invalid_identity() from error
    _check_cancelled(cancelled)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise _invalid_identity()

    try:
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception as error:
        raise _invalid_identity() from error
    if not hmac.compare_digest(public_bytes, info.public_bytes or b""):
        raise _invalid_identity()
    return Identity(
        private_key=private_key,
        public_bytes=public_bytes,
        fingerprint=hashlib.sha256(public_bytes).hexdigest(),
    )
