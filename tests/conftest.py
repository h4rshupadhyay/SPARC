"""Explicit identity credentials and service fixtures for tests."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sparc.encoding import canonical
from sparc.models import Identity, Limits


@pytest.fixture
def credential_provider():
    """Return stable random bytes per resolved store for this test only."""
    phrases: dict[Path, bytes] = {}

    def provide(request):
        from sparc.identity_codec import IdentityCredentials

        key = Path(request.data_dir).resolve()
        phrase = phrases.setdefault(key, secrets.token_urlsafe(32).encode("ascii"))
        confirmation = phrase if request.purpose in {"create", "migrate"} else None
        return IdentityCredentials(phrase, confirmation)

    return provide


@pytest.fixture
def service_factory(credential_provider):
    from sparc.peer.service import PeerService

    services = []

    def create(data_dir, limits=Limits()):
        service = PeerService(
            data_dir,
            limits,
            credential_provider=credential_provider,
        )
        services.append(service)
        return service

    try:
        yield create
    finally:
        for service in reversed(services):
            service.close()


@pytest.fixture
def legacy_identity_store():
    """Create a valid unencrypted v1 store and return its original key."""

    def create(data_dir):
        directory = Path(data_dir)
        directory.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        identity = Identity(
            private_key,
            public_bytes,
            hashlib.sha256(public_bytes).hexdigest(),
        )
        (directory / "identity.json").write_bytes(canonical({
            "version": 1,
            "private_key": base64.b64encode(private_bytes).decode("ascii"),
            "public_key": base64.b64encode(public_bytes).decode("ascii"),
        }))
        return identity

    return create
