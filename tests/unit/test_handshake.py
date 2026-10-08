"""Pure handshake construction and trust-decision contract tests."""

import base64
import hashlib
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _identity(seed=7):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _hello(kind="client_hello", **changes):
    values = {
        "kind": kind,
        "protocol": "SPARC",
        "version": 1,
        "identity_key": base64.b64encode(bytes(range(32))).decode("ascii"),
        "ephemeral_key": base64.b64encode(bytes(range(32, 64))).decode("ascii"),
        "random": base64.b64encode(bytes(reversed(range(32)))).decode("ascii"),
    }
    values.update(changes)
    return values


def test_hello_contains_fresh_random_and_ephemeral_key_each_call():
    from sparc.protocol.handshake_transcript import make_hello, validate_hello

    identity = _identity()
    first, first_private = make_hello(identity, "client_hello")
    second, second_private = make_hello(identity, "client_hello")

    validate_hello(first, signed=False)
    validate_hello(second, signed=False)
    validate_hello(_hello("server_hello"), signed=False)
    assert first["identity_key"] == second["identity_key"] == base64.b64encode(identity.public_bytes).decode()
    assert len(base64.b64decode(first["random"], validate=True)) == 32
    assert len(base64.b64decode(second["random"], validate=True)) == 32
    assert first["random"] != second["random"]
    assert first["ephemeral_key"] != second["ephemeral_key"]
    raw_format = serialization.PrivateFormat.Raw
    no_encryption = serialization.NoEncryption()
    assert first_private.private_bytes(
        serialization.Encoding.Raw, raw_format, no_encryption
    ) != second_private.private_bytes(serialization.Encoding.Raw, raw_format, no_encryption)


def test_transcript_exact_canonical_fields_and_signature_exclusion():
    from sparc.encoding import canonical
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import transcript

    client = _hello("client_hello")
    server = _hello("server_hello", random=base64.b64encode(b"s" * 32).decode())
    expected = canonical({"client_hello": client, "server_hello": server})
    assert transcript(client, server) == expected
    with pytest.raises(SparcError) as error:
        transcript(client, {**server, "signature": base64.b64encode(b"x" * 64).decode()})
    assert error.value.code == "invalid_schema"
    with pytest.raises(SparcError) as error:
        transcript({**client, "unexpected": "field"}, server)
    assert error.value.code == "invalid_schema"


def test_roles_do_not_share_signature_domain():
    from sparc.protocol.handshake_transcript import (
        HANDSHAKE_INITIATOR_DOMAIN,
        HANDSHAKE_RESPONDER_DOMAIN,
    )

    assert HANDSHAKE_RESPONDER_DOMAIN == b"SPARC-v1 handshake responder\x00"
    assert HANDSHAKE_INITIATOR_DOMAIN == b"SPARC-v1 handshake initiator\x00"
    assert HANDSHAKE_RESPONDER_DOMAIN != HANDSHAKE_INITIATOR_DOMAIN


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"version": 2}, "unsupported_version"),
        ({"version": True}, "invalid_schema"),
        ({"protocol": "OTHER"}, "invalid_schema"),
        ({"kind": "client_auth"}, "invalid_schema"),
        ({"unexpected": "field"}, "invalid_schema"),
        ({"random": base64.b64encode(b"x" * 31).decode()}, "invalid_base64"),
        ({"random": base64.b64encode(b"x" * 32).decode().rstrip("=")}, "invalid_base64"),
        ({"random": "%%%"}, "invalid_base64"),
    ],
)
def test_hello_schema_rejections_have_stable_codes(changes, code):
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import validate_hello

    with pytest.raises(SparcError) as error:
        validate_hello(_hello(**changes), signed=False)
    assert error.value.code == code


def test_signed_server_hello_requires_only_canonical_64_byte_signature():
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import validate_hello

    unsigned = _hello("server_hello")
    signature = base64.b64encode(b"s" * 64).decode("ascii")
    validate_hello({**unsigned, "signature": signature}, signed=True)
    for invalid in (base64.b64encode(b"s" * 63).decode(), "!", signature.rstrip("=")[:-1]):
        with pytest.raises(SparcError) as error:
            validate_hello({**unsigned, "signature": invalid}, signed=True)
        assert error.value.code == "invalid_base64"
    with pytest.raises(SparcError) as error:
        validate_hello({**unsigned, "signature": signature, "extra": 1}, signed=True)
    assert error.value.code == "invalid_schema"


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"kind": "other", "signature": base64.b64encode(b"s" * 64).decode()}, "invalid_schema"),
        ({"kind": "client_auth", "signature": base64.b64encode(b"s" * 63).decode()}, "invalid_base64"),
        ({"kind": "client_auth", "signature": "!"}, "invalid_base64"),
        ({"kind": "client_auth", "signature": base64.b64encode(b"s" * 64).decode(), "extra": 1}, "invalid_schema"),
        ({"kind": "client_auth"}, "invalid_schema"),
    ],
)
def test_client_auth_schema_is_exact(payload, code):
    from sparc.models import SparcError
    from sparc.protocol.handshake_transcript import _validate_client_auth

    with pytest.raises(SparcError) as error:
        _validate_client_auth(payload)
    assert error.value.code == code


def test_peer_candidate_and_established_session_are_frozen_and_fingerprint_is_raw_key_hash():
    from sparc.models import Endpoint, Role
    from sparc.protocol.handshake_types import EstablishedSession, PeerCandidate
    from sparc.protocol.records import SessionCodec

    peer_key = bytes(range(32))
    candidate = PeerCandidate(peer_key, hashlib.sha256(peer_key).hexdigest(), Endpoint("127.0.0.1", 43120))
    codec = SessionCodec(_identity(), peer_key, Role.INITIATOR, (b"a" * 32, b"b" * 32), b"c" * 32)
    session = EstablishedSession(codec, candidate, False, "d" * 64)
    with pytest.raises(FrozenInstanceError):
        candidate.fingerprint = "e" * 64
    with pytest.raises(FrozenInstanceError):
        session.newly_approved = True
    assert candidate.fingerprint == hashlib.sha256(peer_key).hexdigest()


def test_approval_changed_pin_never_prompts_and_unknown_true_does_not_write(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError
    from sparc.protocol.handshake_transcript import approve_candidate
    from sparc.protocol.handshake_types import PeerCandidate

    trust = TrustStore(tmp_path)
    endpoint = Endpoint("127.0.0.1", 43120)
    old_key, replacement = b"o" * 32, b"r" * 32
    trust.pin(old_key, endpoint)
    before = (tmp_path / "trusted_peers.json").read_bytes()
    candidate = PeerCandidate(replacement, hashlib.sha256(replacement).hexdigest(), endpoint)
    prompted = []

    with pytest.raises(SparcError) as error:
        approve_candidate(candidate, trust, lambda value: prompted.append(value) or True)
    assert error.value.code == "changed_identity"
    assert prompted == []
    assert (tmp_path / "trusted_peers.json").read_bytes() == before

    unknown_store = TrustStore(tmp_path / "other")
    unknown = PeerCandidate(old_key, hashlib.sha256(old_key).hexdigest(), Endpoint("127.0.0.2", 43121))
    assert approve_candidate(unknown, unknown_store, lambda _candidate: True) is True
    assert not (tmp_path / "other" / "trusted_peers.json").exists()


def test_approval_known_skips_prompt_unknown_requires_literal_true(tmp_path):
    from sparc.identity import TrustStore
    from sparc.models import Endpoint, SparcError
    from sparc.protocol.handshake_transcript import approve_candidate
    from sparc.protocol.handshake_types import PeerCandidate

    trust = TrustStore(tmp_path)
    endpoint = Endpoint("127.0.0.1", 43120)
    key = b"k" * 32
    trust.pin(key, endpoint)
    candidate = PeerCandidate(key, hashlib.sha256(key).hexdigest(), endpoint)
    assert approve_candidate(candidate, trust, lambda _candidate: pytest.fail("known peer prompted")) is False

    unknown = PeerCandidate(b"u" * 32, hashlib.sha256(b"u" * 32).hexdigest(), Endpoint("127.0.0.2", 43121))
    for answer, code in ((False, "pairing_rejected"), (1, "invalid_schema"), (None, "invalid_schema")):
        with pytest.raises(SparcError) as error:
            approve_candidate(unknown, trust, lambda _candidate, answer=answer: answer)
        assert error.value.code == code
