import builtins
import hashlib
import importlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


_DOMAIN = b"SPARC-v1 message\x00"
_TEXT = "SPARC synthetic signature specimen"


def _specimen_module():
    try:
        specimen = importlib.import_module("sparc.analysis.specimen")
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.specimen":
            raise
        pytest.fail("sparc.analysis.specimen must be implemented")
    assert callable(getattr(specimen, "make_specimen", None)), "make_specimen must be implemented"
    assert callable(getattr(specimen, "verify_specimen", None)), "verify_specimen must be implemented"
    return specimen


def _raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_specimen_rejects_edits_and_malformed_key_or_signature():
    specimen = _specimen_module()
    public_key, signed_bytes, signature = specimen.make_specimen()

    assert specimen.verify_specimen(public_key, signed_bytes, signature) is True

    edited_message = signed_bytes[:-1] + bytes((signed_bytes[-1] ^ 1,))
    edited_signature = signature[:-1] + bytes((signature[-1] ^ 1,))
    assert specimen.verify_specimen(public_key, edited_message, signature) is False
    assert specimen.verify_specimen(public_key, signed_bytes, edited_signature) is False
    assert specimen.verify_specimen(public_key[:-1], signed_bytes, signature) is False
    assert specimen.verify_specimen(public_key, signed_bytes, signature[:-1]) is False
    assert specimen.verify_specimen("not bytes", signed_bytes, signature) is False
    assert specimen.verify_specimen(public_key, "not bytes", signature) is False
    assert specimen.verify_specimen(public_key, signed_bytes, bytearray(signature)) is False


def test_specimen_contains_no_live_key_and_uses_c2_domain_context(monkeypatch):
    original_import = builtins.__import__

    def reject_service_import(name, *args, **kwargs):
        fromlist = kwargs.get("fromlist", args[2] if len(args) > 2 else ())
        if (
            name == "sparc.peer.service"
            or name.endswith(".peer.service")
            or (name == "sparc.peer" and "service" in fromlist)
        ):
            raise AssertionError("signature specimen must not access the peer service")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_service_import)
    specimen = _specimen_module()
    first = specimen.make_specimen()
    second = specimen.make_specimen()

    for item in (first, second):
        assert isinstance(item, tuple)
        assert len(item) == 3
        public_key, context, signature = item
        assert type(public_key) is bytes and len(public_key) == 32
        assert type(context) is bytes and context.startswith(_DOMAIN)
        assert type(signature) is bytes and len(signature) == 64
        assert specimen.verify_specimen(public_key, context, signature) is True

        projection_bytes = context[len(_DOMAIN) + 32 + 1 + 8 :]
        projection = json.loads(projection_bytes.decode("utf-8"))
        assert "text" not in projection
        assert projection["byte_count"] == len(_TEXT.encode("ascii"))
        assert projection["sha256"] == hashlib.sha256(_TEXT.encode("ascii")).hexdigest()
        assert projection["kind"] in {"chat", "benchmark"}

    assert first[0] != second[0]
    assert first[1][len(_DOMAIN) : len(_DOMAIN) + 32] == second[1][len(_DOMAIN) : len(_DOMAIN) + 32]


def test_unrelated_generated_identity_cannot_verify_specimen():
    specimen = _specimen_module()
    public_key, signed_bytes, signature = specimen.make_specimen()
    unrelated_private_key = Ed25519PrivateKey.generate()
    unrelated_public_key = _raw_public_key(unrelated_private_key)

    assert unrelated_public_key != public_key
    assert specimen.verify_specimen(unrelated_public_key, signed_bytes, signature) is False
