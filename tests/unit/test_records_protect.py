import base64
import hashlib
import json
import struct
from dataclasses import fields

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


_KEYS = (b"i" * 32, b"r" * 32)
_SESSION_ID = b"P" * 32
_TRANSCRIPT_HASH = hashlib.sha256(b"validated transcript fixture").hexdigest()
_INITIATOR_ID = "0123456789abcdef0123456789abcdef"
_RESPONDER_ID = "fedcba9876543210fedcba9876543210"


def _identity(seed):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _established_pair():
    from sparc.models import Role
    from sparc.protocol.records import SessionCodec
    from sparc.protocol.framing import Frame

    initiator_identity = _identity(3)
    responder_identity = _identity(4)
    initiator = SessionCodec(
        initiator_identity, responder_identity.public_bytes, Role.INITIATOR, _KEYS, _SESSION_ID
    )
    responder = SessionCodec(
        responder_identity, initiator_identity.public_bytes, Role.RESPONDER, _KEYS, _SESSION_ID
    )

    finished = {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}
    responder_finished = responder.protect(finished, frame_type=4)
    length = struct.unpack(">I", responder_finished.frame[:4])[0]
    initiator.open(Frame(4, responder_finished.frame[5:], length))
    initiator_finished = initiator.protect(finished, frame_type=5)
    length = struct.unpack(">I", initiator_finished.frame[:4])[0]
    responder.open(Frame(5, initiator_finished.frame[5:], length))
    return initiator, responder, initiator_identity, responder_identity


def _chat(text, message_id):
    encoded_text = text.encode("utf-8")
    return {
        "kind": "chat",
        "message_id": message_id,
        "text": text,
        "byte_count": len(encoded_text),
        "sha256": hashlib.sha256(encoded_text).hexdigest(),
    }


def _unpack(wire):
    length = struct.unpack(">I", wire[:4])[0]
    assert length == len(wire) - 4
    return length, wire[4], wire[5:]


def _decrypt_application(wire, key, direction):
    length, kind, body = _unpack(wire)
    session_id = body[:32]
    sequence_bytes = body[32:40]
    nonce = b"\x00" * 4 + sequence_bytes
    aad = (
        b"SPARC-v1 record\x00"
        + bytes((kind,))
        + session_id
        + bytes((direction,))
        + sequence_bytes
        + wire[:4]
    )
    plaintext = AESGCM(key).decrypt(nonce, body[40:], aad)
    return length, kind, session_id, sequence_bytes, nonce, plaintext, body


def test_protect_exact_signature_context_and_nonce():
    initiator, _, initiator_identity, _ = _established_pair()
    payload = _chat("héllo", _INITIATOR_ID)
    result = initiator.protect(payload)

    length, kind, session_id, sequence_bytes, nonce, plaintext, body = _decrypt_application(
        result.frame, _KEYS[0], direction=0
    )
    assert kind == 6
    assert session_id == _SESSION_ID
    assert sequence_bytes == (1).to_bytes(8, "big")
    assert nonce == b"\x00" * 4 + (1).to_bytes(8, "big")
    decoded = json.loads(plaintext.decode("utf-8"))
    projection = {
        "kind": "chat",
        "message_id": _INITIATOR_ID,
        "byte_count": len("héllo".encode("utf-8")),
        "sha256": hashlib.sha256("héllo".encode("utf-8")).hexdigest(),
    }
    canonical_projection = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    expected_context = (
        b"SPARC-v1 message\x00"
        + _SESSION_ID
        + b"\x00"
        + (1).to_bytes(8, "big")
        + canonical_projection
    )
    signature = base64.b64decode(decoded["signature"], validate=True)
    initiator_identity.private_key.public_key().verify(signature, expected_context)
    assert decoded == {**payload, "signature": base64.b64encode(signature).decode("ascii")}

    canonical_full = json.dumps(
        decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    assert plaintext == canonical_full
    assert length == 1 + 40 + len(plaintext) + 16
    assert len(body) == length - 1


def test_inspection_contains_digest_ciphertext_tag_and_timings():
    initiator, _, _, _ = _established_pair()
    payload = _chat("inspection text", _INITIATOR_ID)
    result = initiator.protect(payload)

    assert result.inspection is not None
    inspection = result.inspection
    length, kind, session_id, sequence_bytes, nonce, plaintext, body = _decrypt_application(
        result.frame, _KEYS[0], direction=0
    )
    parsed = json.loads(plaintext.decode("utf-8"))
    signature = base64.b64decode(parsed["signature"], validate=True)
    ciphertext_and_tag = body[40:]
    assert inspection.message_id == _INITIATOR_ID
    assert inspection.sequence == 1
    assert inspection.sha256 == hashlib.sha256(payload["text"].encode("utf-8")).hexdigest()
    assert inspection.computed_sha256 is None
    assert inspection.signature == signature
    assert inspection.ciphertext == ciphertext_and_tag[:-16]
    assert inspection.tag == ciphertext_and_tag[-16:]
    assert inspection.nonce == nonce
    assert inspection.plaintext_bytes == len(plaintext)
    assert length == len(result.frame) - 4
    assert kind == 6 and session_id == _SESSION_ID and sequence_bytes == (1).to_bytes(8, "big")

    field_names = {field.name for field in fields(inspection)}
    assert field_names == {
        "message_id", "sequence", "sha256", "computed_sha256", "signature",
        "ciphertext", "nonce", "tag", "plaintext_bytes", "timings",
    }
    assert inspection.timings.hash_ns is None
    assert type(inspection.timings.sign_ns) is int and inspection.timings.sign_ns >= 0
    assert type(inspection.timings.encrypt_ns) is int and inspection.timings.encrypt_ns >= 0
    assert inspection.timings.decrypt_ns is None
    assert inspection.timings.verify_ns is None


def test_separate_direction_keys():
    initiator, responder, _, _ = _established_pair()
    payload_i = _chat("initiator payload", _INITIATOR_ID)
    payload_r = _chat("responder payload", _RESPONDER_ID)

    outgoing_i = initiator.protect(payload_i)
    _, kind_i, sid_i, seq_i, _, plain_i, _ = _decrypt_application(outgoing_i.frame, _KEYS[0], 0)
    outgoing_r = responder.protect(payload_r)
    _, kind_r, sid_r, seq_r, _, plain_r, _ = _decrypt_application(outgoing_r.frame, _KEYS[1], 1)
    assert kind_i == kind_r == 6
    assert sid_i == sid_r == _SESSION_ID
    assert seq_i == seq_r == (1).to_bytes(8, "big")
    assert json.loads(plain_i)["text"] == payload_i["text"]
    assert json.loads(plain_r)["text"] == payload_r["text"]
    assert outgoing_i.frame != outgoing_r.frame
    assert _KEYS[0] != _KEYS[1]
    with pytest.raises(InvalidTag):
        _decrypt_application(outgoing_i.frame, _KEYS[1], 0)
    with pytest.raises(InvalidTag):
        _decrypt_application(outgoing_r.frame, _KEYS[0], 1)


def test_maximum_send_sequence_is_consumed_once_then_exhausted():
    from sparc.models import SparcError

    initiator, _, _, _ = _established_pair()
    initiator._send_next = 2**64 - 1
    payload = _chat("last sequence", _INITIATOR_ID)
    final_record = initiator.protect(payload)
    _, kind, session_id, sequence_bytes, _, plaintext, _ = _decrypt_application(
        final_record.frame, _KEYS[0], direction=0
    )
    assert kind == 6
    assert session_id == _SESSION_ID
    assert sequence_bytes == (2**64 - 1).to_bytes(8, "big")
    assert json.loads(plaintext)["text"] == "last sequence"
    assert initiator._send_next == 2**64

    with pytest.raises(SparcError) as raised:
        initiator.protect(payload)
    assert raised.value.code == "counter_exhausted"
    assert initiator._send_next == 2**64
