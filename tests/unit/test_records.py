import base64
import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


_KEYS = (b"I" * 32, b"R" * 32)
_SESSION_ID = b"D" * 32
_TRANSCRIPT_HASH = hashlib.sha256(b"C2f handshake transcript").hexdigest()
_MESSAGE_ID = "0123456789abcdef0123456789abcdef"
_RUN_ID = "fedcba9876543210fedcba9876543210"
_MAX_SEQUENCE = 2**64 - 1


def _identity(seed):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _finished_pair():
    from sparc.models import Role
    from sparc.protocol.framing import Frame
    from sparc.protocol.records import SessionCodec

    initiator_identity = _identity(5)
    responder_identity = _identity(6)
    initiator = SessionCodec(
        initiator_identity, responder_identity.public_bytes, Role.INITIATOR, _KEYS, _SESSION_ID
    )
    responder = SessionCodec(
        responder_identity, initiator_identity.public_bytes, Role.RESPONDER, _KEYS, _SESSION_ID
    )
    finished = {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}
    wire = responder.protect(finished, frame_type=4).frame
    initiator.open(_frame(wire))
    wire = initiator.protect(finished, frame_type=5).frame
    responder.open(_frame(wire))
    return initiator, responder, initiator_identity, responder_identity


def _frame(wire):
    from sparc.protocol.framing import Frame

    length = struct.unpack(">I", wire[:4])[0]
    return Frame(kind=wire[4], body=wire[5:], length=length)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "utf-8"
    )


def _unsigned_chat(text="Cafe\u0301\n雪🧪", **changes):
    encoded = text.encode("utf-8")
    result = {
        "kind": "chat",
        "message_id": _MESSAGE_ID,
        "text": text,
        "byte_count": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    result.update(changes)
    return result


def _peer_side(recipient_role):
    initiator, responder, initiator_identity, responder_identity = _finished_pair()
    if recipient_role == "initiator":
        # The responder sends with direction 1 and the second traffic key.
        return initiator, responder, responder_identity, _KEYS[1], 1
    return responder, initiator, initiator_identity, _KEYS[0], 0


def _independent_frame(recipient_role, unsigned, *, sequence=1, signature_override=None):
    from sparc.protocol.framing import Frame

    _, _, sender_identity, key, direction = _peer_side(recipient_role)
    projection = dict(unsigned)
    projection.pop("text", None) if projection.get("kind") in ("chat", "benchmark") else None
    projection.pop("signature", None)
    context = (
        b"SPARC-v1 message\x00"
        + _SESSION_ID
        + bytes((direction,))
        + sequence.to_bytes(8, "big")
        + _canonical(projection)
    )
    signature = signature_override if signature_override is not None else sender_identity.private_key.sign(context)
    signed = dict(unsigned)
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    plaintext = _canonical(signed)
    length = 1 + 32 + 8 + len(plaintext) + 16
    prefix = length.to_bytes(4, "big")
    sequence_bytes = sequence.to_bytes(8, "big")
    aad = b"SPARC-v1 record\x00" + b"\x06" + _SESSION_ID + bytes((direction,)) + sequence_bytes + prefix
    nonce = b"\x00" * 4 + sequence_bytes
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Frame(6, _SESSION_ID + sequence_bytes + ciphertext_and_tag, length), signed, plaintext


def _assert_rejected_fail_closed(receiver, frame, expected_code):
    from sparc.models import SparcError

    before = receiver._receive_next
    with pytest.raises(SparcError) as raised:
        receiver.open(frame)
    assert raised.value.code == expected_code
    assert receiver._receive_next == before
    with pytest.raises(SparcError) as reuse_error:
        receiver.open(frame)
    assert reuse_error.value.code == "session_unusable"
    assert receiver._receive_next == before


@pytest.mark.parametrize("recipient_role", ["initiator", "responder"])
def test_unicode_round_trip_and_receiver_inspector(recipient_role, monkeypatch):
    from sparc.protocol import records

    real_sha256 = records.hashlib.sha256
    real_parse_object = records.parse_object
    clock = [0]

    class MeasuredText(str):
        def encode(self, *args, **kwargs):
            clock[0] += 1_000
            return super().encode(*args, **kwargs)

    class FormattedDigest(bytes):
        def hex(self):
            clock[0] += 1_000
            return super().hex()

    class FakeDigest:
        def __init__(self, digest):
            self._digest = digest

        def digest(self):
            clock[0] += 13
            return FormattedDigest(self._digest.digest())

        def hexdigest(self):
            clock[0] += 1_000
            return self._digest.hexdigest()

    def fake_sha256(data):
        clock[0] += 11
        return FakeDigest(real_sha256(data))

    def parse_with_measured_text(raw):
        payload = real_parse_object(raw)
        if isinstance(payload.get("text"), str):
            payload["text"] = MeasuredText(payload["text"])
        return payload

    initiator, responder, _, _ = _finished_pair()
    text = "Cafe\u0301\n雪🧪"
    unsigned = _unsigned_chat(text)
    expected_digest = real_sha256(text.encode("utf-8")).hexdigest()
    if recipient_role == "initiator":
        sender, receiver = responder, initiator
    else:
        sender, receiver = initiator, responder

    protected = sender.protect(unsigned)
    monkeypatch.setattr(records.hashlib, "sha256", fake_sha256)
    monkeypatch.setattr(records.time, "perf_counter_ns", lambda: clock[0])
    monkeypatch.setattr(records, "parse_object", parse_with_measured_text)
    opened = receiver.open(_frame(protected.frame))
    encoded = text.encode("utf-8")
    assert opened.payload["kind"] == "chat"
    assert opened.payload["text"] == text
    assert opened.payload["byte_count"] == len(encoded)
    assert opened.payload["sha256"] == expected_digest
    assert opened.sequence == 1
    assert opened.direction == (1 if recipient_role == "initiator" else 0)
    assert len(opened.payload["signature"]) > 0
    assert opened.inspection is not None
    assert opened.inspection.sha256 == expected_digest
    assert opened.inspection.computed_sha256 == expected_digest
    assert opened.inspection.message_id == _MESSAGE_ID
    assert opened.inspection.sequence == 1
    assert opened.inspection.plaintext_bytes > len(encoded)
    assert opened.inspection.timings.hash_ns == 24
    assert type(opened.inspection.timings.decrypt_ns) is int
    assert type(opened.inspection.timings.verify_ns) is int
    assert opened.inspection.timings.sign_ns is None
    assert opened.inspection.timings.encrypt_ns is None


@pytest.mark.parametrize(
    "unsigned",
    [
        {"kind": "ack", "message_id": _MESSAGE_ID, "sha256": "a" * 64, "status": "verified"},
        {"kind": "ping", "ping_id": _MESSAGE_ID},
        {"kind": "pong", "ping_id": _MESSAGE_ID},
    ],
)
def test_signed_control_records_are_opened_without_text_inspector(unsigned):
    receiver = _peer_side("initiator")[0]
    frame, signed, _ = _independent_frame("initiator", unsigned)
    opened = receiver.open(frame)
    assert opened.payload == signed
    assert opened.inspection is None
    assert opened.sequence == 1
    assert opened.direction == 1


def test_finished_record_has_no_application_coordinates():
    from sparc.models import Role
    from sparc.protocol.records import SessionCodec

    sender_identity = _identity(11)
    receiver_identity = _identity(12)
    sender = SessionCodec(
        sender_identity, receiver_identity.public_bytes, Role.RESPONDER, _KEYS, _SESSION_ID
    )
    receiver = SessionCodec(
        receiver_identity, sender_identity.public_bytes, Role.INITIATOR, _KEYS, _SESSION_ID
    )
    finished = {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}
    opened = receiver.open(_frame(sender.protect(finished, frame_type=4).frame))
    assert opened.sequence is None
    assert opened.direction is None
    assert opened.inspection is None


def test_replay_is_rejected():
    from sparc.models import SparcError

    initiator, responder, _, _ = _finished_pair()
    wire = initiator.protect(_unsigned_chat("replay me")).frame
    frame = _frame(wire)
    responder.open(frame)
    after_success = responder._receive_next
    with pytest.raises(SparcError) as raised:
        responder.open(frame)
    assert raised.value.code == "sequence_failure"
    assert responder._receive_next == after_success
    with pytest.raises(SparcError) as reuse_error:
        responder.open(frame)
    assert reuse_error.value.code == "session_unusable"


def test_out_of_order_fails():
    from sparc.models import SparcError

    initiator, responder, _, _ = _finished_pair()
    initiator.protect(_unsigned_chat("one", message_id="1" * 32))
    second = initiator.protect(_unsigned_chat("two", message_id="2" * 32))
    before = responder._receive_next
    with pytest.raises(SparcError) as raised:
        responder.open(_frame(second.frame))
    assert raised.value.code == "sequence_failure"
    assert responder._receive_next == before


@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("tag", "gcm_authentication_failed"),
        ("ciphertext", "gcm_authentication_failed"),
        ("aad", "gcm_authentication_failed"),
        ("session_id", "session_mismatch"),
        ("sequence", "sequence_failure"),
        ("length", "malformed_frame"),
        ("type", "invalid_record_type"),
        ("unknown_type", "invalid_record_type"),
    ],
)
def test_wire_tamper_fails_closed(tamper, expected_code):
    from sparc.protocol.framing import Frame

    receiver, _, _, _, _ = _peer_side("initiator")
    valid, _, _ = _independent_frame("initiator", _unsigned_chat("tamper target"))
    body = bytearray(valid.body)
    length = valid.length
    kind = valid.kind
    if tamper == "tag":
        body[-1] ^= 1
    elif tamper == "ciphertext":
        body[40] ^= 1
    elif tamper == "aad":
        body[-16:-16] = b"x"
        length += 1
    elif tamper == "session_id":
        body[0] ^= 1
    elif tamper == "sequence":
        body[32:40] = (2).to_bytes(8, "big")
    elif tamper == "length":
        length += 1
    elif tamper == "type":
        kind = 5
    else:
        kind = 7
    _assert_rejected_fail_closed(receiver, Frame(kind, bytes(body), length), expected_code)


@pytest.mark.parametrize("recipient_role", ["initiator", "responder"])
@pytest.mark.parametrize(
    ("corruption", "expected_code"),
    [
        ("bad_signature", "message_signature_failed"),
        ("bad_hash", "digest_mismatch"),
        ("bad_size", "byte_count_mismatch"),
        ("unknown_field", "invalid_schema"),
    ],
)
def test_independently_encrypted_invalid_envelopes_fail_closed(recipient_role, corruption, expected_code):
    receiver, _, _, _, _ = _peer_side(recipient_role)
    unsigned = _unsigned_chat("content verified after decrypt")
    signature_override = None
    if corruption == "bad_signature":
        signature_override = bytes(64)
    elif corruption == "bad_hash":
        unsigned["sha256"] = "0" * 64
    elif corruption == "bad_size":
        unsigned["byte_count"] += 1
    elif corruption == "unknown_field":
        unsigned["extra"] = "not permitted"

    frame, _, _ = _independent_frame(
        recipient_role, unsigned, signature_override=signature_override
    )
    _assert_rejected_fail_closed(receiver, frame, expected_code)


def test_maximum_receive_sequence_consumed_once_then_exhausted():
    from sparc.models import SparcError

    initiator, responder, _, _ = _finished_pair()
    initiator._send_next = _MAX_SEQUENCE
    responder._receive_next = _MAX_SEQUENCE
    final_wire = initiator.protect(_unsigned_chat("last receive sequence")).frame
    opened = responder.open(_frame(final_wire))
    assert opened.payload["text"] == "last receive sequence"
    assert opened.inspection.sequence == _MAX_SEQUENCE
    assert initiator._send_next == 2**64
    assert responder._receive_next == 2**64

    with pytest.raises(SparcError) as send_error:
        initiator.protect(_unsigned_chat("cannot wrap"))
    assert send_error.value.code == "counter_exhausted"
    with pytest.raises(SparcError) as receive_error:
        responder.open(_frame(final_wire))
    assert receive_error.value.code == "counter_exhausted"
    assert initiator._send_next == 2**64
    assert responder._receive_next == 2**64
