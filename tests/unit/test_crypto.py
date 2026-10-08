import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def test_hkdf_exact_inputs():
    from sparc.crypto import derive_traffic_keys

    secret = bytes(range(32))
    transcript = b'{"client_hello":{"kind":"client_hello"},"server_hello":{"kind":"server_hello"}}'
    session_id = hashlib.sha256(b"SPARC-v1 session\x00" + transcript).digest()
    expected = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=b"SPARC-v1 traffic\x00" + session_id,
    ).derive(secret)

    initiator_to_responder, responder_to_initiator, actual_session_id = derive_traffic_keys(secret, transcript)
    assert actual_session_id == session_id
    assert initiator_to_responder == expected[:32]
    assert responder_to_initiator == expected[32:]
    assert initiator_to_responder != responder_to_initiator


def test_aad_and_message_context_exact_bytes():
    from sparc.crypto import message_context, record_aad

    session_id = bytes(range(32))
    direction = 1
    sequence = 0x0102030405060708
    length = 0x00010203
    kind = 6

    expected_aad = (
        b"SPARC-v1 record\x00"
        + bytes((kind,))
        + session_id
        + bytes((direction,))
        + sequence.to_bytes(8, "big")
        + length.to_bytes(4, "big")
    )
    assert record_aad(kind, session_id, direction, sequence, length) == expected_aad

    projection = {
        "kind": "chat",
        "message_id": "0123456789abcdef0123456789abcdef",
        "byte_count": 3,
        "sha256": "a" * 64,
    }
    canonical_projection = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    expected_context = (
        b"SPARC-v1 message\x00"
        + session_id
        + bytes((direction,))
        + sequence.to_bytes(8, "big")
        + canonical_projection
    )
    assert message_context(session_id, direction, sequence, projection) == expected_context


@pytest.mark.parametrize(
    ("secret", "transcript"),
    [
        ("x" * 32, b"transcript"),
        (b"x" * 31, b"transcript"),
        (b"x" * 33, b"transcript"),
        (bytes(32), b"transcript"),
        (b"x" * 32, "transcript"),
    ],
)
def test_derive_traffic_keys_rejects_bad_inputs(secret, transcript):
    from sparc.models import SparcError
    from sparc.crypto import derive_traffic_keys

    with pytest.raises(SparcError) as raised:
        derive_traffic_keys(secret, transcript)
    assert raised.value.code == "invalid_key_exchange"


@pytest.mark.parametrize(
    ("kind", "session_id", "direction", "sequence", "length"),
    [
        (True, bytes(32), 0, 1, 58),
        (3, bytes(32), 0, 1, 58),
        (7, bytes(32), 0, 1, 58),
        (6, "s" * 32, 0, 1, 58),
        (6, bytes(31), 0, 1, 58),
        (6, bytes(32), True, 1, 58),
        (6, bytes(32), 2, 1, 58),
        (6, bytes(32), 0, True, 58),
        (6, bytes(32), 0, -1, 58),
        (6, bytes(32), 0, 2**64, 58),
        (6, bytes(32), 0, 1, True),
        (6, bytes(32), 0, 1, -1),
        (6, bytes(32), 0, 1, 2**32),
    ],
)
def test_record_aad_rejects_invalid_primitive_inputs(kind, session_id, direction, sequence, length):
    from sparc.models import SparcError
    from sparc.crypto import record_aad

    with pytest.raises(SparcError):
        record_aad(kind, session_id, direction, sequence, length)


@pytest.mark.parametrize(
    ("session_id", "direction", "sequence"),
    [
        ("s" * 32, 0, 1),
        (bytes(31), 0, 1),
        (bytes(32), True, 1),
        (bytes(32), 2, 1),
        (bytes(32), 0, True),
        (bytes(32), 0, -1),
        (bytes(32), 0, 2**64),
    ],
)
def test_message_context_rejects_invalid_primitive_inputs(session_id, direction, sequence):
    from sparc.models import SparcError
    from sparc.crypto import message_context

    with pytest.raises(SparcError):
        message_context(session_id, direction, sequence, {"kind": "ping", "ping_id": "0" * 32})


def test_uint64_max_and_protocol_frame_length_are_representable():
    from sparc.crypto import record_aad

    result = record_aad(6, bytes(32), 0, 2**64 - 1, 131072)
    assert result.endswith((2**64 - 1).to_bytes(8, "big") + (131072).to_bytes(4, "big"))
