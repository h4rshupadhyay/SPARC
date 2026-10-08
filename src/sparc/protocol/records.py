"""Authenticated session record codec; this milestone implements finished records."""

import base64
import hashlib
import re
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import message_context, record_aad
from ..encoding import canonical, parse_object
from ..models import Identity, Inspection, OpenedRecord, ProtectedRecord, Role, SparcError, Timings
from .framing import Frame, pack_frame
from .messages import decode_base64, signing_projection, validate_application


_UINT64_MAX = 2**64 - 1
_ID_BYTES = 32
_SEQUENCE_BYTES = 8
_RECORD_HEADER_BYTES = _ID_BYTES + _SEQUENCE_BYTES
_TAG_BYTES = 16
_MIN_ENCRYPTED_LENGTH = 58
_MAX_FRAME_LENGTH = 128 * 1024
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class SessionCodec:
    """Encrypt and authenticate finished records for one session direction pair."""

    def __init__(self, identity: Identity, peer_key: bytes, role: Role,
                 keys: tuple[bytes, bytes], session_id: bytes) -> None:
        if not isinstance(identity, Identity):
            raise TypeError("identity must be an Identity")
        if not isinstance(peer_key, bytes) or len(peer_key) != 32:
            raise SparcError("invalid_schema", "Peer identity key must contain 32 bytes")
        if not isinstance(role, Role):
            raise SparcError("invalid_schema", "Session role is invalid")
        if not isinstance(keys, tuple) or len(keys) != 2 or any(
            not isinstance(key, bytes) or len(key) != 32 for key in keys
        ):
            raise SparcError("invalid_key_exchange", "Traffic keys must be a pair of 32-byte values")
        if not isinstance(session_id, bytes) or len(session_id) != 32:
            raise SparcError("session_mismatch", "Session ID must contain exactly 32 bytes")

        self._identity = identity
        self._peer_key = peer_key
        self._role = role
        self._keys = keys  # (initiator→responder, responder→initiator) for either role.
        self._session_id = session_id
        self._send_next = 0
        self._receive_next = 0
        self._sent_finished = False
        self._received_finished = False
        self._usable = True

    @property
    def session_id(self) -> bytes:
        """The session identifier bound into every record."""
        return self._session_id

    def _ensure_usable(self) -> None:
        if not self._usable:
            raise SparcError("session_unusable", "Session codec cannot be reused after a failed record")

    def _ensure_send_counter(self) -> int:
        if type(self._send_next) is not int or not 0 <= self._send_next <= _UINT64_MAX:
            self._usable = False
            raise SparcError("counter_exhausted", "Outgoing record sequence is exhausted")
        return self._send_next

    def _ensure_receive_counter(self) -> int:
        if type(self._receive_next) is not int or not 0 <= self._receive_next <= _UINT64_MAX:
            self._usable = False
            raise SparcError("counter_exhausted", "Incoming record sequence is exhausted")
        return self._receive_next

    def _finished_send_type(self) -> int:
        if self._role is Role.RESPONDER:
            return 4
        return 5

    def _finished_receive_type(self) -> int:
        if self._role is Role.INITIATOR:
            return 4
        return 5

    def _send_direction(self) -> int:
        return 0 if self._role is Role.INITIATOR else 1

    def _receive_direction(self) -> int:
        return 1 if self._role is Role.INITIATOR else 0

    def _send_key(self) -> bytes:
        return self._keys[self._send_direction()]

    def _receive_key(self) -> bytes:
        return self._keys[self._receive_direction()]

    def _application_gate_open(self) -> bool:
        return self._sent_finished and self._received_finished

    @staticmethod
    def _validate_finished(payload: dict) -> None:
        if not isinstance(payload, dict) or payload.keys() != {"kind", "transcript_sha256"}:
            raise SparcError("invalid_schema", "Finished record fields do not match the schema")
        if payload.get("kind") != "finished":
            raise SparcError("invalid_schema", "Finished record kind is invalid")
        digest = payload.get("transcript_sha256")
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise SparcError("invalid_schema", "Finished transcript digest is invalid")

    def protect(self, payload: dict, frame_type: int = 6) -> ProtectedRecord:
        """Protect a finished record; application records are implemented later."""
        self._ensure_usable()
        sequence = self._ensure_send_counter()
        if type(frame_type) is not int:
            raise SparcError("invalid_record_type", "Frame type must be an integer")

        if frame_type == 6:
            if not self._application_gate_open():
                raise SparcError("invalid_record_type", "Application records require both finished records")
            return self._protect_application(payload, sequence)
        expected_type = self._finished_send_type()
        if frame_type != expected_type:
            raise SparcError("invalid_record_type", "Finished record type does not match this session role")
        if self._sent_finished:
            raise SparcError("sequence_failure", "Finished record was already sent")
        if self._role is Role.INITIATOR and not self._received_finished:
            raise SparcError("sequence_failure", "Initiator must receive responder finished before sending")
        if sequence != 0:
            raise SparcError("sequence_failure", "Finished record must use sequence zero")
        self._validate_finished(payload)

        plaintext = canonical(payload)
        sequence_bytes = sequence.to_bytes(_SEQUENCE_BYTES, "big")
        length = 1 + _RECORD_HEADER_BYTES + len(plaintext) + _TAG_BYTES
        aad = record_aad(frame_type, self._session_id, self._send_direction(), sequence, length)
        nonce = b"\x00" * 4 + sequence_bytes
        try:
            ciphertext_and_tag = AESGCM(self._send_key()).encrypt(nonce, plaintext, aad)
            encoded = pack_frame(
                frame_type,
                self._session_id + sequence_bytes + ciphertext_and_tag,
            )
        except Exception as exc:
            self._usable = False
            raise SparcError("session_unusable", "Could not protect finished record") from exc

        self._send_next = sequence + 1
        self._sent_finished = True
        return ProtectedRecord(frame=encoded, inspection=None)

    def _protect_application(self, payload: dict, sequence: int) -> ProtectedRecord:
        validate_application(payload, signed=False)
        projection = signing_projection(payload)
        direction = self._send_direction()
        context = message_context(self._session_id, direction, sequence, projection)

        started = time.perf_counter_ns()
        try:
            signature = self._identity.private_key.sign(context)
        except Exception as exc:
            self._usable = False
            raise SparcError("session_unusable", "Could not sign application record") from exc
        sign_ns = time.perf_counter_ns() - started
        if len(signature) != 64:
            self._usable = False
            raise SparcError("session_unusable", "Identity returned an invalid signature")

        signed_payload = dict(payload)
        signed_payload["signature"] = base64.b64encode(signature).decode("ascii")
        plaintext = canonical(signed_payload)
        length = 1 + _RECORD_HEADER_BYTES + len(plaintext) + _TAG_BYTES
        if length > _MAX_FRAME_LENGTH:
            raise SparcError("malformed_frame", "Application record exceeds the frame size limit")
        sequence_bytes = sequence.to_bytes(_SEQUENCE_BYTES, "big")
        aad = record_aad(6, self._session_id, direction, sequence, length)
        nonce = b"\x00" * 4 + sequence_bytes
        try:
            aesgcm = AESGCM(self._send_key())
            started = time.perf_counter_ns()
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
            encrypt_ns = time.perf_counter_ns() - started
            encoded = pack_frame(6, self._session_id + sequence_bytes + ciphertext_and_tag)
        except Exception as exc:
            self._usable = False
            raise SparcError("session_unusable", "Could not encrypt application record") from exc

        inspection = None
        if payload.get("kind") in ("chat", "benchmark"):
            inspection = Inspection(
                message_id=payload["message_id"],
                sequence=sequence,
                sha256=payload["sha256"],
                computed_sha256=None,
                signature=signature,
                ciphertext=ciphertext_and_tag[:-_TAG_BYTES],
                nonce=nonce,
                tag=ciphertext_and_tag[-_TAG_BYTES:],
                plaintext_bytes=len(plaintext),
                timings=Timings(hash_ns=None, sign_ns=sign_ns, encrypt_ns=encrypt_ns),
            )

        self._send_next = sequence + 1
        return ProtectedRecord(frame=encoded, inspection=inspection)

    def open(self, frame: Frame) -> OpenedRecord:
        """Authenticate one expected record and advance only after full validation."""
        self._ensure_usable()
        sequence = self._ensure_receive_counter()
        try:
            if isinstance(frame, Frame) and frame.kind == 6:
                if not self._application_gate_open():
                    raise SparcError("invalid_record_type", "Application records require both finished records")
                return self._open_application(frame, sequence)
            return self._open_finished(frame, sequence)
        except SparcError:
            self._usable = False
            raise
        except Exception as exc:
            self._usable = False
            raise SparcError("invalid_schema", "Incoming record is invalid") from exc

    def _open_application(self, frame: Frame, sequence: int) -> OpenedRecord:
        if type(frame.kind) is not int or type(frame.length) is not int:
            raise SparcError("malformed_frame", "Incoming frame metadata is invalid")
        if not isinstance(frame.body, bytes) or frame.length != len(frame.body) + 1:
            raise SparcError("malformed_frame", "Incoming frame length does not match its body")
        if frame.length < _MIN_ENCRYPTED_LENGTH or frame.length > _MAX_FRAME_LENGTH:
            raise SparcError("malformed_frame", "Incoming encrypted frame length is outside bounds")
        if frame.kind != 6:
            raise SparcError("invalid_record_type", "Application record must use frame type 6")
        if len(frame.body) < _RECORD_HEADER_BYTES + _TAG_BYTES + 1:
            raise SparcError("malformed_frame", "Encrypted record body is too short")

        body_session_id = frame.body[:_ID_BYTES]
        if body_session_id != self._session_id:
            raise SparcError("session_mismatch", "Record belongs to a different session")
        sequence_bytes = frame.body[_ID_BYTES:_RECORD_HEADER_BYTES]
        record_sequence = int.from_bytes(sequence_bytes, "big")
        if record_sequence != sequence:
            raise SparcError("sequence_failure", "Incoming record sequence is not the expected value")

        ciphertext_and_tag = frame.body[_RECORD_HEADER_BYTES:]
        aad = record_aad(frame.kind, self._session_id, self._receive_direction(), sequence, frame.length)
        nonce = b"\x00" * 4 + sequence_bytes
        try:
            aesgcm = AESGCM(self._receive_key())
            started = time.perf_counter_ns()
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
            decrypt_ns = time.perf_counter_ns() - started
        except InvalidTag as exc:
            raise SparcError("gcm_authentication_failed", "Incoming record authentication failed") from exc
        except Exception as exc:
            raise SparcError("gcm_authentication_failed", "Incoming record could not be authenticated") from exc

        try:
            payload = parse_object(plaintext)
            validate_application(payload, signed=True)
        except SparcError as exc:
            raise SparcError(exc.code if exc.code == "invalid_base64" else "invalid_schema",
                             "Application record schema is invalid") from exc

        hash_ns = None
        computed_digest = None
        if payload["kind"] in ("chat", "benchmark"):
            text_bytes = payload["text"].encode("utf-8", errors="strict")
            if len(text_bytes) != payload["byte_count"]:
                raise SparcError("byte_count_mismatch", "Application text byte count does not match")
            started = time.perf_counter_ns()
            raw_digest = hashlib.sha256(text_bytes).digest()
            hash_ns = time.perf_counter_ns() - started
            computed_digest = raw_digest.hex()
            if computed_digest != payload["sha256"]:
                raise SparcError("digest_mismatch", "Application text digest does not match")

        signature = decode_base64(payload["signature"], 64)
        projection = signing_projection(payload)
        context = message_context(self._session_id, self._receive_direction(), sequence, projection)
        try:
            peer_public_key = Ed25519PublicKey.from_public_bytes(self._peer_key)
            started = time.perf_counter_ns()
            peer_public_key.verify(signature, context)
            verify_ns = time.perf_counter_ns() - started
        except InvalidSignature as exc:
            raise SparcError("message_signature_failed", "Application signature is invalid") from exc
        except Exception as exc:
            raise SparcError("message_signature_failed", "Application signature could not be verified") from exc

        inspection = None
        if payload["kind"] in ("chat", "benchmark"):
            inspection = Inspection(
                message_id=payload["message_id"],
                sequence=sequence,
                sha256=payload["sha256"],
                computed_sha256=computed_digest,
                signature=signature,
                ciphertext=ciphertext_and_tag[:-_TAG_BYTES],
                nonce=nonce,
                tag=ciphertext_and_tag[-_TAG_BYTES:],
                plaintext_bytes=len(plaintext),
                timings=Timings(
                    hash_ns=hash_ns,
                    decrypt_ns=decrypt_ns,
                    verify_ns=verify_ns,
                ),
            )

        self._receive_next = sequence + 1
        return OpenedRecord(
            payload=payload,
            inspection=inspection,
            sequence=sequence,
            direction=self._receive_direction(),
        )

    def _open_finished(self, frame: Frame, sequence: int) -> OpenedRecord:
        if not isinstance(frame, Frame):
            raise SparcError("malformed_frame", "Incoming record is not a Frame")
        if type(frame.kind) is not int or type(frame.length) is not int:
            raise SparcError("malformed_frame", "Incoming frame metadata is invalid")
        if not isinstance(frame.body, bytes) or frame.length != len(frame.body) + 1:
            raise SparcError("malformed_frame", "Incoming frame length does not match its body")
        if frame.length < _MIN_ENCRYPTED_LENGTH or frame.length > _MAX_FRAME_LENGTH:
            raise SparcError("malformed_frame", "Incoming encrypted frame length is outside bounds")
        if frame.kind == 6:
            if not self._application_gate_open():
                raise SparcError("invalid_record_type", "Application records require both finished records")
            raise SparcError("invalid_record_type", "Application record opening is not implemented")
        expected_type = self._finished_receive_type()
        if frame.kind != expected_type:
            raise SparcError("invalid_record_type", "Finished record type does not match this session role")
        if self._received_finished:
            raise SparcError("sequence_failure", "Finished record was already received")
        if self._role is Role.RESPONDER and not self._sent_finished:
            raise SparcError("sequence_failure", "Responder must send finished before receiving initiator finished")
        if sequence != 0:
            raise SparcError("sequence_failure", "Finished record must use sequence zero")
        if len(frame.body) < _RECORD_HEADER_BYTES + _TAG_BYTES + 1:
            raise SparcError("malformed_frame", "Encrypted record body is too short")

        body_session_id = frame.body[:_ID_BYTES]
        if body_session_id != self._session_id:
            raise SparcError("session_mismatch", "Record belongs to a different session")
        sequence_bytes = frame.body[_ID_BYTES:_RECORD_HEADER_BYTES]
        record_sequence = int.from_bytes(sequence_bytes, "big")
        if record_sequence != sequence:
            raise SparcError("sequence_failure", "Incoming record sequence is not the expected value")
        ciphertext_and_tag = frame.body[_RECORD_HEADER_BYTES:]
        aad = record_aad(frame.kind, self._session_id, self._receive_direction(), sequence, frame.length)
        nonce = b"\x00" * 4 + sequence_bytes
        try:
            plaintext = AESGCM(self._receive_key()).decrypt(nonce, ciphertext_and_tag, aad)
        except InvalidTag as exc:
            raise SparcError("gcm_authentication_failed", "Incoming record authentication failed") from exc
        except Exception as exc:
            raise SparcError("gcm_authentication_failed", "Incoming record could not be authenticated") from exc

        try:
            payload = parse_object(plaintext)
            self._validate_finished(payload)
        except SparcError as exc:
            raise SparcError("invalid_schema", "Finished record schema is invalid") from exc

        self._receive_next = sequence + 1
        self._received_finished = True
        return OpenedRecord(payload=payload, inspection=None)
