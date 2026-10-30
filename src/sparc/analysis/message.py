"""Bounded custom-message experiments, independent of live identities/keys."""
from dataclasses import dataclass
import hashlib
import os
from time import perf_counter_ns

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models import SparcError

MAX_MESSAGE_BYTES = 16384

@dataclass(frozen=True)
class MessageTrial:
    plaintext: str
    plaintext_bytes: int
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    recovered_text: str
    digest: str
    recomputed_digest: str
    public_key: bytes
    signed_bytes: bytes
    signature: bytes
    signature_valid: bool
    timings: dict[str, int]

def run_message_trial(text: str, key: bytes | None = None) -> MessageTrial:
    """Time actual operations on exact UTF-8 bytes; never retain private keys."""
    if type(text) is not str or not 1 <= len(text) <= MAX_MESSAGE_BYTES:
        raise SparcError('invalid_analysis_input', 'Enter a message containing 1–16,384 UTF-8 bytes')
    try:
        data = text.encode('utf-8')
    except UnicodeError as error:
        raise SparcError('invalid_analysis_input', 'The message must be valid UTF-8 text') from error
    if len(data) > MAX_MESSAGE_BYTES:
        raise SparcError('invalid_analysis_input', 'Message exceeds 16,384 UTF-8 bytes')
    if key is not None and (type(key) is not bytes or len(key) != 32):
        raise SparcError('invalid_analysis_input', 'AES-256 lab key must contain exactly 32 bytes')
    cipher = AESGCM(os.urandom(32) if key is None else key)
    nonce = os.urandom(12)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    timings = {}
    def measure(name, call):
        started = perf_counter_ns()
        value = call()
        timings[name] = perf_counter_ns() - started
        return value
    digest = measure('hash', lambda: hashlib.sha256(data).digest()).hex()
    encrypted = measure('encrypt', lambda: cipher.encrypt(nonce, data, None))
    recovered = measure('decrypt', lambda: cipher.decrypt(nonce, encrypted, None))
    recomputed = measure('recompute_hash', lambda: hashlib.sha256(recovered).digest()).hex()
    signature = measure('sign', lambda: private.sign(data))
    measure('verify', lambda: public.verify(signature, recovered))
    return MessageTrial(text, len(data), encrypted[:-16], nonce, encrypted[-16:],
        recovered.decode('utf-8'), digest, recomputed, public_bytes, data, signature,
        True, timings)
