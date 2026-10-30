"""Custom lab messages use real primitives and retain only public evidence."""
from dataclasses import asdict
import hashlib
from importlib import import_module

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sparc.models import SparcError

def module():
    try: return import_module('sparc.analysis.message')
    except ModuleNotFoundError: pytest.fail('custom message laboratory is missing')

def test_custom_unicode_message_roundtrip_digest_and_public_signature():
    key = bytes(range(32)); text = 'Information security — नमस्ते\nAES-256 🔐'
    result = module().run_message_trial(text, key=key)
    encoded = text.encode('utf-8')
    assert result.plaintext == result.recovered_text == text
    assert result.plaintext_bytes == len(encoded)
    assert result.digest == result.recomputed_digest == hashlib.sha256(encoded).hexdigest()
    assert len(result.nonce) == 12 and len(result.tag) == 16
    assert AESGCM(key).decrypt(result.nonce, result.ciphertext + result.tag, None) == encoded
    assert result.signed_bytes == encoded and result.signature_valid
    Ed25519PublicKey.from_public_bytes(result.public_key).verify(result.signature, encoded)
    assert set(result.timings) == {'encrypt','decrypt','hash','recompute_hash','sign','verify'}
    assert all(type(n) is int and n >= 0 for n in result.timings.values())
    assert not {'key','private_key','aes_key'} & asdict(result).keys()

def test_message_runs_use_fresh_nonces_even_with_the_same_lab_key():
    a = module().run_message_trial('same input', key=bytes(32))
    b = module().run_message_trial('same input', key=bytes(32))
    assert a.nonce != b.nonce and a.ciphertext != b.ciphertext
    assert a.digest == b.digest

def test_hash_timing_excludes_digest_hex_encoding(monkeypatch):
    api=module(); active=False; ticks=0
    original=api.hashlib.sha256
    class Digest(bytes):
        def hex(self):
            assert not active,'digest encoding must be outside the primitive timer'
            return super().hex()
    class Hash:
        def __init__(self,data): self.value=original(data)
        def digest(self):
            assert active
            return Digest(self.value.digest())
        def hexdigest(self):
            assert not active,'digest encoding must be outside the primitive timer'
            return self.value.hexdigest()
    def clock():
        nonlocal active,ticks
        active=not active; ticks+=1
        return ticks*100
    monkeypatch.setattr(api.hashlib,'sha256',Hash)
    monkeypatch.setattr(api,'perf_counter_ns',clock)
    result=api.run_message_trial('message')
    assert result.timings['hash']==result.timings['recompute_hash']==100

@pytest.mark.parametrize('text', ['', 'é' * 8193, '\ud800', 12])
def test_invalid_or_oversized_utf8_input_is_actionable(text):
    with pytest.raises(SparcError): module().run_message_trial(text)

@pytest.mark.parametrize('key', [b'', bytes(16), bytes(31), bytes(33), '0' * 64])
def test_custom_message_requires_a_256_bit_binary_key(key):
    with pytest.raises(SparcError): module().run_message_trial('message', key=key)

def test_custom_sensitivity_flips_the_selected_real_operand():
    from sparc.analysis import sensitivity
    function = getattr(sensitivity, 'custom_sensitivity_trial', None)
    assert callable(function), 'custom sensitivity input is missing'
    key, block = bytes(32), b'0123456789abcdef'
    plain = function(key, block, 'plaintext', 0)
    changed_key = function(key, block, 'key', 255)
    assert plain.key == key and plain.block == block
    assert plain.modified_block == bytes([block[0] ^ 128]) + block[1:]
    assert plain.modified_key == key
    assert changed_key.modified_key == bytes(31) + b'\x01'
    assert changed_key.modified_block == block
    assert plain.input_source == changed_key.input_source == 'custom'

@pytest.mark.parametrize('key,block,mode,bit', [(bytes(16),bytes(16),'plaintext',0),
    (bytes(32),bytes(15),'plaintext',0), (bytes(32),bytes(16),'plaintext',128),
    (bytes(32),bytes(16),'key',256)])
def test_custom_sensitivity_rejects_invalid_sizes_and_bit_positions(key,block,mode,bit):
    from sparc.analysis import sensitivity
    function = getattr(sensitivity, 'custom_sensitivity_trial', None)
    assert callable(function), 'custom sensitivity input is missing'
    with pytest.raises(SparcError): function(key,block,mode,bit)
