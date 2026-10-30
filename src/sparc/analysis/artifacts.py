"""Versioned, bounded public lab evidence; no persistent private keys."""
from dataclasses import asdict
import json
from pathlib import Path
import re

from .message import MessageTrial
from .models import Trial
from .specimen import SignatureResult, verify_timed_specimen
from ..storage import atomic_write

# Two text copies can each expand sixfold under JSON control-character escaping,
# in addition to the hexadecimal ciphertext and signed bytes.
MAX_ARTIFACT_BYTES = 524288
MAX_SIGNATURE_ARTIFACT_BYTES = 262144
MAX_SIGNED_BYTES = 65536

def save_artifact(result, destination: Path) -> None:
    if isinstance(result, SignatureResult):
        kind = 'signature'
    elif isinstance(result, MessageTrial):
        kind = 'message'
    elif isinstance(result, Trial):
        kind = 'sensitivity_trial'
    else:
        raise ValueError('This result does not have a public JSON artifact')
    data = asdict(result)
    for name in ('key', 'modified_key'):
        data.pop(name, None)
    data = {name: value.hex() if isinstance(value, bytes) else value for name,value in data.items()}
    payload = dict(format='sparc-public-analysis',version=1,kind=kind,
                   binary_encoding='hex',text_encoding='UTF-8',timing_unit='ns',data=data)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode('utf-8')
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError('Public analysis artifact is too large')
    atomic_write(Path(destination), encoded, private=True, secure_parent=False)

def _pairs(items):
    result = {}
    for key,value in items:
        if key in result:
            raise ValueError('Duplicate JSON fields are not allowed')
        result[key] = value
    return result

def load_signature_artifact(path: Path) -> SignatureResult:
    with Path(path).open('rb') as stream:
        content = stream.read(MAX_SIGNATURE_ARTIFACT_BYTES + 1)
    if len(content) > MAX_SIGNATURE_ARTIFACT_BYTES:
        raise ValueError('Signature artifact exceeds 256 KiB')
    try:
        payload = json.loads(content, object_pairs_hook=_pairs)
        if (type(payload) is not dict or payload.get('format') != 'sparc-public-analysis'
                or type(payload.get('version')) is not int or payload['version'] != 1
                or payload.get('kind') != 'signature' or type(payload.get('data')) is not dict):
            raise ValueError('Choose a version-1 SPARC public signature artifact')
        data = payload['data']
        def binary(name, length=None):
            value = data.get(name)
            if (type(value) is not str or len(value) > MAX_SIGNED_BYTES * 2
                    or re.fullmatch('[0-9a-fA-F]*',value) is None
                    or len(value) % 2 or length is not None and len(value) != length * 2):
                raise ValueError(f'Invalid {name} in signature artifact')
            return bytes.fromhex(value)
        public, signed, signature = binary('public_key',32), binary('signed_bytes'), binary('signature',64)
        sign_ns = data.get('sign_ns')
        if sign_ns is not None and (type(sign_ns) is not int or not 0 <= sign_ns < 2**63):
            raise ValueError('Invalid signing time in signature artifact')
    except (TypeError, UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('Choose a valid SPARC public signature JSON file') from error
    valid, verify_ns = verify_timed_specimen(public,signed,signature)
    return SignatureResult(public,signed,signature,valid,sign_ns,verify_ns)
