"""Strict bounded file envelopes shared by wire validation and audit evidence."""

import re
from dataclasses import dataclass

from ..models import Inspection, SparcError

CHUNK_BYTES = 65536
MAX_FILE_BYTES = 100 * 1024 * 1024
FILE_FIELDS = {
    'file_offer': {'kind', 'transfer_id', 'filename', 'size', 'sha256', 'media_type', 'chunk_size'},
    'file_decision': {'kind', 'transfer_id', 'decision', 'reason'},
    'file_chunk': {'kind', 'transfer_id', 'index', 'offset', 'byte_count', 'sha256', 'data'},
    'file_chunk_ack': {'kind', 'transfer_id', 'index', 'sha256', 'status'},
    'file_complete': {'kind', 'transfer_id', 'size', 'sha256'},
    'file_result': {'kind', 'transfer_id', 'size', 'sha256', 'status'},
    'file_cancel': {'kind', 'transfer_id', 'reason'},
}
FILE_KINDS = frozenset(FILE_FIELDS)
_ID = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_MEDIA = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}


@dataclass(frozen=True)
class FileInspection(Inspection):
    """A bounded ciphertext sample, with its actual length kept separately."""

    ciphertext_length: int = 0


def validate_file(payload: dict, *, projection: bool = False) -> None:
    """Validate an unsigned envelope (or its data-free signing projection)."""
    from .messages import decode_base64

    def require(condition, message):
        if not condition:
            raise SparcError('invalid_schema', message)

    def integer(key, low, high):
        value = payload.get(key)
        require(type(value) is int and low <= value <= high, f'File {key} is outside bounds')

    def text(key, maximum):
        value = payload.get(key)
        require(isinstance(value, str) and bool(value), f'File {key} must be nonempty text')
        try:
            encoded = value.encode('utf-8')
        except UnicodeError as exc:
            raise SparcError('invalid_schema', 'File text is invalid Unicode') from exc
        require(len(encoded) <= maximum and not any(ord(c) < 32 or ord(c) == 127 for c in value),
                f'File {key} exceeds its text bounds')

    require(isinstance(payload, dict), 'File envelope must be an object')
    kind = payload.get('kind')
    fields = FILE_FIELDS.get(kind) if isinstance(kind, str) else None
    require(fields is not None, 'Unsupported file envelope kind')
    expected = fields - {'data'} if projection and kind == 'file_chunk' else fields
    require(payload.keys() == expected, 'File envelope fields do not match schema')
    require(isinstance(payload.get('transfer_id'), str) and bool(_ID.fullmatch(payload['transfer_id'])),
            'File transfer ID is invalid')
    if 'sha256' in fields:
        require(isinstance(payload.get('sha256'), str) and bool(_DIGEST.fullmatch(payload['sha256'])),
                'File SHA-256 digest is invalid')
    if 'size' in fields:
        integer('size', 1, MAX_FILE_BYTES)
    if kind == 'file_offer':
        text('filename', 255)
        require(payload['filename'] not in {'.', '..'} and
                not any(c in payload['filename'] for c in '/\\:'), 'File name must be a safe basename')
        require(isinstance(payload.get('media_type'), str) and payload['media_type'] in _MEDIA, 'Unsupported image media type')
        integer('chunk_size', CHUNK_BYTES, CHUNK_BYTES)
    elif kind == 'file_decision':
        require(payload.get('decision') in ('accept', 'reject'), 'Invalid file decision')
        text('reason', 255)
    elif kind == 'file_chunk':
        integer('index', 0, (MAX_FILE_BYTES - 1) // CHUNK_BYTES)
        integer('offset', 0, MAX_FILE_BYTES - 1)
        require(payload['offset'] == payload['index'] * CHUNK_BYTES, 'File chunk offset is invalid')
        integer('byte_count', 1, CHUNK_BYTES)
        require(payload['offset'] + payload['byte_count'] <= MAX_FILE_BYTES, 'File chunk exceeds file bound')
        if not projection:
            value = payload.get('data')
            require(isinstance(value, str) and len(value) <= 4*((CHUNK_BYTES+2)//3), 'File data exceeds bounds')
            decode_base64(value, payload['byte_count'])
    elif kind == 'file_chunk_ack':
        integer('index', 0, (MAX_FILE_BYTES-1)//CHUNK_BYTES)
        require(payload.get('status') == 'stored', 'Invalid file chunk acknowledgment')
    elif kind == 'file_result':
        require(payload.get('status') == 'verified', 'Invalid file completion result')
    elif kind == 'file_cancel':
        text('reason', 255)
