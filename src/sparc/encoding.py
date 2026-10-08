"""Strict JSON parsing and canonical encoding for signed SPARC data."""

import json
from typing import Any

from .models import SparcError


class _DuplicateKey(ValueError):
    pass


def _validate(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SparcError("invalid_json_value", f"{path} contains a non-string object key")
            _validate(key, f"{path} key")
            _validate(item, f"{path}.{key}")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SparcError("invalid_json_value", f"{path} contains invalid Unicode") from exc
        return
    if isinstance(value, bool) or value is None:
        raise SparcError("invalid_json_value", f"{path} has an unsupported JSON value")
    if isinstance(value, int):
        return
    if isinstance(value, (float, complex)):
        raise SparcError("invalid_json_value", f"{path} has an unsupported numeric value")
    raise SparcError("invalid_json_value", f"{path} has an unsupported value type")


def canonical(value: dict) -> bytes:
    """Return the exact canonical UTF-8 JSON representation of an object."""
    try:
        if not isinstance(value, dict):
            raise SparcError("invalid_json_value", "JSON root must be an object")
        _validate(value)
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        return text.encode("utf-8")
    except SparcError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SparcError("invalid_json_value", "Value cannot be encoded as canonical JSON") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant {value}")


def _reject_float(value: str) -> None:
    raise ValueError("floating point values are not permitted")


def parse_object(raw: bytes) -> dict:
    """Parse a JSON object while rejecting duplicate keys and unsupported values."""
    if not isinstance(raw, bytes):
        raise SparcError("invalid_json", "JSON input must be bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
        if not isinstance(value, dict):
            raise SparcError("invalid_json", "JSON root must be an object")
        _validate(value)
        return value
    except _DuplicateKey as exc:
        raise SparcError("duplicate_json_key", "JSON object contains a duplicate key") from exc
    except SparcError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SparcError("invalid_json", "Input is not a valid supported JSON object") from exc
