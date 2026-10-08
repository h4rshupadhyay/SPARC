import pytest


def test_canonical_exact_bytes():
    from sparc.encoding import canonical

    assert canonical({"b": 2, "a": "✓"}) == b'{"a":"\\u2713","b":2}'


@pytest.mark.parametrize(
    "value",
    [
        [],
        "text",
        {1: "non-string key"},
        {"items": [1]},
        {"value": True},
        {"value": False},
        {"value": None},
        {"value": 1.25},
        {"nested": {"value": float("nan")}},
        {"nested": {"value": float("inf")}},
        {"value": "\ud800"},
    ],
)
def test_canonical_rejects_values_outside_json_contract(value):
    from sparc.encoding import canonical
    from sparc.models import SparcError

    with pytest.raises(SparcError):
        canonical(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'"text"',
        b'{"items":[1]}',
        b'{"value":true}',
        b'{"value":false}',
        b'{"value":null}',
        b'{"value":1.25}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"a":1,"a":2}',
        b'{"outer":{"a":1,"a":2}}',
        b"{\"value\":\xff}",
        b'{"value":"\\ud800"}',
        b'{"value":1} trailing',
    ],
)
def test_parse_object_rejects_invalid_json_types_and_syntax(raw):
    from sparc.encoding import parse_object
    from sparc.models import SparcError

    with pytest.raises(SparcError):
        parse_object(raw)


def test_parse_object_accepts_noncanonical_bytes_and_preserves_unicode():
    from sparc.encoding import parse_object

    assert parse_object(b'{ "z" : 2, "text" : "e\\u0301" }') == {
        "z": 2,
        "text": "e\u0301",
    }


def test_canonical_preserves_unicode_without_normalization():
    from sparc.encoding import canonical

    assert canonical({"text": "e\u0301"}) == b'{"text":"e\\u0301"}'
