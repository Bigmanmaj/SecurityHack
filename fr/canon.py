"""Canonical JSON: the bytes that get signed.

The whole system rests on an independent implementation being able to reproduce
these bytes exactly. The rules are chosen to make that boring rather than clever:

1. UTF-8, no BOM.
2. Object keys sorted by Unicode code point.
3. Separators exactly ``,`` and ``:`` -- no whitespace.
4. ``ensure_ascii=False`` -- emit real UTF-8, never ``\\uXXXX`` escapes.
5. Floats are banned at write time and rejected at verify time. Integers only:
   scores are integer milli-units, timestamps integer nanoseconds. This deletes
   the entire hardest half of RFC 8785 (number formatting) along with any
   float-repr drift between languages.
6. Duplicate object keys are a hard reject.
7. No NaN/Infinity, no leading zeros, no -0.
"""

import json

# Integers must survive a round-trip through any sane JSON implementation,
# including ones that back numbers with int64. Anything wider is rejected at the
# door rather than silently becoming a float somewhere else.
INT_MAX = 2**63 - 1
INT_MIN = -(2**63)


class CanonError(ValueError):
    """Base class: this value cannot be canonicalized."""


class SchemaError(CanonError):
    """Rejected by the value rules (float, bad type, duplicate key)."""


class UnstableError(CanonError):
    """Parses, but does not survive a canonicalize/parse round trip."""


def _reject_float(text):
    raise SchemaError(f"float literal banned in canonical JSON: {text!r}")


def _reject_constant(text):
    raise SchemaError(f"JSON constant banned in canonical JSON: {text!r}")


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SchemaError(f"duplicate object key: {key!r}")
        out[key] = value
    return out


def loads(data):
    """Parse JSON under the canonical rules (floats and duplicate keys raise)."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    try:
        return json.loads(
            data,
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise SchemaError(f"not valid JSON: {exc}") from exc


def validate(value, path="$"):
    """Recursively assert that ``value`` is representable in canonical JSON."""
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not INT_MIN <= value <= INT_MAX:
            raise SchemaError(f"{path}: integer out of int64 range: {value}")
        return
    if isinstance(value, float):
        raise SchemaError(f"{path}: floats are banned; use integer milli-units")
    if isinstance(value, list):
        for i, item in enumerate(value):
            validate(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SchemaError(f"{path}: object key must be a string, got {type(key).__name__}")
            validate(item, f"{path}.{key}")
        return
    raise SchemaError(f"{path}: unsupported type {type(value).__name__}")


def dumps(value):
    """Canonical UTF-8 bytes for ``value``. These are the bytes that get signed."""
    validate(value)
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        check_circular=True,
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        # Lone surrogates parse fine but have no UTF-8 encoding, so no two
        # implementations could ever agree on the bytes to sign.
        raise UnstableError(f"value is not encodable as UTF-8: {exc}") from exc


def assert_stable(value):
    """Canonicalize, re-parse, re-canonicalize, and require byte equality."""
    once = dumps(value)
    twice = dumps(loads(once))
    if once != twice:
        raise UnstableError("canonical form is not idempotent")
    return once


def canonical(value):
    """Alias for :func:`dumps`, spelled the way the spec talks about it."""
    return dumps(value)
