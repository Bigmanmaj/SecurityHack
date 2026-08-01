"""The one and only serialization that is ever hashed or signed (SPEC.md)."""

import json


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized: a float or a disallowed type."""


def canonical_bytes(obj):
    """Serialize ``obj`` to the canonical byte string defined by SPEC.md.

    Allowed types are dict (str keys), list, str, int, bool and None. A float
    anywhere in the structure raises CanonicalizationError, because floats have
    no stable cross-platform decimal form and would break hash reproducibility.
    """
    _check(obj, "$")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _check(obj, path):
    if isinstance(obj, float):
        raise CanonicalizationError(f"float at {path}: floats are never canonicalizable")
    if obj is None or isinstance(obj, (bool, int, str)):
        return
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            _check(item, f"{path}[{index}]")
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str) or isinstance(key, bool):
                raise CanonicalizationError(f"non-string key {key!r} at {path}")
            _check(value, f"{path}.{key}")
        return
    raise CanonicalizationError(f"disallowed type {type(obj).__name__} at {path}")
