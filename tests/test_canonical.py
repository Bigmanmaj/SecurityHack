import json

import pytest

from attest.canonical import CanonicalizationError, canonical_bytes


def test_keys_are_sorted_and_separators_are_compact():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_sorting_is_recursive():
    obj = {"z": {"y": 1, "x": [{"b": True, "a": None}]}}
    assert canonical_bytes(obj) == b'{"z":{"x":[{"a":null,"b":true}],"y":1}}'


def test_non_ascii_is_not_escaped():
    assert canonical_bytes({"k": "café"}) == '{"k":"café"}'.encode("utf-8")


def test_scalars_and_containers_round_trip():
    for obj in [{}, [], "", "x", 0, -17, True, False, None, [1, [2, [3]]]]:
        assert json.loads(canonical_bytes(obj).decode("utf-8")) == obj


def test_large_int_is_allowed():
    assert canonical_bytes({"n": 2**70}) == b'{"n":%d}' % 2**70


@pytest.mark.parametrize(
    "obj",
    [
        1.0,
        {"a": 0.5},
        {"a": {"b": [1, 2, 3.5]}},
        [[[-0.0]]],
        {"a": float("nan")},
        {"a": float("inf")},
    ],
)
def test_any_float_anywhere_is_rejected(obj):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(obj)


@pytest.mark.parametrize(
    "obj",
    [
        b"bytes",
        (1, 2),
        {1, 2},
        {"a": b"bytes"},
        {"a": (1, 2)},
        [object()],
    ],
)
def test_disallowed_types_are_rejected(obj):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(obj)


def test_non_string_dict_keys_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: "a"})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({True: "a"})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"ok": {None: "a"}})


def test_error_message_points_at_the_offending_path():
    with pytest.raises(CanonicalizationError) as excinfo:
        canonical_bytes({"a": {"b": [0, 1.5]}})
    assert "$.a.b[1]" in str(excinfo.value)
