"""Canonicalization is the highest-risk detail, so it gets tested adversarially.

If two implementations can disagree about the bytes to sign, every other
guarantee in the system is decorative.
"""

import json

import pytest

import verify_episode
from fr import canon


def test_key_order_does_not_change_the_bytes():
    a = {"zulu": 1, "alpha": 2, "mike": {"z": 1, "a": 2}}
    b = {"alpha": 2, "mike": {"a": 2, "z": 1}, "zulu": 1}
    assert canon.dumps(a) == canon.dumps(b)
    assert canon.dumps(a) == b'{"alpha":2,"mike":{"a":2,"z":1},"zulu":1}'


def test_keys_sort_by_code_point_not_locale():
    value = {"a": 1, "A": 2, "\u00e4": 3, "z": 4, "Z": 5}
    assert canon.dumps(value) == '{"A":2,"Z":5,"a":1,"z":4,"ä":3}'.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        {"score": 0.873},
        {"nested": {"list": [1, 2, 3.5]}},
        [[[{"deep": 1e10}]]],
    ],
)
def test_floats_are_banned(value):
    with pytest.raises(canon.SchemaError):
        canon.dumps(value)


def test_integer_milli_units_are_the_replacement_for_floats():
    assert canon.dumps({"score_milli": 873}) == b'{"score_milli":873}'


def test_integers_beyond_int64_are_rejected():
    with pytest.raises(canon.SchemaError):
        canon.dumps({"n": 2**63})


def test_duplicate_keys_are_a_hard_reject():
    with pytest.raises(canon.SchemaError):
        canon.loads('{"a":1,"a":2}')


def test_nan_and_infinity_are_rejected():
    for text in ('{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}'):
        with pytest.raises(canon.SchemaError):
            canon.loads(text)


def test_non_ascii_round_trips_as_real_utf8():
    value = {"text": "vendör onbøarding ✓ 日本語 🛫"}
    raw = canon.dumps(value)
    assert b"\\u" not in raw
    assert canon.loads(raw) == value


@pytest.mark.parametrize("text", ["a b", "a\tb", "a\nb", "a\rb", "\u0000", "\u007f", "  "])
def test_whitespace_and_control_characters_survive(text):
    value = {"text": text}
    assert canon.loads(canon.dumps(value)) == value


def test_deeply_nested_structure_is_stable():
    value = {"a": 1}
    for i in range(60):
        value = {"k%d" % i: [value, {"z": i, "a": None, "flag": True}]}
    assert canon.assert_stable(value) == canon.dumps(value)


def test_lone_surrogate_is_unstable_not_merely_invalid():
    # It parses. It has no UTF-8 encoding. That is CANON_UNSTABLE, not SCHEMA_INVALID.
    value = canon.loads('{"text":"pol\\ud800"}')
    with pytest.raises(canon.UnstableError):
        canon.dumps(value)


def test_booleans_and_null_are_not_confused_with_integers():
    assert canon.dumps({"a": True, "b": False, "c": None}) == b'{"a":true,"b":false,"c":null}'


def test_verifier_agrees_with_the_library_byte_for_byte():
    """The independent reimplementation is only useful if it is checked against."""
    samples = [
        {"alpha": 1, "zulu": [1, 2, {"b": None, "a": True}]},
        {"text": "vendör ✓", "score_milli": -873, "ok": False},
        {"": {"": {"": []}}},
        {"ts_ns": 1785312862123456789, "seq": 0},
    ]
    for value in samples:
        assert canon.dumps(value) == verify_episode.canonical(value)


def test_verifier_rejects_the_same_things_the_library_does():
    for text in ('{"a":1,"a":2}', '{"a":1.5}', '{"a":NaN}'):
        with pytest.raises(canon.SchemaError):
            canon.loads(text)
        with pytest.raises(verify_episode.Fail) as exc:
            verify_episode.parse(text)
        assert exc.value.code == "SCHEMA_INVALID"


def test_pretty_on_disk_form_parses_to_the_same_canonical_bytes():
    body = {"v": 1, "seq": 3, "payload": {"b": 1, "a": [1, {"y": 2, "x": 3}]}}
    pretty = json.dumps(body, indent=4, sort_keys=False, ensure_ascii=True)
    assert canon.dumps(canon.loads(pretty)) == canon.dumps(body)
