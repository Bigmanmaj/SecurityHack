import pytest
from dilithium_py.ml_dsa import ML_DSA_65

from attest.canonical import CanonicalizationError, canonical_bytes
from attest.keys import (
    SIGNER_IDS,
    generate_keypair,
    load_trust_dir,
    sign_payload,
    verify_payload,
    write_public_key,
)


def test_signer_ids_are_the_four_spec_roles():
    assert set(SIGNER_IDS) == {"recorder", "anchor-1", "investigator", "anchor-2"}


def test_sign_then_verify_round_trip(keyring):
    public_key, secret_key = keyring["recorder"]
    payload = {"type": "answer", "seq": 3, "ts": "2026-01-01T00:00:00Z"}
    signature = sign_payload(secret_key, payload)
    assert verify_payload(public_key, payload, signature)


def test_signature_is_lowercase_hex(keyring):
    _, secret_key = keyring["recorder"]
    signature = sign_payload(secret_key, {"a": 1})
    assert signature == signature.lower()
    assert bytes.fromhex(signature)


def test_signature_is_over_canonical_bytes(keyring):
    public_key, secret_key = keyring["recorder"]
    payload = {"b": 2, "a": 1}
    signature = sign_payload(secret_key, payload)
    assert ML_DSA_65.verify(public_key, canonical_bytes(payload), bytes.fromhex(signature))
    # Key order is not part of the canonical form, so the signature still checks out.
    assert verify_payload(public_key, {"a": 1, "b": 2}, signature)


def test_verify_rejects_tampered_payload(keyring):
    public_key, secret_key = keyring["recorder"]
    signature = sign_payload(secret_key, {"tool": "shell", "seq": 1})
    assert not verify_payload(public_key, {"tool": "shell", "seq": 2}, signature)


def test_verify_rejects_signature_from_another_signer(keyring):
    payload = {"type": "attribution", "seq": 4}
    signature = sign_payload(keyring["investigator"][1], payload)
    assert not verify_payload(keyring["recorder"][0], payload, signature)


@pytest.mark.parametrize("bad", ["", "zz", "abc", "00" * 3309])
def test_verify_returns_false_for_unusable_signature_hex(keyring, bad):
    public_key, _ = keyring["recorder"]
    assert not verify_payload(public_key, {"a": 1}, bad)


def test_verify_propagates_canonicalization_errors(keyring):
    public_key, secret_key = keyring["recorder"]
    signature = sign_payload(secret_key, {"a": 1})
    with pytest.raises(CanonicalizationError):
        verify_payload(public_key, {"a": 1.5}, signature)


def test_sign_payload_rejects_floats(keyring):
    _, secret_key = keyring["recorder"]
    with pytest.raises(CanonicalizationError):
        sign_payload(secret_key, {"latency": 1.5})


def test_write_public_key_writes_hex_named_by_signer(tmp_path, keyring):
    public_key, _ = keyring["anchor-1"]
    path = write_public_key(tmp_path / "trust", "anchor-1", public_key)
    assert path.name == "anchor-1.pub.hex"
    assert bytes.fromhex(path.read_text().strip()) == public_key


def test_write_public_key_refuses_unknown_signer(tmp_path, keyring):
    public_key, _ = keyring["recorder"]
    with pytest.raises(ValueError):
        write_public_key(tmp_path / "trust", "attacker", public_key)


def test_load_trust_dir_returns_every_public_key(trust_dir, keyring):
    trusted = load_trust_dir(trust_dir)
    assert set(trusted) == set(SIGNER_IDS)
    assert trusted["recorder"] == keyring["recorder"][0]


def test_load_trust_dir_tolerates_trailing_whitespace(tmp_path, keyring):
    public_key, _ = keyring["recorder"]
    directory = tmp_path / "trust"
    directory.mkdir()
    (directory / "recorder.pub.hex").write_text(public_key.hex() + "\n\n")
    assert load_trust_dir(directory)["recorder"] == public_key


def test_load_trust_dir_ignores_other_files(trust_dir):
    (trust_dir / "README.txt").write_text("not a key")
    (trust_dir / "recorder.pub.hex.bak").write_text("dead")
    assert set(load_trust_dir(trust_dir)) == set(SIGNER_IDS)


def test_load_trust_dir_raises_on_missing_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_trust_dir(tmp_path / "nope")


def test_load_trust_dir_raises_on_unreadable_key(tmp_path):
    directory = tmp_path / "trust"
    directory.mkdir()
    (directory / "recorder.pub.hex").write_text("not hex")
    with pytest.raises(ValueError):
        load_trust_dir(directory)


def test_load_trust_dir_raises_on_a_wrong_length_key(tmp_path, keyring):
    directory = tmp_path / "trust"
    directory.mkdir()
    (directory / "recorder.pub.hex").write_text(keyring["recorder"][0][:100].hex())
    with pytest.raises(ValueError):
        load_trust_dir(directory)


@pytest.mark.parametrize("truncate", [0, 100, 1951])
def test_verify_returns_false_for_an_unusable_public_key(keyring, truncate):
    public_key, secret_key = keyring["recorder"]
    signature = sign_payload(secret_key, {"a": 1})
    assert not verify_payload(public_key[:truncate], {"a": 1}, signature)


def test_secret_key_never_reaches_the_trust_dir(trust_dir, secret_keys):
    published = "".join(path.read_text() for path in trust_dir.iterdir())
    for secret_key in secret_keys.values():
        assert secret_key.hex() not in published


def test_generate_keypair_returns_distinct_keys():
    (public_a, secret_a), (public_b, secret_b) = generate_keypair(), generate_keypair()
    assert public_a != public_b and secret_a != secret_b
    assert not verify_payload(public_b, {"a": 1}, sign_payload(secret_a, {"a": 1}))
