import pytest

from attest.keys import SIGNER_IDS, generate_keypair, write_public_key


@pytest.fixture(scope="session")
def keyring():
    """One ML-DSA-65 keypair per signer id, generated once for the whole session."""
    return {signer_id: generate_keypair() for signer_id in SIGNER_IDS}


@pytest.fixture
def trust_dir(tmp_path, keyring):
    """A verifier-side trust directory holding the public key of every signer."""
    directory = tmp_path / "trust"
    for signer_id, (public_key, _) in keyring.items():
        write_public_key(directory, signer_id, public_key)
    return directory


@pytest.fixture
def secret_keys(keyring):
    """Signing keys, in memory only, keyed by signer id."""
    return {signer_id: secret_key for signer_id, (_, secret_key) in keyring.items()}
