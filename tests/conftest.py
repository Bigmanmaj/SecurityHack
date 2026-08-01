import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fr import Recorder, genesis_payload  # noqa: E402
from fr import record as R  # noqa: E402

# A fixed seed so tests can play the part of an attacker who compromised the
# machine at record k and holds seed_k. Real episodes seed from os.urandom.
TEST_SEED0 = bytes(range(32))

BLOB_TEXT = b"a large payload: the full assembled prompt, stored out of line\n"


def build_episode(root, seed0=TEST_SEED0, records=8, seal=True):
    """A small synthetic episode with a blob reference and a terminal SEAL."""
    rec = Recorder.open_new(root, actor="agent:test-harness@1", seed=seed0)
    rec.append(
        R.GENESIS,
        genesis_payload(
            agent_version="test/0.1",
            model_id="mock",
            params={"temperature_milli": 0},
            tool_allowlist=["search_docs", "read_doc"],
            corpus_manifest=[{"doc_id": "doc-01.md", "sha3": "0" * 64, "bytes": 12}],
            task="synthetic episode",
        ),
    )
    rec.append(R.USER_INPUT, {"text": "summarize the policy"})
    ref = rec.put_blob(BLOB_TEXT)
    rec.append(R.LLM_CALL, {"model": "mock", "prompt": ref, "params": {"temperature_milli": 0}})
    rec.append(R.LLM_RESPONSE, {"text": "a summary with ünicode ✓ and \"quotes\""})
    for i in range(max(0, records - 5)):
        rec.append(R.REPLAY_RUN, {"run": i, "score_milli": 873 + i})
    rec.append(R.AGENT_FINAL, {"text": "done"})
    if seal:
        rec.seal("normal")
    return rec


def blob_digest():
    from fr.hashes import blob_hash

    return blob_hash(BLOB_TEXT)


@pytest.fixture
def episode(tmp_path):
    root = str(tmp_path / "episode")
    build_episode(root)
    return root
