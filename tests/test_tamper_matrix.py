"""The acceptance test for the whole project.

One row per reason code in the taxonomy: mutate a good episode exactly one way,
assert the verifier comes back with exactly that code. If this file is green, the
project works.
"""

import json
import os

import pytest

import verify_episode
from conftest import BLOB_TEXT, TEST_SEED0, blob_digest, build_episode
from demo import adversary as adv
from demo import attacks
from fr import reasons
from fr.hashes import sha3_hex
from fr.recorder import RECORDS_DIRNAME


def verify_expecting(root, code):
    with pytest.raises(verify_episode.Fail) as exc:
        verify_episode.verify(root)
    fail = exc.value
    assert fail.code == code, f"expected {code}, got {fail.code}: {fail.detail}"
    assert fail.detail, "every failure must carry a human-readable detail"
    return fail


def test_good_episode_is_green(episode):
    summary = verify_episode.verify(episode)
    assert summary["count"] == 9
    assert summary["types"][0] == "GENESIS"
    assert summary["types"][-1] == "SEAL"


# --- raw edits: no key required, and no signature survives them ------------

def test_signature_invalid(episode):
    adv.raw_edit(episode, 3, b"a summary with", b"a summarz with")
    fail = verify_expecting(episode, reasons.SIGNATURE_INVALID)
    assert fail.seq == 3
    assert fail.path.endswith("000003.json")


def test_schema_invalid_float(episode):
    adv.raw_edit(episode, 5, b'"score_milli": 874', b'"score_milli": 87.4')
    verify_expecting(episode, reasons.SCHEMA_INVALID)


def test_schema_invalid_unknown_type(episode):
    adv.raw_edit(episode, 5, b'"type": "REPLAY_RUN"', b'"type": "SOMETHING_ELSE"')
    verify_expecting(episode, reasons.SCHEMA_INVALID)


def test_schema_invalid_duplicate_key(episode):
    adv.raw_edit(episode, 5, b'"run": 1,', b'"run": 1,\n      "run": 2,')
    verify_expecting(episode, reasons.SCHEMA_INVALID)


def test_schema_invalid_missing_field(episode):
    path = adv.record_path(episode, 5)
    entry = adv.load_record(episode, 5)
    del entry["body"]["actor"]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(entry, fh, indent=2)
    verify_expecting(episode, reasons.SCHEMA_INVALID)


def test_canon_unstable(episode):
    # A lone surrogate parses as JSON but has no UTF-8 encoding, so no two
    # implementations could ever agree on the bytes to sign.
    adv.raw_edit(episode, 1, b'"summarize the policy"', b'"summarize the pol\\ud800"')
    verify_expecting(episode, reasons.CANON_UNSTABLE)


def test_blob_hash_mismatch(episode):
    adv.swap_blob(episode, blob_digest(), b"an innocent-looking prompt")
    fail = verify_expecting(episode, reasons.BLOB_HASH_MISMATCH)
    assert fail.seq == 2


def test_blob_deleted(episode):
    os.remove(os.path.join(episode, "blobs", blob_digest() + ".bin"))
    verify_expecting(episode, reasons.BLOB_HASH_MISMATCH)


# --- file-level surgery ---------------------------------------------------

def test_sequence_gap(episode):
    adv.delete_record(episode, 4)
    verify_expecting(episode, reasons.SEQUENCE_GAP)


def test_duplicate_seq(episode):
    adv.duplicate_record(episode, 4)
    verify_expecting(episode, reasons.DUPLICATE_SEQ)


def test_truncated_tail_seal_removed(episode):
    adv.truncate_tail(episode, 8)
    fail = verify_expecting(episode, reasons.TRUNCATED_TAIL)
    assert fail.expected == "SEAL"


def test_truncated_tail_count_disagrees(episode):
    # Chop back past the SEAL: the remaining records verify perfectly, and the
    # count in the SEAL is what gives the truncation away.
    adv.truncate_tail(episode, 7)
    verify_expecting(episode, reasons.TRUNCATED_TAIL)


def test_anchor_mismatch(episode):
    adv.swap_anchor(episode)
    verify_expecting(episode, reasons.ANCHOR_MISMATCH)


def test_anchor_missing(episode):
    os.remove(os.path.join(episode, "anchor.pub"))
    verify_expecting(episode, reasons.ANCHOR_MISMATCH)


# --- key compromise at record k: the attack that "just sign it" loses to ---

def test_chain_break(episode):
    adv.resign(episode, 4, lambda b: b.update(prev=sha3_hex(b"a history that never happened")),
               seed0=TEST_SEED0)
    fail = verify_expecting(episode, reasons.CHAIN_BREAK)
    assert fail.seq == 4


def test_ratchet_mismatch(episode):
    # Re-sign with a fresh key the chain never committed to.
    adv.resign(episode, 4, lambda b: b["payload"].update(score_milli=0),
               seed0=TEST_SEED0, forged_seed=bytes(32))
    verify_expecting(episode, reasons.RATCHET_MISMATCH)


def test_episode_mismatch(episode):
    adv.resign(episode, 4, lambda b: b.update(episode="ep-19700101T000000Z-dead"),
               seed0=TEST_SEED0)
    verify_expecting(episode, reasons.EPISODE_MISMATCH)


def test_timestamp_regression(episode):
    adv.resign(episode, 4, lambda b: b.update(ts_ns=1), seed0=TEST_SEED0)
    verify_expecting(episode, reasons.TIMESTAMP_REGRESSION)


def test_seal_misplaced(tmp_path):
    root = build_investigated_episode(tmp_path)
    open_seq = _seq_of(root, "INVESTIGATION_OPEN")
    adv.resign(root, open_seq,
               lambda b: b["payload"].update(parent_head=sha3_hex(b"some other head")),
               seed0=TEST_SEED0)
    verify_expecting(root, reasons.SEAL_MISPLACED)


def test_seal_misplaced_wrong_follower(tmp_path):
    root = build_investigated_episode(tmp_path)
    open_seq = _seq_of(root, "INVESTIGATION_OPEN")
    payload = adv.load_record(root, open_seq)["body"]["payload"]
    adv.resign(root, open_seq,
               lambda b: b.update(type="ANCHOR",
                                  payload={"count": open_seq, "head_hash": payload["parent_head"],
                                           "alg": "ML-DSA-65"}),
               seed0=TEST_SEED0)
    verify_expecting(root, reasons.SEAL_MISPLACED)


def test_reopened_episode_is_green(tmp_path):
    root = build_investigated_episode(tmp_path)
    summary = verify_episode.verify(root)
    assert len(summary["seals"]) == 2
    assert summary["types"][-1] == "SEAL"


# --- the residual gap, stated as a test rather than discovered on stage -----

def test_truncating_back_to_an_earlier_seal_verifies_and_that_is_the_known_limit(tmp_path):
    """Chopping the whole investigation leaves a chain that is internally perfect.

    Intra-file sealing cannot catch this: the earlier SEAL's count matches the
    files that remain. Only a witness held outside the operator's reach can.
    """
    root = build_investigated_episode(tmp_path)
    full = verify_episode.verify(root)
    first_seal = full["seals"][0]
    adv.truncate_tail(root, first_seal + 1)

    shortened = verify_episode.verify(root)
    assert shortened["count"] == first_seal + 1
    assert shortened["seals"] == [first_seal]

    with pytest.raises(verify_episode.Fail) as exc:
        verify_episode.verify(root, expect_count=full["count"])
    assert exc.value.code == reasons.TRUNCATED_TAIL

    with pytest.raises(verify_episode.Fail) as exc:
        verify_episode.verify(root, expect_head=full["head_hash"])
    assert exc.value.code == reasons.TRUNCATED_TAIL


def test_a_wholly_substituted_chain_needs_a_published_anchor_to_catch(tmp_path):
    """anchor.pub lives in the directory the operator controls.

    Regenerating the episode from a fresh seed and rewriting anchor.pub produces a
    chain that verifies against itself. It does not verify against the anchor the
    episode was published under.
    """
    original = str(tmp_path / "original")
    build_episode(original)
    published = verify_episode.verify(original)["anchor"]

    substituted = str(tmp_path / "substituted")
    build_episode(substituted, seed0=bytes([7] * 32))
    verify_episode.verify(substituted)

    with pytest.raises(verify_episode.Fail) as exc:
        verify_episode.verify(substituted, expect_anchor=published)
    assert exc.value.code == reasons.ANCHOR_MISMATCH


def test_a_matching_witness_stays_green(episode):
    summary = verify_episode.verify(episode)
    verify_episode.verify(episode, expect_anchor=summary["anchor"],
                          expect_head=summary["head_hash"], expect_count=summary["count"])


def test_every_reason_code_has_a_row():
    """Guard against a reason code that exists in the taxonomy but is never tested."""
    source = open(os.path.join(os.path.dirname(__file__), "test_tamper_matrix.py")).read()
    untested = [code for code in reasons.ALL if f"reasons.{code}" not in source]
    assert not untested, f"reason codes with no tamper-matrix row: {untested}"


# --- the attack menu the web UI renders, proven one entry at a time --------

def episode_target(root, foreign_root=None):
    bodies = verify_episode.verify(root)["bodies"]
    foreign = None
    if foreign_root:
        foreign = verify_episode.verify(foreign_root)["episode"]
    return attacks.Target(root=root, episode=bodies[0]["episode"], count=len(bodies),
                          bodies=bodies, foreign_root=foreign_root, foreign_episode=foreign)


@pytest.mark.parametrize("attack", attacks.ATTACKS, ids=lambda a: a.key)
def test_every_menu_attack_produces_the_reason_code_it_claims(attack, tmp_path):
    """The web UI renders this registry as buttons. Each button's promise is a test.

    If an attack's declared reason code drifts from what the verifier actually
    returns, the demo would be lying to a judge. This is the test that stops that.
    """
    root = str(tmp_path / "episode")
    foreign = str(tmp_path / "foreign")
    rag_style_episode(root)
    rag_style_episode(foreign)

    target = episode_target(root, foreign_root=foreign)
    seq, note = attacks.apply(attack.key, target)
    assert note, "every attack must explain what it did"

    verify_expecting(root, attack.reason)
    assert isinstance(seq, int)


def test_the_menu_covers_the_whole_taxonomy():
    declared = {attack.reason for attack in attacks.ATTACKS}
    missing = [code for code in reasons.ALL if code not in declared]
    assert not missing, f"reason codes the attack menu cannot demonstrate: {missing}"


def test_menu_attacks_that_need_a_live_key_say_so_instead_of_failing_quietly(tmp_path):
    root = str(tmp_path / "closed")
    rag_style_episode(root)
    os.remove(os.path.join(root, ".recorder-state.json"))  # append-closed, like golden
    target = episode_target(root)

    for attack in attacks.ATTACKS:
        if attack.requires != attacks.NEEDS_LIVE_KEY:
            continue
        with pytest.raises(attacks.AttackUnavailable, match="no live key"):
            attacks.apply(attack.key, target)


def test_splicing_from_itself_is_refused_rather_than_shown_as_a_no_op(tmp_path):
    root = str(tmp_path / "solo")
    rag_style_episode(root)
    target = episode_target(root, foreign_root=root)
    with pytest.raises(attacks.AttackUnavailable, match="nothing foreign"):
        attacks.apply("splice_episode", target)


def rag_style_episode(root):
    """A real agent episode: the attacks target TOOL_CALL, RETRIEVAL, and blobs."""
    from agent import rag

    rag.run_episode(root, scenario="poisoned", backend_name="mock")
    return root


# --- helpers --------------------------------------------------------------

def build_investigated_episode(tmp_path):
    """A sealed episode that was reopened, extended, and resealed."""
    from fr import Recorder
    from fr import record as R

    root = str(tmp_path / "episode")
    rec = build_episode(root)
    seal_head = json.loads(open(adv.record_path(root, rec.count - 1)).read())["body"]["payload"]["head_hash"]

    rec2 = Recorder.reopen(root, actor="investigator:test@1")
    rec2.reopen_after_seal()
    rec2.append(R.INVESTIGATION_OPEN, {"parent_head": seal_head, "investigator": "test/0.1",
                                       "method": "none"})
    rec2.append(R.REPLAY_RUN, {"run": 0, "violation": False})
    rec2.seal("normal")
    return root


def _seq_of(root, type_):
    records = os.path.join(root, RECORDS_DIRNAME)
    for name in sorted(os.listdir(records)):
        with open(os.path.join(records, name), "r", encoding="utf-8") as fh:
            body = json.load(fh)["body"]
        if body["type"] == type_:
            return body["seq"]
    raise AssertionError(f"no {type_} record in {root}")


def test_blob_text_is_referenced(episode):
    assert os.path.exists(os.path.join(episode, "blobs", blob_digest() + ".bin"))
    with open(os.path.join(episode, "blobs", blob_digest() + ".bin"), "rb") as fh:
        assert fh.read() == BLOB_TEXT
