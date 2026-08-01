"""C2: `verify_episode` against SPEC.md §5, and the CLI around it.

Every bundle here is built by `tests/bundles.py` from the spec text plus
`dilithium_py`, so the verifier is never checked against the code that produced
the thing it is verifying.
"""

import json
import subprocess
import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

from verifier.verify import verify_episode

from .bundles import BundleBuilder, MANIFEST_PAYLOAD, valid_bundle
from .vectors import canon, h, signed_message

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verifier" / "verify_cli.py"


def reasons_for(builder) -> list[str]:
    ok, reasons = verify_episode(builder.episode, builder.trust)
    assert ok == (reasons == [])
    return reasons


def tokens(reasons) -> set[str]:
    return {reason.split(":")[0] for reason in reasons}


# -- the happy path ----------------------------------------------------------


def test_a_well_formed_bundle_is_green(tmp_path):
    builder = valid_bundle(tmp_path)

    ok, reasons = verify_episode(builder.episode, builder.trust)

    assert reasons == []
    assert ok is True


def test_a_bundle_with_two_anchors_over_prefixes_is_green(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.add("attribution", {"method": "single-chunk-ablation"}, signer="investigator")
    builder.anchor("anchor-2")

    assert reasons_for(builder) == []


def test_paths_may_be_strings_or_path_objects(tmp_path):
    builder = valid_bundle(tmp_path)

    ok, _ = verify_episode(str(builder.episode), str(builder.trust))

    assert ok is True


# -- per record (SPEC 5.1) ---------------------------------------------------


def test_editing_a_payload_reports_hash_mismatch_and_bad_signature(tmp_path):
    builder = valid_bundle(tmp_path)
    record = builder.read_record(2)
    record["payload"]["args_hash"] = "f" + record["payload"]["args_hash"][1:]
    builder.write_record(record)

    reasons = reasons_for(builder)

    assert tokens(reasons) == {"HASH_MISMATCH", "BAD_SIGNATURE"}
    assert all("00002.json" in reason for reason in reasons)


def test_repairing_the_hash_after_editing_still_fails(tmp_path):
    """The obvious next move for a tamperer: recompute the hash they broke.

    That trades HASH_MISMATCH for a leaf the anchor never covered, so the
    signature and the root both give them away.
    """
    builder = valid_bundle(tmp_path)
    record = builder.read_record(3)
    record["payload"]["answer_hash"] = h(canon("a different answer"))
    record["payload_hash"] = h(canon(record["payload"]))
    builder.write_record(record)

    assert tokens(reasons_for(builder)) == {"BAD_SIGNATURE", "ROOT_MISMATCH"}


def test_a_signer_with_no_trusted_key_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.unpublish("recorder")

    reasons = reasons_for(builder)

    assert tokens(reasons) == {"UNKNOWN_SIGNER"}
    assert any("recorder" in reason for reason in reasons)
    assert len(reasons) == 4, "one per record, and no cascade into BAD_SIGNATURE"


def test_a_signature_from_the_wrong_key_is_rejected(tmp_path):
    builder = valid_bundle(tmp_path)
    _, other_secret = ML_DSA_65.keygen()
    record = builder.read_record(1)
    record["sig"] = ML_DSA_65.sign(
        other_secret,
        signed_message("retrieval", record["payload"], record["binding"], "recorder"),
        deterministic=True,
    ).hex()
    builder.write_record(record)

    assert tokens(reasons_for(builder)) == {"BAD_SIGNATURE"}


def test_a_record_bound_to_a_different_manifest_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    record = builder.read_record(1)
    record["binding"] = h(canon({"schema": "flightrec/v2", "policy": "something else"}))
    record["sig"] = ML_DSA_65.sign(
        builder.key("recorder")[1],
        signed_message("retrieval", record["payload"], record["binding"], "recorder"),
        deterministic=True,
    ).hex()
    builder.write_record(record)

    assert tokens(reasons_for(builder)) == {"BINDING_BROKEN"}


def test_a_manifest_record_that_binds_to_something_is_reported(tmp_path):
    builder = BundleBuilder(tmp_path)
    builder.add("manifest", MANIFEST_PAYLOAD)
    manifest = builder.read_record(0)
    manifest["binding"] = manifest["payload_hash"]
    builder.write_record(manifest)
    builder.anchor("anchor-1")

    assert "BINDING_BROKEN" in tokens(reasons_for(builder))


def test_a_bundle_with_no_manifest_is_reported(tmp_path):
    builder = BundleBuilder(tmp_path)
    builder.add("answer", {"answer_hash": h(canon("a"))}, binding=None)
    builder.anchor("anchor-1")

    assert "NO_MANIFEST" in tokens(reasons_for(builder))


def test_a_second_manifest_record_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.add("manifest", {**MANIFEST_PAYLOAD, "agent_id": "impostor"}, binding=None)

    assert "NO_MANIFEST" in tokens(reasons_for(builder))


def test_an_unparseable_record_is_reported_without_crashing(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.record_path(2).write_text("{ this is not json", encoding="utf-8")

    assert "MALFORMED_RECORD" in tokens(reasons_for(builder))


def test_a_record_missing_a_field_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    record = builder.read_record(2)
    del record["sig"]
    builder.write_record(record)

    assert "MALFORMED_RECORD" in tokens(reasons_for(builder))


def test_an_empty_episode_is_reported(tmp_path):
    builder = BundleBuilder(tmp_path)

    assert tokens(reasons_for(builder)) >= {"NO_RECORDS", "NO_ANCHOR"}


# -- sequence and anchors ----------------------------------------------------


def test_deleting_a_record_reports_the_gap_the_count_and_the_root(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.record_path(2).unlink()

    assert tokens(reasons_for(builder)) == {"SEQ_GAP_OR_DUP", "COUNT_MISMATCH", "ROOT_MISMATCH"}


def test_truncating_the_tail_leaves_the_sequence_intact_but_not_the_anchor(tmp_path):
    """Dropping the last record is not a gap, which is what the anchor is for."""
    builder = valid_bundle(tmp_path)
    builder.record_path(3).unlink()

    reasons = reasons_for(builder)

    assert "SEQ_GAP_OR_DUP" not in tokens(reasons)
    assert tokens(reasons) == {"COUNT_MISMATCH", "ROOT_MISMATCH"}


def test_duplicating_a_seq_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    record = builder.read_record(3)
    record["seq"] = 2
    builder.record_path(3).unlink()
    (builder.episode / "records" / "00003b.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
    )

    assert "SEQ_GAP_OR_DUP" in tokens(reasons_for(builder))


def test_swapping_two_seqs_survives_the_signatures_but_not_the_root(tmp_path):
    """SPEC §3.1: per-record signatures do not bind order; the root does."""
    builder = valid_bundle(tmp_path)
    second, third = builder.read_record(2), builder.read_record(3)
    second["seq"], third["seq"] = 3, 2
    builder.write_record(second)
    builder.write_record(third)

    reasons = reasons_for(builder)

    assert tokens(reasons) == {"ROOT_MISMATCH"}
    assert "SEQ_GAP_OR_DUP" not in tokens(reasons), "0..N-1 is still intact after a swap"


def test_appending_a_record_without_reanchoring_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.add("attribution", {"method": "single-chunk-ablation"}, signer="investigator")

    assert tokens(reasons_for(builder)) == {"COUNT_MISMATCH"}


def test_a_bundle_with_no_anchor_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    (builder.episode / "anchors" / "anchor-1.json").unlink()

    assert tokens(reasons_for(builder)) == {"NO_ANCHOR"}


def test_an_anchor_claiming_a_different_root_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.anchor("anchor-2", merkle_root=h(b"not the root"))

    reasons = reasons_for(builder)

    assert tokens(reasons) == {"ROOT_MISMATCH"}
    assert any("anchor-2" in reason for reason in reasons)


def test_an_anchor_with_an_edited_payload_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    anchor = builder.read_anchor("anchor-1")
    anchor["payload"]["record_count"] = 99
    builder.write_anchor(anchor)

    reasons = reasons_for(builder)

    assert "BAD_ANCHOR" in tokens(reasons)
    assert any("HASH_MISMATCH" in reason for reason in reasons)


def test_an_anchor_signed_by_an_untrusted_key_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.anchor("anchor-2", signer="rogue", trusted=False)

    reasons = reasons_for(builder)

    assert "BAD_ANCHOR" in tokens(reasons)
    assert any("UNKNOWN_SIGNER" in reason for reason in reasons)


def test_an_anchor_bound_to_another_manifest_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    anchor = builder.read_anchor("anchor-1")
    anchor["binding"] = h(canon({"other": "manifest"}))
    anchor["sig"] = ML_DSA_65.sign(
        builder.key("anchor-1")[1],
        signed_message("anchor", anchor["payload"], anchor["binding"], "anchor-1"),
        deterministic=True,
    ).hex()
    builder.write_anchor(anchor)

    assert any("BINDING_BROKEN" in reason for reason in reasons_for(builder))


def test_an_anchor_covering_more_records_than_exist_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.anchor("anchor-2", record_count=99)

    assert "COUNT_MISMATCH" in tokens(reasons_for(builder))


def test_every_failure_is_reported_not_just_the_first(tmp_path):
    builder = valid_bundle(tmp_path)
    edited = builder.read_record(1)
    edited["payload"]["query_hash"] = h(canon("different"))
    builder.write_record(edited)
    builder.record_path(2).unlink()

    assert tokens(reasons_for(builder)) == {
        "HASH_MISMATCH",
        "BAD_SIGNATURE",
        "SEQ_GAP_OR_DUP",
        "COUNT_MISMATCH",
        "ROOT_MISMATCH",
    }


def test_an_empty_trust_directory_is_reported(tmp_path):
    builder = valid_bundle(tmp_path)
    for key_file in builder.trust.glob("*.pub.hex"):
        key_file.unlink()

    assert "NO_TRUST_KEYS" in tokens(reasons_for(builder))


# -- the CLI -----------------------------------------------------------------


def run_cli(builder, *extra):
    return subprocess.run(
        [sys.executable, str(CLI), "--episode", str(builder.episode), "--trust", str(builder.trust),
         *extra],
        capture_output=True,
        text=True,
    )


def test_cli_prints_green_and_exits_zero(tmp_path):
    result = run_cli(valid_bundle(tmp_path))

    assert result.returncode == 0
    assert result.stdout.strip().splitlines()[-1] == "GREEN"


def test_cli_prints_each_reason_on_its_own_line_then_red(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.record_path(2).unlink()

    result = run_cli(builder)
    lines = result.stdout.strip().splitlines()

    assert result.returncode == 1
    assert lines[-1] == "RED"
    printed = {line.split(":")[0] for line in lines if line.split(":")[0].isupper()}
    assert {"SEQ_GAP_OR_DUP", "COUNT_MISMATCH", "ROOT_MISMATCH"} <= printed


def test_cli_summary_names_the_records_and_the_violation(tmp_path):
    result = run_cli(valid_bundle(tmp_path))

    assert "4 records" in result.stdout
    assert "transfer_funds" in result.stdout
    assert "no attribution" in result.stdout


def test_cli_summary_reports_the_attribution_when_present(tmp_path):
    builder = valid_bundle(tmp_path)
    builder.add(
        "attribution",
        {"method": "single-chunk-ablation", "culprit_chunk_hash": h(canon("c"))},
        signer="investigator",
    )
    builder.anchor("anchor-2")

    result = run_cli(builder)

    assert result.returncode == 0
    assert "single-chunk-ablation" in result.stdout
    assert "investigator" in result.stdout


def test_cli_resolves_a_culprit_hash_against_a_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "doc_00.md").write_text("clean document", encoding="utf-8")
    (corpus / "doc_07.md").write_text("poisoned document", encoding="utf-8")

    builder = valid_bundle(tmp_path)
    builder.add(
        "attribution",
        {
            "method": "single-chunk-ablation",
            "culprit_chunk_hash": h(canon("poisoned document")),
        },
        signer="investigator",
    )
    builder.anchor("anchor-2")

    result = run_cli(builder, "--corpus", str(corpus))

    assert result.returncode == 0
    assert "doc_07" in result.stdout


def test_cli_reports_a_missing_episode_as_red(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "--episode", str(tmp_path / "nope"), "--trust", str(tmp_path)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout.strip().splitlines()[-1] == "RED"


def test_the_verifier_package_still_imports_nothing_from_the_producer():
    code = (
        "import sys, verifier.verify, verifier.canonical;"
        "print([m for m in sys.modules if m.startswith('flightrec')])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "[]"
