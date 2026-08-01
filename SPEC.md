# SPEC — frozen at T+0. Changes require all three people, and none after Sync 1.

## Canonical bytes
canonical_bytes(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False).encode("utf-8").
Allowed payload types: dict (str keys), list, str, int, bool, None.
Any float anywhere → raise CanonicalizationError. This is the ONLY serialization
ever hashed or signed.

## Hash
H(x) = SHA3-256(x). Stored as lowercase hex.

## Signatures
ML-DSA-65 via dilithium-py (`from dilithium_py.ml_dsa import ML_DSA_65`).
signature = ML_DSA_65.sign(sk, canonical_bytes(payload)). Stored hex.
Private keys exist only in process memory. Public keys: trust/<signer_id>.pub.hex.
signer_ids: "recorder", "anchor-1", "investigator", "anchor-2".

## Record file (episode/records/NNNNNN.json, NNNNNN = zero-padded seq)
{ "payload": {...}, "payload_hash": "<hex of H(canonical_bytes(payload))>",
  "signature": "<hex>", "signer_id": "<id>", "created_at": "<iso8601 utc>" }
payload_hash and signature are CLAIMS — the verifier recomputes both.

## Payload schemas (all have "type", "seq", "ts"; all except manifest have
"chain_binding" = the manifest's payload_hash)
manifest    seq=0: episode_id, agent_id, model, policy:{forbidden_tools:[...]}
retrieval        : query_hash, chunk_hashes:[hex,...]   # hashes only, never content
tool_call        : tool, args_hash
answer           : answer_hash
attribution      : method:"single-chunk-ablation", culprit_chunk_hash, runs:int,
                   baseline_misbehaved:true, flipped_on_ablation:true
Signers: manifest/retrieval/tool_call/answer → "recorder"; attribution → "investigator".

## Anchor (episode/anchor.json — same record file shape, signer "anchor-1",
re-anchor after investigation overwrites with signer "anchor-2")
payload: { type:"anchor", chain_binding, record_count, merkle_root, ts }

## Merkle
Leaves in seq order over ALL records incl. manifest.
leaf_i = H( seq_i as 8-byte big-endian || bytes.fromhex(payload_hash_i) )
parent = H(left || right); odd node PROMOTED (not duplicated). Root = hex.

## Verifier (verify_cli.py --episode DIR --trust DIR)
Trust dir is the VERIFIER'S OWN copy of the public keys (copied once at publish
time) — never read keys from the episode bundle.
Checks, each with a named reason on failure:
HASH_MISMATCH(file)      recomputed payload_hash != stored
BAD_SIGNATURE(file)      signature invalid over canonical_bytes(payload)
UNKNOWN_SIGNER(file)     signer_id has no key in trust dir
BINDING_BROKEN(file)     chain_binding != manifest payload_hash
SEQ_GAP_OR_DUP           seqs are not exactly 0..N-1
COUNT_MISMATCH           anchor.record_count != number of records
ROOT_MISMATCH            recomputed Merkle root != anchor.merkle_root
BAD_ANCHOR(reason)       anchor fails hash/signature/signer checks
Exit 0 + "GREEN" if no failures; else print every reason, "RED", exit 1.
