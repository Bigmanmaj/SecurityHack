"""Adversary simulation for the tamper matrix.

Two kinds of attack are modelled, and the distinction is the point of the project:

* **Raw edits** -- the operator opens the file in an editor. Cheap, and caught by
  the signature.
* **Key compromise at record k** -- the operator seizes the machine, takes the
  live ratchet seed, and re-signs from k onward with legitimate keys. This is the
  attack that "just sign your logs" loses to. Forward security means the attacker
  can only ever reach forward: rewriting record k still leaves record k-1's hash,
  record k+1's ``prev``, or the ratchet commitment pointing somewhere else.

``seed_at(seed0, k)`` here plays the role of "the seed the attacker found in
memory"; in a real compromise they would read it off the box, which is what
:func:`live_seed` does against a recorder that is still open.
"""

import base64
import json
import os
import shutil
import time

from fr import canon, pqc
from fr.hashes import sha3_hex
from fr.ratchet import seed_at
from fr.recorder import RECORDS_DIRNAME, STATE_FILENAME, record_filename


def record_path(root, seq):
    return os.path.join(root, RECORDS_DIRNAME, record_filename(seq))


def load_record(root, seq):
    with open(record_path(root, seq), "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_record(root, seq, entry):
    with open(record_path(root, seq), "w", encoding="utf-8") as fh:
        json.dump(entry, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def raw_edit(root, seq, old, new):
    """Edit the file on disk. No key required, and no signature survives it."""
    path = record_path(root, seq)
    with open(path, "rb") as fh:
        data = fh.read()
    if old not in data:
        raise AssertionError(f"{old!r} not present in {path}")
    with open(path, "wb") as fh:
        fh.write(data.replace(old, new, 1))
    return path


def resign(root, seq, mutate, seed0, forged_seed=None):
    """Rewrite record ``seq`` and re-sign it as an attacker holding seed_k would.

    ``next_pk`` is preserved, so the rest of the chain still ratchets correctly and
    the verifier has to catch the lie some other way.
    """
    entry = load_record(root, seq)
    body = entry["body"]
    mutate(body)
    seed = forged_seed if forged_seed is not None else seed_at(seed0, seq)
    pk, sk = pqc.key_derive(seed)
    message = canon.dumps(body)
    entry["sig"] = {
        "alg": pqc.ALG,
        "pk": base64.b64encode(pk).decode("ascii"),
        "value": base64.b64encode(pqc.sign(sk, message)).decode("ascii"),
    }
    write_record(root, seq, entry)
    return sha3_hex(message)


def delete_record(root, seq):
    os.remove(record_path(root, seq))


def duplicate_record(root, seq):
    """Copy a record to a filename that sorts immediately after the original."""
    src = record_path(root, seq)
    dst = src.replace(".json", "a.json")
    shutil.copyfile(src, dst)
    return dst


def truncate_tail(root, seq_from):
    for name in sorted(os.listdir(os.path.join(root, RECORDS_DIRNAME))):
        seq = int(name.split(".")[0].rstrip("a") or 0)
        if seq >= seq_from:
            os.remove(os.path.join(root, RECORDS_DIRNAME, name))


def swap_anchor(root, value=None):
    path = os.path.join(root, "anchor.pub")
    with open(path, "w", encoding="ascii") as fh:
        fh.write((value or sha3_hex(b"a different chain entirely")) + "\n")
    return path


def live_seed(root):
    """The seed the recorder holds *right now*, as an attacker with root would read it.

    Returns ``(seed, next_seq, prev_hash)`` or ``None`` when the episode has been
    closed to appends. This is the honest shape of a real compromise: it buys the
    ability to sign the next record, and nothing at all about the previous ones.
    """
    path = os.path.join(root, STATE_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    return bytes.fromhex(state["seed"]), state["next_seq"], state["prev_hash"]


def forge_append(root, episode, seq, prev, seed, type_="AGENT_FINAL", payload=None,
                 actor="operator:seized-the-box@1", ts_ns=None):
    """Append a record signed with a seized live key.

    The attacker can do this -- forward security protects the past, not the future.
    What they cannot do is make the forged record claim a different past: ``prev``
    is checked against the record that is already on disk.
    """
    from fr import record as R
    from fr.ratchet import Ratchet

    ratchet = Ratchet(seed, index=seq)
    body = R.make_body(
        episode=episode,
        seq=seq,
        ts_ns=ts_ns if ts_ns is not None else time.time_ns(),
        prev=prev,
        next_pk=ratchet.next_pk_hash,
        type_=type_,
        actor=actor,
        payload=payload if payload is not None else {"text": "nothing to see here"},
    )
    message = canon.dumps(body)
    entry = {
        "body": body,
        "sig": {
            "alg": pqc.ALG,
            "pk": base64.b64encode(ratchet.pk).decode("ascii"),
            "value": base64.b64encode(ratchet.sign(message)).decode("ascii"),
        },
    }
    write_record(root, seq, entry)
    return sha3_hex(message)


def splice_record(root, seq, source_root, source_seq=None):
    """Drop a record from a different episode into this one, byte for byte."""
    entry = load_record(source_root, seq if source_seq is None else source_seq)
    write_record(root, seq, entry)
    return entry["body"]


def swap_blob(root, digest, data=b"swapped payload"):
    path = os.path.join(root, "blobs", f"{digest}.bin")
    with open(path, "wb") as fh:
        fh.write(data)
    return path
