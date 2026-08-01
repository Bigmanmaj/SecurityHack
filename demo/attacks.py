"""The attack menu, as data.

Every entry is a real mutation with a declared reason code. The tamper-matrix
tests iterate this registry and assert each attack produces the code it claims,
and the web UI renders the same registry as buttons. There is no third
implementation: the button a judge presses is the mutation the test suite proves.

Each ``apply`` takes an episode root plus a :class:`Target` describing the live
episode, and returns a human-readable note about what it did.
"""

import os
import secrets

from fr import reasons
from fr.hashes import sha3_hex

from . import adversary as adv

# What an attack needs from the episode before it can run at all.
NEEDS_NOTHING = "nothing"
NEEDS_LIVE_KEY = "live_key"      # the recorder is still open: seed_n is on disk
NEEDS_FOREIGN = "foreign"        # a second, different episode to splice from


class AttackUnavailable(RuntimeError):
    """The episode on disk cannot support this attack, and we say why."""


class Target:
    """Everything an attack needs to know about the episode it is about to edit."""

    def __init__(self, root, episode, count, bodies, foreign_root=None, foreign_episode=None):
        self.root = root
        self.episode = episode
        self.count = count
        self.bodies = bodies
        self.foreign_root = foreign_root
        self.foreign_episode = foreign_episode

    def seq_of(self, *types, default=None):
        """The first record of any of ``types``, or a sensible middle record."""
        for body in self.bodies:
            if body["type"] in types:
                return body["seq"]
        return default if default is not None else max(1, self.count // 2)

    @property
    def tool_call_seq(self):
        return self.seq_of("TOOL_CALL")

    @property
    def middle_seq(self):
        return max(1, self.count // 2)


class Attack:
    def __init__(self, key, label, reason, blurb, apply, requires=NEEDS_NOTHING, star=False):
        self.key = key
        self.label = label
        self.reason = reason
        self.blurb = blurb
        self.apply = apply
        self.requires = requires
        self.star = star

    def as_json(self):
        return {"key": self.key, "label": self.label, "reason": self.reason,
                "blurb": self.blurb, "requires": self.requires, "star": self.star}


# --- the mutations --------------------------------------------------------

def _edit_one_byte(target):
    seq = target.tool_call_seq
    body = next(b for b in target.bodies if b["seq"] == seq)
    # The tool name is the edit worth showing; the actor is the fallback, because
    # every record has one.
    candidates = [(b'"http_post"', b'"http_post "'),
                  (('"' + body["actor"] + '"').encode("utf-8"),
                   ('"' + body["actor"] + ' "').encode("utf-8"))]
    for find, replace in candidates:
        try:
            adv.raw_edit(target.root, seq, find, replace)
        except AssertionError:
            continue
        return seq, "record %d: %s -> %s" % (seq, find.decode(), replace.decode())
    raise AttackUnavailable("nothing editable found in record %d" % seq)


def _delete_a_record(target):
    seq = target.middle_seq
    adv.delete_record(target.root, seq)
    return seq, f"deleted records/{seq:06d}.json from the middle of the chain"


def _duplicate_a_record(target):
    seq = target.middle_seq
    adv.duplicate_record(target.root, seq)
    return seq, f"copied records/{seq:06d}.json to a second file claiming the same seq"


def _chop_the_tail(target):
    cut = max(1, target.count - 1)
    adv.truncate_tail(target.root, cut)
    return cut, f"removed the final {target.count - cut} record(s), including the SEAL"


def _resign_with_a_fresh_key(target):
    """The "but you hold the key" objection, executed live.

    The attacker generates a perfectly good ML-DSA keypair and produces a
    perfectly good signature. It still fails, because the *previous* record
    already committed to which key was allowed to sign next -- and that key is gone.
    """
    seq = target.tool_call_seq
    adv.resign(
        target.root, seq,
        lambda body: body["payload"].update(authorized=True),
        seed0=None, forged_seed=secrets.token_bytes(32),
    )
    return seq, f"record {seq} re-signed with a brand new key, and marked authorized"


def _splice_a_fabricated_history(target):
    seized = adv.live_seed(target.root)
    if seized is None:
        raise AttackUnavailable(
            "this episode is closed to appends: there is no live key to seize. "
            "Record a fresh episode first."
        )
    seed, seq, _prev = seized
    adv.forge_append(
        target.root, episode=target.episode, seq=seq,
        prev=sha3_hex(b"a history that never happened"), seed=seed,
        payload={"text": "the tool call never happened"},
    )
    return seq, (f"seized the live key and appended record {seq} claiming a different "
                 "previous record")


def _append_past_the_seal(target):
    seized = adv.live_seed(target.root)
    if seized is None:
        raise AttackUnavailable(
            "this episode is closed to appends: there is no live key to seize. "
            "Record a fresh episode first."
        )
    seed, seq, prev = seized
    adv.forge_append(target.root, episode=target.episode, seq=seq, prev=prev, seed=seed,
                     payload={"text": "quietly added after the fact"})
    return seq, f"seized the live key and appended record {seq} after a sealed episode"


def _backdate_a_record(target):
    seized = adv.live_seed(target.root)
    if seized is None:
        raise AttackUnavailable(
            "this episode is closed to appends: there is no live key to seize. "
            "Record a fresh episode first."
        )
    seed, seq, prev = seized
    adv.forge_append(target.root, episode=target.episode, seq=seq, prev=prev, seed=seed,
                     ts_ns=1, payload={"text": "this happened first, honestly"})
    return seq, f"appended record {seq} back-dated to 1970 to reorder the story"


def _splice_from_another_episode(target):
    if not target.foreign_root or not os.path.isdir(target.foreign_root):
        raise AttackUnavailable("no second episode is available to splice from")
    if target.foreign_episode == target.episode:
        raise AttackUnavailable(
            "the loaded episode is the golden episode, so there is nothing foreign to "
            "splice. Record a fresh episode first."
        )
    seq = target.middle_seq
    body = adv.splice_record(target.root, seq, target.foreign_root)
    return seq, f"overwrote record {seq} with record {seq} from episode {body['episode']}"


def _swap_a_blob(target):
    for body in target.bodies:
        for ref in _blob_refs(body["payload"]):
            adv.swap_blob(target.root, ref, b"an innocent-looking prompt")
            return body["seq"], (f"swapped the contents of blobs/{ref[:12]}....bin, "
                                 f"referenced by record {body['seq']}")
    raise AttackUnavailable("this episode references no blobs")


def _slip_in_a_float(target):
    for body in target.bodies:
        if body["type"] != "RETRIEVAL":
            continue
        for chunk in body["payload"].get("chunks", []):
            score = chunk.get("score_milli")
            if isinstance(score, int) and score > 10:
                adv.raw_edit(target.root, body["seq"],
                             ('"score_milli": %d' % score).encode(),
                             ('"score_milli": %s' % (score / 10)).encode())
                return body["seq"], ("turned score_milli %d into a float in record %d"
                                     % (score, body["seq"]))
    raise AttackUnavailable("no integer score found to turn into a float")


def _insert_a_lone_surrogate(target):
    seq = target.seq_of("USER_INPUT")
    body = next(b for b in target.bodies if b["seq"] == seq)
    text = body["payload"].get("text", "")
    if len(text) < 4:
        raise AttackUnavailable("no text long enough to corrupt")
    adv.raw_edit(target.root, seq, f'"{text}"'.encode("utf-8"),
                 ('"' + text[:-3] + '\\ud800"').encode("utf-8"))
    return seq, f"replaced the tail of record {seq}'s text with an unencodable surrogate"


def _rewrite_the_anchor(target):
    adv.swap_anchor(target.root)
    return 0, "replaced anchor.pub with the hash of a different key"


def _blob_refs(value):
    if isinstance(value, dict):
        if isinstance(value.get("blob_sha3"), str):
            yield value["blob_sha3"]
        for item in value.values():
            yield from _blob_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from _blob_refs(item)


# --- the registry ---------------------------------------------------------

ATTACKS = (
    Attack("edit_byte", "Edit one byte", reasons.SIGNATURE_INVALID,
           "Open the file in an editor and change one character.", _edit_one_byte),
    Attack("delete_record", "Delete a record", reasons.SEQUENCE_GAP,
           "Remove a record file from the middle of the chain.", _delete_a_record),
    Attack("duplicate_record", "Duplicate a record", reasons.DUPLICATE_SEQ,
           "Copy a record so two files claim the same seq.", _duplicate_a_record),
    Attack("chop_tail", "Chop the tail", reasons.TRUNCATED_TAIL,
           "Delete the last record, taking the SEAL with it.", _chop_the_tail),
    Attack("resign_fresh_key", "Re-sign with a fresh key", reasons.RATCHET_MISMATCH,
           "Generate a new keypair and sign a doctored record with it. This is the "
           "'but the operator holds the key' objection, run live.",
           _resign_with_a_fresh_key, star=True),
    Attack("splice_history", "Seize the live key, splice a fake past", reasons.CHAIN_BREAK,
           "Take the key the recorder holds right now and append a record that names a "
           "previous record which never existed.",
           _splice_a_fabricated_history, requires=NEEDS_LIVE_KEY, star=True),
    Attack("append_past_seal", "Seize the live key, append past the SEAL",
           reasons.SEAL_MISPLACED,
           "Quietly add a record to an episode that was already sealed.",
           _append_past_the_seal, requires=NEEDS_LIVE_KEY),
    Attack("backdate_record", "Seize the live key, back-date a record",
           reasons.TIMESTAMP_REGRESSION,
           "Append a validly signed record stamped before the one it follows.",
           _backdate_a_record, requires=NEEDS_LIVE_KEY),
    Attack("splice_episode", "Splice from another episode", reasons.EPISODE_MISMATCH,
           "Overwrite a record with a genuine, genuinely signed record from a different "
           "episode.", _splice_from_another_episode, requires=NEEDS_FOREIGN),
    Attack("swap_blob", "Swap an evidence blob", reasons.BLOB_HASH_MISMATCH,
           "Replace the stored prompt with a more flattering one.", _swap_a_blob),
    Attack("float_score", "Slip a float into a score", reasons.SCHEMA_INVALID,
           "Floats have no single canonical form, so they are banned outright.",
           _slip_in_a_float),
    Attack("lone_surrogate", "Insert an unencodable character", reasons.CANON_UNSTABLE,
           "A lone surrogate parses as JSON but has no UTF-8 encoding, so no two "
           "implementations could agree on the bytes to sign.", _insert_a_lone_surrogate),
    Attack("rewrite_anchor", "Rewrite the anchor", reasons.ANCHOR_MISMATCH,
           "Point anchor.pub at a different key entirely.", _rewrite_the_anchor),
)

BY_KEY = {attack.key: attack for attack in ATTACKS}


def apply(key, target):
    """Run one attack. Returns ``(seq, note)``; raises AttackUnavailable if it cannot."""
    if key not in BY_KEY:
        raise AttackUnavailable(f"unknown attack: {key}")
    return BY_KEY[key].apply(target)
