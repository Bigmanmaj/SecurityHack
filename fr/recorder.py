"""Append-only recorder: canon -> hash -> ratchet -> sign -> fsync.

Knows nothing about agents. It takes typed events and turns them into evidence.
"""

import base64
import json
import os
import secrets
import time

from . import canon, pqc, record
from .hashes import ZERO_HASH, blob_hash, sha3_hex
from .ratchet import PARAMS as RATCHET_PARAMS
from .ratchet import Ratchet

RECORDER_VERSION = "fr/0.1.0"
STATE_FILENAME = ".recorder-state.json"
ANCHOR_FILENAME = "anchor.pub"
RECORDS_DIRNAME = "records"
BLOBS_DIRNAME = "blobs"
SEQ_PAD = 6


class RecorderError(RuntimeError):
    pass


def new_episode_id(now=None):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now if now is not None else time.time()))
    return f"ep-{stamp}-{secrets.token_hex(2)}"


def record_filename(seq):
    return f"{seq:0{SEQ_PAD}d}.json"


def _write_atomic(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class Recorder:
    """Owns one episode directory and one ratchet.

    The live ratchet seed is persisted to ``.recorder-state.json`` so a later
    process (the investigator) can extend the same chain. That file is the only
    key material that exists anywhere: it signs the future, and it is useless
    against the past, which is exactly the property the threat model claims.
    """

    def __init__(self, root, episode, ratchet, next_seq, prev_hash, actor, state_path):
        self.root = root
        self.episode = episode
        self.ratchet = ratchet
        self.next_seq = next_seq
        self.prev_hash = prev_hash
        self.actor = actor
        self.state_path = state_path
        self.last_ts_ns = 0
        self.sealed = False

    # ------------------------------------------------------------------ setup

    @classmethod
    def open_new(cls, root, actor, episode=None, seed=None):
        root = os.path.abspath(root)
        if os.path.exists(os.path.join(root, RECORDS_DIRNAME)) and os.listdir(
            os.path.join(root, RECORDS_DIRNAME)
        ):
            raise RecorderError(f"{root}/{RECORDS_DIRNAME} already contains records")
        os.makedirs(os.path.join(root, RECORDS_DIRNAME), exist_ok=True)
        os.makedirs(os.path.join(root, BLOBS_DIRNAME), exist_ok=True)
        ratchet = Ratchet(seed) if seed is not None else Ratchet.new()
        _write_atomic(os.path.join(root, ANCHOR_FILENAME), (ratchet.anchor + "\n").encode("ascii"))
        rec = cls(
            root=root,
            episode=episode or new_episode_id(),
            ratchet=ratchet,
            next_seq=0,
            prev_hash=ZERO_HASH,
            actor=actor,
            state_path=os.path.join(root, STATE_FILENAME),
        )
        rec._save_state()
        return rec

    @classmethod
    def reopen(cls, root, actor=None):
        root = os.path.abspath(root)
        state_path = os.path.join(root, STATE_FILENAME)
        if not os.path.exists(state_path):
            raise RecorderError(
                f"no recorder state at {state_path}: this episode is closed to appends "
                "(the ratchet seed is gone, and it cannot be reconstructed)"
            )
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        ratchet = Ratchet(bytes.fromhex(state["seed"]), index=state["next_seq"])
        rec = cls(
            root=root,
            episode=state["episode"],
            ratchet=ratchet,
            next_seq=state["next_seq"],
            prev_hash=state["prev_hash"],
            actor=actor or state["actor"],
            state_path=state_path,
        )
        rec.last_ts_ns = state.get("last_ts_ns", 0)
        return rec

    def _save_state(self):
        state = {
            "episode": self.episode,
            "next_seq": self.next_seq,
            "prev_hash": self.prev_hash,
            "actor": self.actor,
            "last_ts_ns": self.last_ts_ns,
            "seed": self.ratchet.export_seed().hex(),
        }
        _write_atomic(self.state_path, json.dumps(state, indent=2).encode("utf-8"))
        os.chmod(self.state_path, 0o600)

    # ------------------------------------------------------------------ paths

    @property
    def anchor(self):
        with open(os.path.join(self.root, ANCHOR_FILENAME), "r", encoding="ascii") as fh:
            return fh.read().strip()

    def record_path(self, seq):
        return os.path.join(self.root, RECORDS_DIRNAME, record_filename(seq))

    def blob_path(self, digest):
        return os.path.join(self.root, BLOBS_DIRNAME, f"{digest}.bin")

    @property
    def head_hash(self):
        return self.prev_hash

    @property
    def count(self):
        return self.next_seq

    # ------------------------------------------------------------------ write

    def put_blob(self, data):
        """Store a large payload out of line and return a hash reference for it."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        digest = blob_hash(data)
        path = self.blob_path(digest)
        if not os.path.exists(path):
            _write_atomic(path, data)
        return record.blob_ref(digest, len(data))

    def _now_ns(self):
        # Strictly increasing: a coarse or non-monotonic clock must never make a
        # legitimate episode fail TIMESTAMP_REGRESSION.
        ts = time.time_ns()
        if ts <= self.last_ts_ns:
            ts = self.last_ts_ns + 1
        return ts

    def append(self, type_, payload, actor=None):
        if self.sealed:
            raise RecorderError("recorder is sealed; reopen the episode to append")
        seq = self.next_seq
        ts_ns = self._now_ns()
        body = record.make_body(
            episode=self.episode,
            seq=seq,
            ts_ns=ts_ns,
            prev=self.prev_hash,
            next_pk=self.ratchet.next_pk_hash,
            type_=type_,
            actor=actor or self.actor,
            payload=payload,
        )
        message = canon.assert_stable(body)
        signature = self.ratchet.sign(message)
        entry = {
            "body": body,
            "sig": {
                "alg": pqc.ALG,
                "pk": _b64(self.ratchet.pk),
                "value": _b64(signature),
            },
        }
        _write_atomic(self.record_path(seq), _pretty(entry))

        self.prev_hash = sha3_hex(message)
        self.next_seq = seq + 1
        self.last_ts_ns = ts_ns
        self.ratchet.advance()
        self._save_state()
        return body

    def anchor_record(self):
        """Publish the current head hash inside the chain itself."""
        return self.append(
            record.ANCHOR,
            {"count": self.count, "head_hash": self.head_hash, "alg": pqc.ALG},
        )

    def seal(self, reason="normal"):
        body = self.append(
            record.SEAL,
            {"count": self.next_seq + 1, "head_hash": self.prev_hash, "reason": reason},
        )
        self.sealed = True
        return body

    def reopen_after_seal(self):
        """Allow appends again after a SEAL.

        The format only tolerates an intermediate SEAL when the very next record
        is an ``INVESTIGATION_OPEN`` naming that SEAL's head hash, so the caller
        is on the hook for writing one immediately.
        """
        self.sealed = False
        return self


def _b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def _pretty(entry):
    """On-disk form is indented and readable. Only the canonical body is signed."""
    return (json.dumps(entry, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def genesis_payload(agent_version, model_id, params, tool_allowlist, corpus_manifest, task=None):
    payload = {
        "recorder": RECORDER_VERSION,
        "agent_version": agent_version,
        "model_id": model_id,
        "params": params,
        "tool_allowlist": sorted(tool_allowlist),
        "corpus_manifest": corpus_manifest,
        "ratchet": dict(RATCHET_PARAMS),
        "hash_alg": "SHA3-256",
        "sig_alg": pqc.ALG,
    }
    if task is not None:
        payload["task"] = task
    return payload
