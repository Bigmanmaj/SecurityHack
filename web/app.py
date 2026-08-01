"""The demo server: a window onto the real CLI, never a reimplementation of it.

The one rule this file exists to enforce: **no verification logic runs here, and
none runs in the browser.** Every verdict on screen comes from
``subprocess.run(["python", "verify_episode.py", ...])`` and is rendered verbatim
alongside its integer exit code. Everything else the server does is reading files
and describing them.

Run it with::

    python -m web.app          # http://127.0.0.1:8000

It binds to loopback only. It also, deliberately, ships the adversary's toolkit:
a write endpoint and a menu of real tamper attacks. The claim is that write access
to the log directory is not enough, so the demo hands the judge write access. See
the path-handling notes on :func:`record_path` -- shipping a real path traversal
bug at a security hackathon would be its own kind of embarrassing.
"""

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import verify_episode  # noqa: E402
from agent import rag  # noqa: E402
from agent.corpus import Corpus, load_docs  # noqa: E402
from demo import attacks  # noqa: E402
from fr import canon  # noqa: E402
from fr.hashes import sha3_hex  # noqa: E402
from fr.recorder import RECORDS_DIRNAME, STATE_FILENAME, record_filename  # noqa: E402
from investigator.cli import InvestigationError, investigate  # noqa: E402

EPISODE_ROOT = os.path.join(REPO, os.environ.get("FR_EPISODE", "episode"))
GOLDEN_ROOT = os.path.join(REPO, "episodes", "golden")
INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
MAX_RECORD_BYTES = 4 * 1024 * 1024

app = FastAPI(title="Flight Recorder", docs_url=None, redoc_url=None)


class Demo:
    """All the state there is. One episode, no sessions, no database."""

    def __init__(self):
        self.lock = threading.Lock()
        self.busy = None
        self.reset_soft()

    def reset_soft(self):
        # Signing latency is only real for records this process watched being
        # signed. For a loaded episode we show nothing rather than inventing it.
        self.sign_ms = {}
        self.verdict = None
        self.edited = set()
        self.source = "empty"


DEMO = Demo()


# --- paths: the client's string never touches the filesystem ---------------

def record_path(seq, root=None):
    """Build a record path from an integer. Never join client-supplied strings."""
    root = os.path.realpath(root or EPISODE_ROOT)
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq < 1_000_000:
        raise HTTPException(400, "seq must be an integer in [0, 999999]")
    path = os.path.realpath(os.path.join(root, RECORDS_DIRNAME, record_filename(seq)))
    if os.path.commonpath([path, root]) != root:
        raise HTTPException(400, "refusing to operate outside the episode root")
    return path


# These all default to "the configured episode" rather than capturing it in a
# default argument, which would freeze the path at import time.
def episode_exists(root=None):
    records = os.path.join(root or EPISODE_ROOT, RECORDS_DIRNAME)
    return os.path.isdir(records) and bool(os.listdir(records))


def transportable(value):
    """Make a parsed record safe to put in a JSON response.

    A tampered record can contain a lone surrogate -- that is one of the attacks
    on the menu. It parses as JSON and has no UTF-8 encoding, which is exactly why
    the verifier rejects it, and also why it would otherwise crash the response
    encoder on the way to the browser. Substituting U+FFFD for display changes
    nothing on disk: the verifier reads the file, not this.
    """
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, list):
        return [transportable(item) for item in value]
    if isinstance(value, dict):
        return {transportable(k): transportable(v) for k, v in value.items()}
    return value


def read_bodies(root=None):
    """Parse the record files as they are on disk. This is a picture, not a verdict."""
    records_dir = os.path.join(root or EPISODE_ROOT, RECORDS_DIRNAME)
    if not os.path.isdir(records_dir):
        return []
    out = []
    for name in sorted(f for f in os.listdir(records_dir) if f.endswith(".json")):
        path = os.path.join(records_dir, name)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            entry = json.loads(raw.decode("utf-8"))
            body = entry["body"]
            try:
                body_hash = sha3_hex(canon.dumps(body))
            except Exception:
                body_hash = None
            out.append(transportable({
                "file": name,
                "seq": body.get("seq"),
                "episode": body.get("episode"),
                "type": body.get("type"),
                "actor": body.get("actor"),
                "ts_ns": body.get("ts_ns"),
                "prev": body.get("prev"),
                "next_pk": body.get("next_pk"),
                "hash": body_hash,
                "payload": body.get("payload"),
                "readable": True,
            }))
        except Exception as exc:
            out.append({"file": name, "seq": None, "type": "UNREADABLE", "readable": False,
                        "error": str(exc)})
    return out


def read_anchor(root=None):
    path = os.path.join(root or EPISODE_ROOT, "anchor.pub")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="ascii", errors="replace") as fh:
        return fh.read().strip()


def episode_id(root=None):
    bodies = read_bodies(root)
    return bodies[0].get("episode") if bodies else None


# --- the state the page renders -------------------------------------------

def spine(bodies):
    """One row per record, plus the erased-key story told from real timestamps."""
    rows = []
    for i, body in enumerate(bodies):
        if not body["readable"]:
            rows.append({**body, "key": None})
            continue
        signed_at = body["ts_ns"]
        erased_at = bodies[i + 1]["ts_ns"] if i + 1 < len(bodies) and bodies[i + 1]["readable"] \
            else None
        rows.append({
            "file": body["file"],
            "seq": body["seq"],
            "type": body["type"],
            "actor": body["actor"],
            "hash": body["hash"],
            "prev": body["prev"],
            "next_pk": body["next_pk"],
            "ts_ns": signed_at,
            "sign_ms": DEMO.sign_ms.get(body["seq"]),
            "edited": body["seq"] in DEMO.edited,
            "key": {
                "signed_at": signed_at,
                "erased_at": erased_at,
                "erased": erased_at is not None,
            },
        })
    return rows


def episode_view(bodies):
    """Task, retrieval, tool calls and the finding -- whatever is on disk so far."""
    view = {"task": None, "chunks": [], "tool_calls": [], "violation": None,
            "finding": None, "answer": None, "seals": []}
    for body in bodies:
        if not body["readable"]:
            continue
        payload, type_ = body.get("payload") or {}, body["type"]
        if type_ == "USER_INPUT":
            view["task"] = payload.get("text")
        elif type_ == "RETRIEVAL" and not view["chunks"]:
            view["chunks"] = [
                {"doc_id": c.get("doc_id"), "chunk_id": c.get("chunk_id"),
                 "sha3": c.get("sha3"), "score_milli": c.get("score_milli"),
                 "char_span": c.get("char_span"), "rank": c.get("rank"),
                 "key": "%s#%s" % (c.get("doc_id"), c.get("chunk_id"))}
                for c in payload.get("chunks", [])
            ]
        elif type_ == "TOOL_CALL":
            view["tool_calls"].append({"seq": body["seq"], "name": payload.get("name"),
                                       "args": payload.get("args"),
                                       "authorized": payload.get("authorized")})
        elif type_ == "POLICY_VIOLATION":
            view["violation"] = {"seq": body["seq"], "rule": payload.get("rule"),
                                 "tool": payload.get("tool"),
                                 "offending_seq": payload.get("offending_seq"),
                                 "reason": payload.get("reason")}
        elif type_ == "ATTRIBUTION_FINDING":
            view["finding"] = payload
        elif type_ == "AGENT_FINAL":
            view["answer"] = payload.get("text")
        elif type_ == "SEAL":
            view["seals"].append(body["seq"])
    return view


def state_payload():
    bodies = read_bodies()
    return {
        "exists": bool(bodies),
        "source": DEMO.source,
        "episode": episode_id(),
        "anchor": read_anchor(),
        "count": len(bodies),
        "records": spine(bodies),
        "episode_view": episode_view(bodies),
        "verdict": DEMO.verdict,
        "appendable": os.path.exists(os.path.join(EPISODE_ROOT, STATE_FILENAME)),
        "busy": DEMO.busy,
        "attacks": [a.as_json() for a in attacks.ATTACKS],
    }


@app.get("/")
def index():
    return FileResponse(INDEX_HTML, media_type="text/html")


@app.get("/api/state")
def get_state():
    return state_payload()


# --- the verifier: a real subprocess, rendered verbatim -------------------

REASON_RE = re.compile(r"^\s*RED - ([A-Z_]+)\s*$", re.M)
SEQ_RE = re.compile(r"^\s*record\s+(\d+)\s+(\S*)\s*$", re.M)


@app.post("/api/verify")
def post_verify():
    """Run the real verifier and hand back exactly what it said.

    Nothing here interprets the chain. ``returncode`` is the verdict; the reason
    code and seq are scraped only so the UI knows which row to colour.
    """
    if not episode_exists():
        raise HTTPException(409, "no episode on disk: record one first")
    started = time.perf_counter()
    argv = [sys.executable, "verify_episode.py", EPISODE_ROOT, "--no-color"]
    proc = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=300)
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    reason = REASON_RE.search(proc.stdout)
    located = SEQ_RE.search(proc.stdout)
    verdict = {
        "command": "python verify_episode.py %s" % os.path.relpath(EPISODE_ROOT, REPO),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "green": proc.returncode == 0,
        "reason": reason.group(1) if reason else None,
        "seq": int(located.group(1)) if located else None,
        "path": located.group(2) if located else None,
        "elapsed_ms": elapsed_ms,
        "records": len(read_bodies()),
        "at": time.time(),
    }
    with DEMO.lock:
        DEMO.verdict = verdict
        if proc.returncode == 0:
            DEMO.edited.clear()
    return verdict


# --- the record editor: the adversary's toolkit, shipped on purpose -------

@app.get("/api/records/{seq}")
def get_record(seq: int):
    path = record_path(seq)
    if not os.path.exists(path):
        raise HTTPException(404, "no record %d" % seq)
    with open(path, "rb") as fh:
        raw = fh.read()
    return {"seq": seq, "path": os.path.relpath(path, REPO), "bytes": len(raw),
            "text": raw.decode("utf-8", errors="replace"),
            "edited": seq in DEMO.edited}


@app.put("/api/records/{seq}")
async def put_record(seq: int, request: Request):
    """Write attacker-chosen bytes to a record file.

    This is the threat model, not a bug: our claim is that write access to the log
    directory is not enough. ``seq`` is an int, the path is constructed server-side
    from it, and the result is asserted to sit inside the episode root.
    """
    path = record_path(seq)
    if not os.path.exists(path):
        raise HTTPException(404, "no record %d" % seq)
    payload = await request.json()
    text = payload.get("text")
    if not isinstance(text, str):
        raise HTTPException(400, "expected {\"text\": \"...\"}")
    data = text.encode("utf-8", errors="surrogatepass")
    if len(data) > MAX_RECORD_BYTES:
        raise HTTPException(413, "record too large")
    with open(path, "wb") as fh:
        fh.write(data)
    with DEMO.lock:
        DEMO.edited.add(seq)
        DEMO.verdict = None  # the bytes changed; we do not pretend to know the verdict
    return {"ok": True, "seq": seq, "bytes": len(data), "state": state_payload()}


@app.post("/api/tamper/{key}")
def post_tamper(key: str):
    """Apply one attack from the registry the tamper-matrix tests assert on."""
    if not episode_exists():
        raise HTTPException(409, "no episode on disk: record one first")
    bodies = [b for b in read_bodies() if b["readable"]]
    if not bodies:
        raise HTTPException(409, "no readable records to attack")
    target = attacks.Target(
        root=EPISODE_ROOT,
        episode=bodies[0].get("episode"),
        count=len(bodies),
        bodies=[{"seq": b["seq"], "type": b["type"], "actor": b["actor"],
                 "payload": b["payload"]} for b in bodies],
        foreign_root=GOLDEN_ROOT if os.path.isdir(GOLDEN_ROOT) else None,
        foreign_episode=episode_id(GOLDEN_ROOT) if os.path.isdir(GOLDEN_ROOT) else None,
    )
    try:
        seq, note = attacks.apply(key, target)
    except attacks.AttackUnavailable as exc:
        raise HTTPException(409, str(exc)) from exc
    with DEMO.lock:
        DEMO.edited.add(seq)
        DEMO.verdict = None
    attack = attacks.BY_KEY[key]
    return {"ok": True, "seq": seq, "note": note, "expected_reason": attack.reason,
            "label": attack.label, "state": state_payload()}


# --- streaming the two live runs ------------------------------------------

def sse(work, name):
    """Run ``work(emit)`` on a thread and stream what it emits as Server-Sent Events."""
    if DEMO.busy:
        raise HTTPException(409, "already running: %s" % DEMO.busy)
    channel = queue.Queue()

    def emit(event, data):
        channel.put((event, data))

    def runner():
        DEMO.busy = name
        try:
            work(emit)
        # Named "failed", not "error": EventSource dispatches its own native
        # "error" event on every disconnect, and the two must not collide.
        except verify_episode.Fail as fail:
            emit("failed", {"message": "%s: %s" % (fail.code, fail.detail), "reason": fail.code})
        except InvestigationError as exc:
            emit("failed", {"message": str(exc)})
        except Exception as exc:  # a crashed demo should say so, not hang
            emit("failed", {"message": "%s: %s" % (type(exc).__name__, exc)})
        finally:
            DEMO.busy = None
            emit("done", {"state": state_payload()})
            channel.put(None)

    threading.Thread(target=runner, daemon=True).start()

    def stream():
        while True:
            item = channel.get()
            if item is None:
                return
            event, data = item
            yield "event: %s\ndata: %s\n\n" % (event, json.dumps(data))

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/run/events")
def run_events(scenario: str = "poisoned"):
    """Beat 1. EventSource is GET-only, hence a GET that does something."""
    if episode_exists():
        raise HTTPException(409, "an episode is already on disk: reset first")

    def work(emit):
        with DEMO.lock:
            DEMO.reset_soft()
            DEMO.source = "live"
        emit("start", {"scenario": scenario})
        started = time.perf_counter()

        def on_record(body, sign_ms):
            DEMO.sign_ms[body["seq"]] = sign_ms
            emit("record", {"seq": body["seq"], "type": body["type"], "actor": body["actor"],
                            "ts_ns": body["ts_ns"], "prev": body["prev"],
                            "hash": sha3_hex(canon.dumps(body)), "sign_ms": sign_ms,
                            "payload": body["payload"]})

        rec, answer = rag.run_episode(EPISODE_ROOT, scenario=scenario, backend_name="mock",
                                      on_record=on_record)
        emit("recorded", {"count": rec.count, "anchor": rec.anchor, "answer": answer,
                          "elapsed_ms": int((time.perf_counter() - started) * 1000)})

    return sse(work, "run")


@app.get("/api/investigate/events")
def investigate_events():
    """Beat 2. Refuses on RED, because the tool should embody its own argument."""
    if not episode_exists():
        raise HTTPException(409, "no episode on disk: record one first")

    def work(emit):
        with DEMO.lock:
            DEMO.source = "live"

        def on_record(body, sign_ms):
            DEMO.sign_ms[body["seq"]] = sign_ms
            emit("record", {"seq": body["seq"], "type": body["type"], "actor": body["actor"],
                            "ts_ns": body["ts_ns"], "prev": body["prev"],
                            "hash": sha3_hex(canon.dumps(body)), "sign_ms": sign_ms,
                            "payload": body["payload"]})

        investigate(EPISODE_ROOT, echo=lambda line: emit("log", {"line": line}),
                    on_event=lambda kind, data: emit(kind, data), on_record=on_record)

    return sse(work, "investigate")


# --- documents, for the span highlight in beat 2 --------------------------

@app.get("/api/doc")
def get_doc(doc_id: str):
    """Return a corpus document by id. Lookup is by exact key in the loaded corpus."""
    docs = load_docs()
    if doc_id not in docs:
        raise HTTPException(404, "no such document")
    corpus = Corpus(docs)
    return {"doc_id": doc_id, "text": docs[doc_id],
            "chunks": [c.citation() for c in corpus.chunks if c.doc_id == doc_id]}


# --- reset ----------------------------------------------------------------

@app.post("/api/reset")
def post_reset():
    """Back to a blank slate, so beat 1 records live. One keypress, every time."""
    if DEMO.busy:
        raise HTTPException(409, "a run is in progress")
    if os.path.isdir(EPISODE_ROOT):
        shutil.rmtree(EPISODE_ROOT)
    with DEMO.lock:
        DEMO.reset_soft()
    return state_payload()


@app.post("/api/load-golden")
def post_load_golden():
    """The offline fallback. If we show this instead of a live run, we say so."""
    if DEMO.busy:
        raise HTTPException(409, "a run is in progress")
    if not os.path.isdir(GOLDEN_ROOT):
        raise HTTPException(404, "episodes/golden is not present")
    if os.path.isdir(EPISODE_ROOT):
        shutil.rmtree(EPISODE_ROOT)
    shutil.copytree(GOLDEN_ROOT, EPISODE_ROOT)
    with DEMO.lock:
        DEMO.reset_soft()
        DEMO.source = "golden"
    return state_payload()


@app.exception_handler(HTTPException)
def http_error(request, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


def main():
    import uvicorn

    port = int(os.environ.get("FR_PORT", "8000"))
    # Loopback only. This server hands out a write endpoint on purpose; it has no
    # business being reachable from the network.
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
