#!/usr/bin/env bash
# Three beats, three minutes. Hermetic: no network, mock LLM, nothing to fail.
set -u

EPISODE="${1:-episode}"
PY="${PY:-python3}"
cd "$(dirname "$0")/.."

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '\033[2m$ %s\033[0m\n' "$*"; }
pause() { [ -n "${FAST:-}" ] || sleep "${1:-1}"; }

rm -rf "$EPISODE"

bold "BEAT 1 - the incident is recorded"
echo "The agent is asked to summarize the vendor onboarding policy. It retrieves five"
echo "chunks, one of them poisoned, and calls http_post - a tool this task never authorized."
pause
step "$PY -m agent.rag --scenario poisoned --out $EPISODE"
$PY -m agent.rag --scenario poisoned --out "$EPISODE" || exit 1
pause
step "$PY verify_episode.py $EPISODE"
$PY verify_episode.py "$EPISODE" || exit 1
echo "                                                          exit $?"
pause 2

bold "BEAT 2 - the investigator proves causation"
echo "It refuses to run on a RED episode, replays the episode with inputs ablated, and"
echo "signs its verdict into the same chain."
pause
step "$PY -m investigator.cli $EPISODE"
$PY -m investigator.cli "$EPISODE" || exit 1
pause
step "$PY verify_episode.py $EPISODE"
$PY verify_episode.py "$EPISODE" || exit 1
echo "The investigation did not break the chain. It extended it."
pause 2

bold "BEAT 3 - one character"
TARGET=$($PY - "$EPISODE" <<'EOF'
import json, os, sys
records = os.path.join(sys.argv[1], "records")
for name in sorted(os.listdir(records)):
    path = os.path.join(records, name)
    if json.load(open(path))["body"]["type"] == "TOOL_CALL":
        print(path)
        break
EOF
)
step "$PY demo/tamper.py $TARGET"
$PY demo/tamper.py "$TARGET"
pause
step "$PY verify_episode.py $EPISODE"
$PY verify_episode.py "$EPISODE"
echo "                                                          exit $?"

bold "The operator could edit the file. They could not make the edit survive verification."
echo "Every row of the failure taxonomy is a scripted answer - try one yourself:"
echo "  \$ $PY demo/tamper.py $EPISODE --find '\"authorized\": false' --replace '\"authorized\": true'"
echo "  \$ rm $EPISODE/records/000004.json && $PY verify_episode.py $EPISODE"
