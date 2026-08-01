#!/usr/bin/env bash
#
# The three-beat flightrec demo. Runs with no API key and no network.
#
#   bash scripts/demo.sh              # beat 2 runs the investigation live from the cache
#   bash scripts/demo.sh --canned     # beat 2 verifies the committed post-investigation bundle
#   bash scripts/demo.sh --no-pause   # do not wait for a keypress between beats
#
# The committed bundles are never modified: everything happens in a copy under
# /tmp, so the demo is idempotent and can be rehearsed from the same checkout.

set -euo pipefail
cd "$(dirname "$0")/.."

CANNED=0
PAUSE=1
for arg in "$@"; do
  case "$arg" in
    --canned)   CANNED=1 ;;
    --no-pause) PAUSE=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

WORK=/tmp/flightrec_demo
TAMPERED=/tmp/flightrec_tampered
PYTHON=${PYTHON:-python3}

rm -rf "$WORK" "$TAMPERED"
if [[ "$CANNED" == "1" ]]; then
  cp -r episode_demo_done "$WORK"
else
  cp -r episode_demo "$WORK"
fi

rule() { printf '\n\033[1m%s\033[0m\n\n' "$1"; }

pause() {
  [[ "$PAUSE" == "1" && -t 0 ]] || return 0
  printf '\n\033[2m-- press enter --\033[0m'
  read -r
  printf '\n'
}

# The verifier exits 1 on a bad bundle, which is a result and not an error.
verify() {
  local status=0
  "$PYTHON" verifier/verify_cli.py --episode "$1" --trust trust --corpus data/corpus || status=$?
  echo "exit=$status"
  return 0
}

rule "BEAT 1 — here is what the agent did, and you can check it yourself"
echo "An agent answered a refund question over ten support documents."
echo "This bundle is what it recorded. We hold only the public keys in trust/."
echo
verify "$WORK"
pause

rule "BEAT 2 — which document made it do that?"
if [[ "$CANNED" == "1" ]]; then
  echo "(canned) the committed post-investigation bundle:"
else
  echo "Replay the episode once per document, each time with that document removed."
  echo "Every model call comes from the cache, so this is a controlled experiment."
  echo
  "$PYTHON" scripts/investigate.py --episode "$WORK" --demo-keys
  echo
fi
verify "$WORK"
pause

rule "BEAT 3 — now let us tamper with it"
"$PYTHON" scripts/tamper.py flip --episode "$WORK" --out "$TAMPERED" --force
echo
verify "$TAMPERED"

rule "One character changed. The bundle can no longer speak for itself."
