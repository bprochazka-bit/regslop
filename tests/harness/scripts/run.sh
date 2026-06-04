#!/usr/bin/env bash
# Start the Linux agent, optionally point at a Windows agent, run the harness.
#
# Usage:
#   run.sh [--linux-port N] [--windows-host HOST] [--windows-port N]
#          [--standin] [--ffi] [--tag TAG] [--windows-smb]
#
# --standin starts a SECOND local Linux agent to stand in for the Windows side
# during bring-up, so the full differential path (semantic, bytewise) exercises
# before the real Windows agent exists. The two agents are protocol identical;
# the harness treats them interchangeably.
#
# --ffi is the C ABI acceptance (issue #112): the primary agent runs the rlib
# backend (--backend libreg) and the peer runs the C ABI backend (--backend ffi),
# so the same operation sequences are driven through libreg directly and through
# its Layer 4 cdylib surface and the result hives are diffed. Green on semantic
# is the acceptance bar for the C ABI (#106) and the Python binding (#108).
#
# --windows-smb (passed through to the harness) pulls each saved Windows hive
# off the VM over the `winreg` SMB share and runs the byte-level structural
# invariants on offreg's live output. Needs a real offreg agent (not --standin)
# and smbclient on this box.
#
# Builds in release. Cleans up spawned agents on exit. Debian first: native
# binaries, no containers.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$REPO_ROOT/tests/harness"
LINUX_AGENT_DIR="$REPO_ROOT/agents/linux"

LINUX_PORT=7878
WINDOWS_HOST=""
WINDOWS_PORT=7879
STANDIN=0
FFI=0
PRIMARY_BACKEND=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux-port) LINUX_PORT="$2"; shift 2 ;;
    --windows-host) WINDOWS_HOST="$2"; shift 2 ;;
    --windows-port) WINDOWS_PORT="$2"; shift 2 ;;
    --standin) STANDIN=1; shift ;;
    --ffi) FFI=1; STANDIN=1; PRIMARY_BACKEND="libreg"; shift ;;
    --tag) EXTRA_ARGS+=(--tag "$2"); shift 2 ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

echo "Building Linux agent and harness (release) ..."
( cd "$LINUX_AGENT_DIR" && cargo build --release )
( cd "$HARNESS_DIR" && cargo build --release )

AGENT_BIN="$LINUX_AGENT_DIR/target/release/libreg-agent-linux"
HARNESS_BIN="$HARNESS_DIR/target/release/libreg-harness"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

PRIMARY_ARGS=(--port "$LINUX_PORT")
[[ -n "$PRIMARY_BACKEND" ]] && PRIMARY_ARGS+=(--backend "$PRIMARY_BACKEND")
echo "Starting Linux agent on port $LINUX_PORT ${PRIMARY_BACKEND:+(--backend $PRIMARY_BACKEND)} ..."
"$AGENT_BIN" "${PRIMARY_ARGS[@]}" &
PIDS+=($!)

if [[ "$STANDIN" == "1" ]]; then
  if [[ "$FFI" == "1" ]]; then
    echo "Starting C ABI peer agent on port $WINDOWS_PORT (--backend ffi) ..."
    "$AGENT_BIN" --port "$WINDOWS_PORT" --backend ffi &
  else
    echo "Starting stand-in Linux agent on port $WINDOWS_PORT (poses as windows) ..."
    "$AGENT_BIN" --port "$WINDOWS_PORT" &
  fi
  PIDS+=($!)
  WINDOWS_HOST="127.0.0.1"
fi

sleep 1

HARNESS_CMD=("$HARNESS_BIN"
  --linux-port "$LINUX_PORT"
  --tests-dir "$HARNESS_DIR/tests"
  --results-dir "$HARNESS_DIR/results"
  --corpus-dir "$REPO_ROOT/tests/corpus/synthetic")
if [[ -n "$WINDOWS_HOST" ]]; then
  HARNESS_CMD+=(--windows-host "$WINDOWS_HOST" --windows-port "$WINDOWS_PORT")
fi
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  HARNESS_CMD+=("${EXTRA_ARGS[@]}")
fi

echo "Running harness ..."
"${HARNESS_CMD[@]}"
