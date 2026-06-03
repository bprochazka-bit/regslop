#!/usr/bin/env bash
# Start the libreg-backed Linux agent and run a fuzzer against it through the
# differential harness. Mirrors tests/harness/scripts/run.sh, but the target is
# the real libreg backend (the point is to find libreg bugs) and the driver is
# one of the fuzzer binaries.
#
# Usage:
#   run-fuzz.sh [op|data|hive] [--standin] [--count N] [--seed S] [-- <extra fuzzer args>]
#
# Modes:
#   op    operation fuzzer   (default)
#   data  value-payload fuzzer
#   hive  structure-aware hive mutation fuzzer
#
# --standin starts a SECOND agent (in-memory backend) on the windows port so the
# semantic and bytewise axes have a second, independent implementation to diff
# libreg against. Without it the run is single-agent: structural and roundtrip
# are graded against libreg alone (still catches crashes, invariant violations,
# and save/reload bugs). NOTE: both agents share /tmp paths, so the standin path
# is best-effort; single-agent is the dependable default.
#
# Builds in release. Cleans up spawned agents on exit. Debian first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$REPO_ROOT/tests/harness"
LINUX_AGENT_DIR="$REPO_ROOT/agents/linux"
FUZZ_DIR="$REPO_ROOT/tests/fuzz"

MODE="op"
case "${1:-op}" in
  op|data|hive) MODE="$1"; shift || true ;;
esac

LINUX_PORT=7878
WINDOWS_PORT=7879
STANDIN=0
PASSTHRU=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --standin) STANDIN=1; shift ;;
    --linux-port) LINUX_PORT="$2"; shift 2 ;;
    --) shift; while [[ $# -gt 0 ]]; do PASSTHRU+=("$1"); shift; done ;;
    *) PASSTHRU+=("$1"); shift ;;
  esac
done

echo "Building libreg agent, harness, and fuzzers (release) ..."
( cd "$LINUX_AGENT_DIR" && cargo build --release )
( cd "$HARNESS_DIR" && cargo build --release )
( cd "$FUZZ_DIR" && cargo build --release )

AGENT_BIN="$LINUX_AGENT_DIR/target/release/libreg-agent-linux"
HARNESS_BIN="$HARNESS_DIR/target/release/libreg-harness"
FUZZ_BIN="$FUZZ_DIR/target/release/${MODE}_fuzz"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "Starting libreg agent on port $LINUX_PORT (backend=libreg) ..."
"$AGENT_BIN" --port "$LINUX_PORT" --backend libreg &
PIDS+=($!)

FUZZ_ARGS=(--harness-bin "$HARNESS_BIN" --linux-port "$LINUX_PORT")
if [[ "$STANDIN" == "1" ]]; then
  echo "Starting stand-in agent on port $WINDOWS_PORT (backend=mem, poses as windows) ..."
  "$AGENT_BIN" --port "$WINDOWS_PORT" --backend mem &
  PIDS+=($!)
  FUZZ_ARGS+=(--windows-host 127.0.0.1 --windows-port "$WINDOWS_PORT")
fi

sleep 1
echo "Running ${MODE}_fuzz ..."
cd "$REPO_ROOT"
"$FUZZ_BIN" "${FUZZ_ARGS[@]}" "${PASSTHRU[@]}"
