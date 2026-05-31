# ADR 0001: HTTP + JSON for the agent protocol

- Status: accepted
- Date: 2026-05-30
- Deciders: spec agent
- Scope: the wire protocol between the harness and the two agents
  (CONTRACTS.md "Agent HTTP Protocol")

## Context

The differential harness drives two agents that must be interchangeable:
the Linux agent (wrapping libreg) and the Windows agent (wrapping
offreg.dll, cross-compiled and run on a Windows VM). The harness sends the
same operation sequence to both, collects results, and diffs them.

Constraints that shaped the choice:

- The Windows agent is cross-compiled from Linux with the `windows` crate
  and runs on a separate VM reached over the LAN. The transport must cross
  a network boundary, not just a process boundary.
- Operation sequences are authored and inspected by humans and generated
  in bulk by the fuzzer. Readability of requests on the wire helps when
  debugging differ failures (CLAUDE.md "reproduce manually with curl").
- The two agents are written by different agents who do not read each
  other's code. A schema they can each implement independently, and that
  the harness can validate, matters more than raw throughput.
- v0.1 is single-writer, one request at a time per handle
  (agents/windows/CLAUDE.md rule 6). There is no streaming or
  long-lived-session requirement.

## Decision

Use HTTP/1.1 with JSON request and response bodies. One uniform envelope
`{ "ok", "error", "data" }` with a stable `code` on errors. Endpoints and
schemas are fixed in CONTRACTS.md.

## Alternatives considered

### gRPC / protobuf

Pros: typed schema, codegen for both Rust agents, efficient framing,
streaming if ever needed.

Cons: the `.proto` becomes a second source of truth competing with
CONTRACTS.md, and codegen drift between the two agents would be a class of
bug the project specifically wants to avoid. Not inspectable with curl. No
streaming requirement to justify the framing. Cross-compiling the gRPC
stack for `x86_64-pc-windows-gnu` alongside the `windows` crate adds build
risk for the one agent that is hardest to build. Rejected for v0.1;
revisit if performance targets (deferred to v0.2) demand it.

### Raw TCP with a custom binary frame

Pros: minimal dependencies, total control.

Cons: every agent reimplements framing and parsing; no off-the-shelf
debugging; the fuzzer and harness would both need a hand-written codec.
The hive bytes themselves are the only large payloads, and those are
exchanged as paths/handles or base64, not streamed. Rejected.

### FFI / in-process linking

Pros: fastest, no network.

Cons: impossible. offreg.dll runs on Windows; libreg is a Linux library.
The whole point of the architecture is that the oracle is a real Windows
process. Rejected as infeasible.

### Read parameters in the query string vs the request body

Reads (`/key/list`, `/key/info`, `/value/get`, `/key/security` GET, the
`/hive/*` diagnostics) need parameters: a handle, a path, sometimes a value
name. Two ways to carry them.

Query string: the conventional REST shape, and it sidesteps the "GET with a
body" oddity (RFC 7231 leaves a GET body's semantics undefined, and some
HTTP stacks drop or forbid it).

Request body: every endpoint, read or write, then takes the same JSON object
under the same envelope, so a request differs from its write counterpart
only by method. One schema per endpoint, no separate query-string encoding
to define, escape, and keep in sync across both agents and the harness.
Paths contain backslashes and value names can be empty or contain arbitrary
characters, which query-string encoding handles but adds a second escaping
layer the body avoids.

We chose the body. This is a closed transport: two custom agents on a LAN
with the harness as the only client, so there are no intermediary proxies or
caches to strip a GET body. The one place it bites is client libraries that
forbid GET bodies (the harness uses `ureq`, whose typed builder refuses
them), so the harness sends reads through a hand-built `http::Request`; this
is a client-side detail, not a contract change. Agents route reads on path,
except `/key/security` which routes on method per CONTRACTS 0.1.2 (GET reads,
POST writes). If a future transport must cross a boundary that mangles GET
bodies, revisit this and move read params to the query string then.

## Consequences

- Large binary payloads (hive files, security descriptors, big REG_BINARY
  values) are base64 in JSON or exchanged by path/handle, never streamed.
  Acceptable at v0.1 sizes; flagged for v0.2 if big-data fuzzing strains
  it.
- Numbers above 2^53 cannot be represented exactly as JSON numbers, so
  REG_QWORD is sent as a string when it exceeds 2^53 (CONTRACTS value
  table). This is a direct consequence of choosing JSON.
- The envelope and `code` field let the harness match errors
  programmatically without parsing prose (CONTRACTS "Error Codes").
- Versioning is in-band via `GET /version`; the harness aborts on major
  mismatch (CONTRACTS "Versioning").
- The protocol is human-debuggable with curl, which CLAUDE.md relies on
  for reproducing differ failures.
