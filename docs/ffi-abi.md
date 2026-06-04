# libreg C ABI: governing rules

Status: governing rules ratified (issue #107); the concrete symbol list and
`libreg.h` are the library agent's to fill in as Layer 4 `api/` lands (#106).

This document is part of the contract surface. CONTRACTS.md remains the source
of truth for the agent HTTP protocol; this file governs the in-process C ABI
that native bindings (e.g. the Python binding, #108) link against. It carries
the same version as CONTRACTS.md (see "Versioning"). Only the spec agent
writes to it; a change requires a `contracts`-labeled PR and a version bump,
exactly like CONTRACTS.md.

## Why a separate document

The C ABI is a real cross-component interface, so universal rules 1 and 7
apply: it is governed here, and a binding MUST NOT invent types or error codes
the spec has not ratified. It is deliberately NOT folded into CONTRACTS.md:
that document is written around the HTTP wire (transport, JSON envelope,
canonical form, base64/QWORD wire rules, the `/version` handshake), and a
C-symbol/header surface does not belong inside it. Nor is the C ABI a purely
internal libreg surface (the way `logical::Hive`, which only the Rust clients
link by path, is owned by `libreg/CLAUDE.md`): because out-of-process language
bindings depend on it, it needs a ratified, stable contract.

## What this document governs vs defers

Governs now (ratified, #106 must conform):

- The error model across the boundary.
- The value-data and string representation at the boundary.
- Versioning and the backend-id getter.
- Panic safety and buffer ownership.
- The acceptance oracle.

Defers to the library agent (#106), to be recorded here once implemented:

- The exact exported symbol names and signatures.
- The opaque handle type name(s).
- The committed `libreg/include/libreg.h`.

The pattern mirrors ADR 0004: the governing rules are pinned before the
implementation so #106 does not bake in types the spec would reject; the
concrete surface is appended here when the `cdylib` exists, via a follow-up
`contracts` PR, not invented up front.

## Scope

The C ABI exposes the same registry operations CONTRACTS.md defines for the
HTTP protocol, so a binding reaches the whole library: hive lifecycle
(create/load/save/close), keys (create with RegCreateKeyEx intermediates,
delete with a recursive flag, rename, list, info), values (set/get/delete over
all REG_* types), security (get/set SDDL), and diagnostics (canonical dump,
checksum, validate). No operation, type, or error code exists at the C ABI
that is not already defined for the HTTP protocol. This is an additive
in-process surface; it does not change the HTTP agents or the wire protocol.

## 1. Error model

The C ABI reports outcomes as a stable integer error enum that maps **1:1** to
the CONTRACTS.md "Error Codes" table. The names are the single source of truth
in CONTRACTS.md; the C ABI assigns each a stable integer and MUST NOT add a
code, drop one, or diverge in meaning:

`HIVE_NOT_FOUND`, `HIVE_CORRUPT`, `HANDLE_INVALID`, `KEY_NOT_FOUND`,
`KEY_EXISTS`, `VALUE_NOT_FOUND`, `TYPE_MISMATCH`, `ACCESS_DENIED`,
`LOG_CORRUPT`, `KEY_HAS_CHILDREN`, `BAD_REQUEST`, `INTERNAL`, plus a success
value (0).

- A binding surfaces these to its callers under the same code names a HTTP
  caller sees, so the two interfaces agree on what each outcome means.
- The `BAD_REQUEST` vs `INTERNAL` split is preserved at the boundary exactly
  as CONTRACTS.md defines it: `BAD_REQUEST` is a caller error (a malformed
  argument, an unknown constant), `INTERNAL` is a library bug. A binding MUST
  NOT collapse the two.
- The human-readable detail string is exposed through a thread-local
  last-error getter (the integer is the stable contract; the string is
  diagnostic only and not part of it).
- The integer values themselves are assigned by #106 and recorded here once
  fixed; callers should use the names, and the binding maps names to integers
  from the ratified header.

## 2. Value-data and string representation

The HTTP protocol's base64 encoding of binary types and its "REG_QWORD as a
string when > 2^53" rule are **JSON wire artifacts and do NOT apply at the C
ABI**. The C ABI is binary-native:

- Binary value data (REG_BINARY, REG_RESOURCE_LIST, etc.) crosses as a
  `(pointer, length)` pair, not base64.
- 64-bit integers (REG_QWORD) cross as native 64-bit values, not strings.
- Strings (paths, names, SDDL, canonical JSON) cross as length-explicit C
  buffers; a binding MUST NOT rely on NUL termination for binary value data.

Despite the different in-memory representation, **the canonical form remains
the single acceptance oracle**: a hive produced through the C ABI must be
semantically equal (canonical JSON equality, the `semantic` tag) to the same
operations driven through the HTTP agent. Representation at the boundary is an
encoding detail; canonical-form equality is the contract.

## 3. Versioning

The C ABI carries the **same contract version** as CONTRACTS.md, not a
separate one. There is one project contract version; both the HTTP protocol
and the C ABI move with it.

- The ABI exposes a version getter returning the backend id string, identical
  to the agent handshake `backend` field (e.g. `libreg-0.1.0`), so a binding
  and the harness can check it the same way `/version` is checked over HTTP.
- A binding verifies the loaded library's reported version against the version
  it was built for; a major-version mismatch is fatal, mirroring the HTTP
  handshake rule that the harness aborts on a major mismatch.

## 4. Panic safety and ownership

These are correctness requirements at the boundary, ratified here so #106
implements them and bindings may rely on them:

- Every C ABI entry point wraps its body so a Rust panic cannot unwind across
  the FFI boundary; a panic is reported as `INTERNAL`. No undefined behavior
  at the boundary.
- Every buffer the library allocates and hands out is released by a
  library-provided free function with documented ownership; callers do not
  free library memory with their own allocator, and the library does not free
  caller memory.
- Opaque handles are created and destroyed only by the API; Rust structs are
  never exposed across the boundary.

## 5. Acceptance

The harness is the judge (universal rule 3). The acceptance bar for the C ABI
(and for #106) is a binding- or C-driven sequence (create a hive, write each
REG_* type, set and read an SDDL, save, reload, dump) whose result is
semantically equal to the same sequence driven through the HTTP agent.
Wiring an FFI-driven backend into the harness alongside the agent-driven one
is the intended way to keep this honest.

## Downstream

- Library agent (#106): implement Layer 4 `api/` as a `cdylib` conforming to
  the rules above; then record the exported symbols, handle type(s), and the
  committed `libreg/include/libreg.h` here via a follow-up `contracts` PR
  (the spec agent appends them; the library agent supplies them).
- Clients agent (#108): the Python `ctypes` binding targets the ratified code
  names and the binary-native representation above; it does not apply the
  base64 / QWORD-as-string wire rules.
- Spec agent: on the first `cdylib`, append the concrete symbol list to this
  document and confirm the integer enum values, keeping the 1:1 mapping.
