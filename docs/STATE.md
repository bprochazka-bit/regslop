# Spec Agent STATE

Last session: 2026-05-31 (the synthetic offreg corpus landed; used it to
resolve and CLOSE #22/#23 and my open minor-version question, PR #32, and
to validate the 0.1.6 default SD against real offreg bytes). Earlier today:
triaged #22/#23 as bytewise (PR #25); cleared the inbound queue 0.1.3-0.1.6
plus ADR 0004.

## CONTRACTS.md

Current on main: **0.1.6** (all spec PRs through PR #17 merged). Nothing in
flight.

- 0.1.0: initial (merged).
- 0.1.1 PATCH: invariant clarifications + the KEY_COMP_NAME typo fix
  (merged, PR #2).
- 0.1.2 MINOR: resolves the Windows agent's spec requests (merged, PR #4).
  Adds error code KEY_HAS_CHILDREN; clarifies /key/security GET vs POST;
  defines canonical SDDL normalization (see ADR 0003); specifies
  /key/rename subtree preservation and the harness last_write exclusion
  under a renamed path; sharpens the sort comparator.
- 0.1.3 MINOR: ratifies the default security descriptor for a key created
  without an explicit one (offreg-observed, asserted by `semantic`; issue
  #11). Merged, PR #13.
- 0.1.4 MINOR: adds error code BAD_REQUEST for a malformed request (vs
  INTERNAL for an agent bug). Merged, PR #14.
- 0.1.5 PATCH: clarifies /key/create (creates all missing intermediates,
  RegCreateKeyEx-style; KEY_EXISTS only when the leaf exists). Merged,
  PR #16.
- 0.1.6 PATCH: confirms reads are GET carrying params in the JSON body, not
  the query string; rationale in ADR 0001. Merged, PR #17.

## Windows agent requests (resolved 2026-05-30, in 0.1.2)

Source: agents/windows/STATE.md "Spec items to raise" + assumptions.

- KEY_HAS_CHILDREN error code: ADDED in 0.1.2.
- /key/rename last_write: DECISION (with user) = exclude last_write under
  the renamed path from semantic comparison; subtree otherwise preserved.
  In 0.1.2.
- /key/security read vs write: by HTTP method, not sddl presence. In 0.1.2.
- SACL / SDDL canonical form (assumption 6): ADR 0003; compare O/G/D
  always, SACL only when both report one. In 0.1.2.
- Sort comparator (assumption 7): confirmed case-insensitive Unicode
  ordinal, casing preserved; siblings are case-insensitive-unique. In
  0.1.2.

## Issue #6 downstream work: ALL MERGED

The work the 0.1.2 decisions created for the owning agents has landed:

- Windows agent: method-based /key/security dispatch + KEY_HAS_CHILDREN
  mapping (PR #7); no spurious SACL stamped on rename (PR #8).
- Harness: last_write exclusion and ADR-0003 SDDL normalization
  (src/differ/sddl.rs), conformed to 0.1.2 (PR #9).
- Linux agent: emits KEY_HAS_CHILDREN; conformed to 0.1.2 (PR #9).
- Live VM run: harness + Linux agent green against offreg on the shared
  Windows VM (PR #10). `semantic` is GREEN. Issue #6 CLOSED.

## Done this session (all merged to main)

- Verified CONTRACTS.md invariants against Suhanov's "Windows registry file
  format specification" and Google Project Zero's regf writeup (both
  retrieved 2026-05-30).
- docs/hive-format.md: base block, hbin, cell types
  (nk, vk, sk, lf, lh, li, ri, db), value list, encoding rules, and a map
  from each CONTRACTS invariant to its documenting section. (PR #1)
- docs/adr/0001-http-protocol.md (HTTP+JSON over gRPC for v0.1). (PR #1)
- docs/adr/0002-canonical-form.md (sorted keys, dropped sub-second
  precision, base64). (PR #1)
- docs/adr/0003-sddl-security.md (SDDL on the wire, normalized binary diff,
  SACL compared only when both sides report one). (PR #5)
- docs/adr/README.md (ADR index). (PR #1, updated PR #5)
- .github issue templates (spec-question, contract-change, differ-failure)
  and PULL_REQUEST_TEMPLATE.md. (PR #1)
- CONTRACTS 0.1.1 (PR #2) and 0.1.2 (PR #4); created the `contracts` and
  `spec` labels.
- Issue #6: decision table answering the Windows agent, with downstream
  work assigned per subtree. (All downstream PRs merged; issue #6 CLOSED.)
- CONTRACTS 0.1.3 (PR #13, merged): ratified the default security
  descriptor; closed issue #11.
- CONTRACTS 0.1.4 (PR #14, merged): added the BAD_REQUEST error code.
- CONTRACTS 0.1.5 (PR #16, merged): clarified /key/create semantics.
- CONTRACTS 0.1.6 (PR #17, merged): confirmed the GET-body read transport.
- ADR 0004 (PR #18, merged): dual transaction logs + a proposed recovery
  control surface (see Pending ADRs).

## Inbound spec questions from implementation agents

Raised in agents/linux/spec-questions.md and tests/harness/spec-questions.md.
The original queue (the items below) is cleared; none required inventing a
wire endpoint, each pinned existing green behavior or (recovery) was captured
as a design proposal. Two later library questions (#22, #23) are triaged and
corpus-gated; see "Later library questions" below.

- **Default security descriptor for a fresh key (issue #11).** Ratified the
  offreg-observed default
  `O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)` in
  0.1.3; asserted by `semantic`. Issue #11 closed. DOWNSTREAM: the library
  agent built the binary SD codec + this default in libreg (PR #21); the
  create-path consumer is step 4 (not done yet). The Linux MemBackend still
  hardcodes the SDDL as a stand-in.
- **BAD_REQUEST error code (linux Q2).** Added in 0.1.4: malformed request
  (bad JSON, missing/wrong-typed field, unknown constant) returns
  BAD_REQUEST; INTERNAL is reserved for agent bugs on a well-formed request.
  DOWNSTREAM: the Linux agent conformed (PR #26). The Windows agent has NOT
  yet adopted BAD_REQUEST (still INTERNAL/TYPE_MISMATCH); their conformance
  work, flagged in agents/linux/spec-questions.md item 2.
- **/key/create intermediate-key semantics (linux Q3).** Pinned in 0.1.5:
  creates all missing intermediates (RegCreateKeyEx-style), reuses existing
  ones, KEY_EXISTS only when the leaf exists. Verified by reading the
  Windows oracle (offreg/key.rs loops ORCreateKey per level) and the green
  harness tests deep_key_create / key_create_existing_is_error. No
  downstream; both agents already conform.
- **GET-with-JSON-body transport (linux Q5).** Confirmed in 0.1.6: reads are
  GET, params travel in the JSON body, not the query string. Rationale and
  the GET-body caveat (ureq forbids GET bodies, so the harness hand-builds
  the request) are in ADR 0001. No downstream.
- **Recovery-tag control surface (harness Q2).** Captured in ADR 0004 as a
  PROPOSAL (Linux-only POST /test/crash_save), deliberately NOT added to
  CONTRACTS yet (no implementation exists; spec agent does not add endpoints
  without one). DOWNSTREAM (gating): the library agent must prototype
  dual-log recovery + the hook before it enters CONTRACTS as a MINOR.

Resolved/non-action (recorded so they are not re-litigated):
- linux Q1 (non-empty delete) and Q6 (/key/security method dispatch):
  RESOLVED in 0.1.2, confirmed live against offreg.
- linux Q7 / harness "was 1" (timestamp comparison): RESOLVED in 0.1.2
  (timestamps excluded from semantic equality).
- harness Q1 (bytewise applicability): no contract change; the in-memory
  Linux backend cannot emit regf bytes, so bytewise/most-of-structural are
  reported n/a, not counted as passes. Revisit when a real backend lands.
- harness Q3 (SACL-present security sub-tag): deferred to the harness agent
  per ADR 0003; revisit with the corpus loader.

## Later library questions (#22, #23): RESOLVED and CLOSED

Filed by the library agent. First triaged as bytewise-only (PR #25), then
fully answered from the synthetic offreg corpus (PR #29) once it landed. I
parsed the fixtures and verified each claim against the bytes; findings in
docs/hive-format.md 3.3/3.4 via PR #32. Both issues closed.

- **#23 single-subkey create canonical form.** From ref_one_ascii.hiv /
  ref_multi.hiv: offreg emits an `lh` even for one subkey (never `lf`); cells
  laid out root nk, sk, lh, child nk in the root hbin; children share the
  root sk (refcount rises per key); KEY_COMP_NAME per the <= U+00FF rule;
  root nk subkey_count/list-offset updated. For `semantic` only the logical
  form matters; the rest is bytewise.
- **#22 lh non-ASCII name hash.** From ref_latin1.hiv (`Café`): hash =
  (hash*37 + RtlUpcaseUnicodeChar(unit)) & 0xFFFFFFFF over UTF-16 units, full
  Unicode upcase (0x352f57 needs U+00E9 -> U+00C9; ASCII-only would give
  0x352f77). Compressed Latin-1 names expand byte -> UTF-16 unit before
  hashing. Bytewise-only; ASCII was already correct.

Bonus cross-check: the offreg sk descriptor is 144 bytes and decodes to
exactly the 0.1.6 ratified default, byte-content-identical to the library SD
codec (PR #21). offreg's body order is DACL, owner, group (noted for
bytewise; the library codec currently emits owner-first).

## Open spec questions (mine; still NOT resolved; do not guess in code)

1. RESOLVED (0.1.7), issue #34 closed. Invariant 11 promotion threshold: the
   Windows agent added tests/corpus/synthetic/ref_ri.hiv (PR #35, 1100
   subkeys k00000..k01099). Parsed it: the root carries an ri over three lh
   leaves of 507, 507, and 86, so an lh/lf leaf holds at most 507 entries and
   the 508th subkey promotes to ri. NOTE: offreg's 507 is well below the
   live-kernel ~1013 (CmpSplitLeaf); the oracle, not the literature, is what
   the differ checks, so libreg targets 507. Corrected CONTRACTS invariant 11
   from "1015" to 507 and recorded the verification in hive-format.md (0.1.7).

2. RESOLVED from the corpus (PR #32). offreg-10.0.22621 writes minor version
   5 (v1.5) for a freshly created and saved hive (all four
   tests/corpus/synthetic fixtures: major 1, minor 5, seq 1/1, no logs).
   libreg should write minor 5 to match (Hard Rule 4); consistent with
   CONTRACTS "v1.5 hives". Minor 6 is the live-kernel dual-log on-disk
   variant offreg does not produce, so it is out of differential scope and
   relevant only to libreg's own recovery tag (ADR 0004). No CONTRACTS change
   needed; recorded in hive-format.md Versions.

3. class_name in the canonical form. The canonical schema includes
   `class_name`, but no v0.1 operation sets a key class. Either keep it
   (always null until a class-setting op exists) or note it as reserved.
   Leaning keep-as-null; waiting to see if offreg reports nonnull classes
   on any corpus hive.

## ADRs

- 0001 HTTP+JSON: accepted (PR #1); extended PR #17 with the
  query-string-vs-body decision.
- 0002 canonical form: accepted (PR #1).
- 0003 SDDL on the wire / normalized binary diff: accepted (PR #5). The
  semantic-vs-bytewise boundary it implies for subkey lists/hashes was
  spelled out in docs/hive-format.md by PR #25 (triage of #22, #23).
- 0004 dual transaction logs + recovery control surface: PROPOSED (PR #18).
  Documents the dual-log rationale and proposes a Linux-only
  POST /test/crash_save for the recovery tag. NOT in CONTRACTS yet. Moves to
  accepted (and the endpoint enters CONTRACTS as a MINOR) once the library
  agent prototypes log recovery + the hook. The dual-log minor-version
  question (open question 2 below) is flagged unresolved inside it.

## Environment notes (for the next session)

- This worktree (/home/prozac/projects/libreg-spec) is the spec agent.
  `main` is checked out in a sibling worktree (/home/prozac/projects/libreg),
  so `git checkout main` FAILS here. To branch for a PR: `git fetch`, then
  `git branch -f <name> origin/main && git checkout <name>` (or fast-forward
  the current branch onto origin/main and stash any working-tree edit).
- gh is installed (2.45.0) and authenticated as bprochazka-bit. Merging via
  `gh pr merge --delete-branch` cannot delete the branch locally (worktree
  layout) and may leave the remote branch; delete it with
  `gh api -X DELETE repos/bprochazka-bit/regslop/git/refs/heads/<branch>`.
- Remote is `git@github.com:bprochazka-bit/regslop.git`. Labels `contracts`
  and `spec` exist. Other agents work in sibling worktrees: libreg-windows,
  libreg-library, libreg-harness, libreg-fuzz.

## What I would do next

The inbound queue is empty. Remaining work is blocked on other agents or on
corpus/VM availability, not on a spec decision:

- Watch for downstream follow-ups and review any PR touching CONTRACTS.md or
  crossing a subtree boundary. Status as of this session:
  - Library: SD codec + ratified default landed (PR #21); Layer 1 allocator
    landed (PR #27). Still owed: the step 4 create path that consumes the
    default, and the dual-log recovery + /test/crash_save prototype (ADR
    0004).
  - Linux agent: conformed to BAD_REQUEST (PR #26).
  - Windows agent: still owes BAD_REQUEST conformance (item flagged in
    agents/linux/spec-questions.md item 2). Not a spec question; nudge if a
    malformed-request differential test is added.
- When the ADR 0004 hook lands, add POST /test/crash_save to CONTRACTS as a
  MINOR (test-mode, Linux only, Windows not_supported) and move ADR 0004 to
  accepted.
- Resolve my open questions 1 (invariant 11 split point) and 2 (dual-log
  minor version, 5 vs 6) once a corpus hive or the live VM can dump the
  relevant structures; fold answers into hive-format.md and a follow-up
  PATCH, and reconcile the CONTRACTS "Transaction Log Behavior" wording.
- Decide open question 3 (class_name) once offreg is seen reporting a
  nonnull class on a corpus hive.
