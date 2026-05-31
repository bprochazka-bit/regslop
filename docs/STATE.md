# Spec Agent STATE

Last session: 2026-05-31 (wrap-up after the implementation agents conformed
to 0.1.2 and went green against the live offreg VM).

## CONTRACTS.md

Current on main: **0.1.2** (all spec PRs merged). No bump this session.

- 0.1.0: initial (merged).
- 0.1.1 PATCH: invariant clarifications + the KEY_COMP_NAME typo fix
  (merged, PR #2).
- 0.1.2 MINOR: resolves the Windows agent's spec requests (merged, PR #4).
  Adds error code KEY_HAS_CHILDREN; clarifies /key/security GET vs POST;
  defines canonical SDDL normalization (see ADR 0003); specifies
  /key/rename subtree preservation and the harness last_write exclusion
  under a renamed path; sharpens the sort comparator.

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
  Windows VM (PR #10). `semantic` is GREEN. Issue #6 can be closed.

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
  work assigned per subtree. (All downstream PRs now merged; see above.)

## Inbound spec questions from implementation agents (NEED A DECISION)

New since 0.1.2; raised in agents/linux/spec-questions.md and
tests/harness/spec-questions.md. These are the spec agent's queue. None
invent wire endpoints; each ships a provisional behavior so the harness
stays green, but they want the contract pinned.

1. **Default security descriptor for a fresh key (issue #11, `contracts`).**
   CONTRACTS.md does not specify the SDDL a newly created key inherits. The
   first live differential run showed the old 2-ACE placeholder diverging
   from offreg on every key. The Linux agent captured offreg's actual
   default from the VM and set DEFAULT_SDDL to match:
   `O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)`
   (SYSTEM full, Administrators full, Everyone read, Restricted Code read,
   all container-inheritable). `semantic` is GREEN with it. ACTION: ratify
   this (or a deliberately chosen default) in CONTRACTS.md as 0.1.3. This is
   the highest-priority open item: a stand-in MemBackend default is in the
   wire path with no contract behind it.

2. **BAD_REQUEST error code (linux Q2).** No code for a malformed request
   (missing field / bad JSON); the agent uses INTERNAL provisionally. A
   dedicated code would let the harness tell caller bugs from agent bugs.
   ACTION: decide add-code (MINOR) vs keep-INTERNAL; record either way.

3. **/key/create intermediate-key semantics (linux Q3).** Linux ships
   RegCreateKeyEx semantics (create all intermediate keys; KEY_EXISTS only
   when the final component exists). offreg ORCreateKey may create a single
   key requiring parents. Live differ is green so far, but the contract is
   silent. ACTION: state the intended semantics in CONTRACTS.md.

4. **GET-with-JSON-body transport (linux Q5).** Reads are GET with a JSON
   body; the agent routes on path and accepts a body on any method, and the
   harness sends GET bodies via a low-level builder. ACTION: confirm this
   transport is intended, or move read params to the query string. Likely
   just a confirmation + a sentence in the HTTP ADR.

5. **Recovery-tag control surface (harness Q2).** CONTRACTS.md mentions "a
   separate test mode that simulates crashes" but defines no control
   surface for aborting mid-save deterministically. The recovery tag is
   blocked until this is specified. ACTION: spec the crash-injection hook
   (ties into ADR 0004, dual logs).

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

## Open spec questions (mine; still NOT resolved; do not guess in code)

1. Invariant 11 promotion threshold "1015". Public sources checked
   2026-05-30 (Project Zero regf writeup, Eric Zimmerman's parser) put the
   lh/lf leaf maximum near 1013, with li splitting around 508, so "1015" is
   close but off by a couple and version dependent; sources also disagree
   on the exact number. Decision: treat the leaf->ri split point as
   offreg-defined. libreg matches offreg (libreg rule 4); the harness
   2000-subkey test (libreg step 8) establishes the real boundary. Did NOT
   change the number in CONTRACTS.md. Revisit once the Windows agent can
   dump a wide key and the harness reports the actual split count, then
   replace "1015" with the empirical value or with "offreg-defined".

2. Dual-log minor version. CONTRACTS "Transaction Log Behavior" says "v1.5
   hives (Windows 8.1+)". The on-disk base-block minor version for dual
   logging is 6, not 5. Confirm what libreg actually writes against a
   corpus hive before pinning, then reconcile the CONTRACTS wording. Held
   pending corpus availability (tests/corpus is gitignored / downloaded
   separately).

3. class_name in the canonical form. The canonical schema includes
   `class_name`, but no v0.1 operation sets a key class. Either keep it
   (always null until a class-setting op exists) or note it as reserved.
   Leaning keep-as-null; waiting to see if offreg reports nonnull classes
   on any corpus hive.

## Pending ADRs

- 0003 SDDL on the wire / normalized binary diff: WRITTEN and accepted
  (PR #5).
- 0004 dual transaction logs design rationale (why two logs, recovery
  ordering) + the crash-injection control surface for the recovery tag
  (inbound question 5). Still pending; write alongside resolving the
  minor-version open question.

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

- Ratify the default SDDL (issue #11) in a 0.1.3 CONTRACTS PR, labeled
  `contracts`, on its own (rule 1: no contract change bundled with anything
  else). Decide between offreg's captured default and a deliberately chosen
  one, then have the Linux and library agents conform. Highest priority.
- In the same or a sibling contracts pass, decide BAD_REQUEST (inbound 2),
  pin /key/create intermediate-key semantics (inbound 3), and confirm the
  GET-body transport in the HTTP ADR (inbound 4).
- Draft ADR 0004 (dual transaction logs) covering the recovery-tag
  crash-injection control surface (inbound 5) alongside open question 2.
- Resolve my open questions 1 (invariant 11 split point) and 2 (dual-log
  minor version) once a corpus hive or the live VM can dump the relevant
  structures; fold answers into hive-format.md and a follow-up PATCH.
- Decide open question 3 (class_name) once offreg is seen reporting a
  nonnull class on a corpus hive.
- Close issue #6 (all downstream PRs merged).
