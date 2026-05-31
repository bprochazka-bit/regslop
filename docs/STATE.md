# Spec Agent STATE

Last session: 2026-05-30

## CONTRACTS.md

- 0.1.0: initial (merged).
- 0.1.1 PATCH: invariant clarifications + the KEY_COMP_NAME typo fix
  (merged, PR #2).
- 0.1.2 MINOR: resolves the Windows agent's spec requests (PR #4, branch
  `spec/contracts-0.1.2`). Adds error code KEY_HAS_CHILDREN; clarifies
  /key/security GET vs POST; defines canonical SDDL normalization (see ADR
  0003); specifies /key/rename subtree preservation and the harness
  last_write exclusion under a renamed path; sharpens the sort comparator.

## Windows agent requests (resolved 2026-05-30)

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

Downstream work this creates (for the owning agents, not the spec agent):
library emits KEY_HAS_CHILDREN and may preserve rename timestamps; harness
implements the last_write exclusion and the SDDL normalization; Windows
agent switches to method-based security dispatch and maps the
key-has-children case to the new code.

## Done this session

- Verified CONTRACTS.md invariants against Suhanov's "Windows registry file
  format specification" and Google Project Zero's regf writeup (both
  retrieved 2026-05-30).
- Wrote docs/hive-format.md: base block, hbin, cell types
  (nk, vk, sk, lf, lh, li, ri, db), value list, encoding rules, and a map
  from each CONTRACTS invariant to its documenting section.
- Wrote docs/adr/0001-http-protocol.md (HTTP+JSON over gRPC for v0.1).
- Wrote docs/adr/0002-canonical-form.md (sorted keys, dropped sub-second
  precision, base64).
- Wrote docs/adr/README.md (ADR index).
- Wrote .github issue templates (spec-question, contract-change,
  differ-failure) and PULL_REQUEST_TEMPLATE.md.

## Verification findings (feed the 0.1.1 PATCH)

Confirmed correct against the references: invariants 1, 2, 5, 6, 9
(header = 32), 10, 12 (16344, minor > 3), 13, 14, 15, 17; nk/vk/sk/db
layouts; KEY_COMP_NAME = 0x0020; checksum quirks (0 -> 1, 0xFFFFFFFF ->
0xFFFFFFFE).

Clarifications / typos to fix in CONTRACTS.md (all PATCH, no wire change):

1. Invariant 3 checksum: "XOR of dwords 0..507" is imprecise. It is the
   XOR of the first 127 little-endian u32 values (bytes 0..507), plus the
   0 -> 1 and 0xFFFFFFFF -> 0xFFFFFFFE quirks. Reword.
2. Invariant 4: "Total size (base block dword 40)" is the HIVE BINS DATA
   SIZE and excludes the 4096-byte base block. Clarify wording.
3. Invariant 9: state the hbin header is 32 bytes explicitly.
4. Invariant 16: "VALUE_COMP_NAME" is a typo; the nk name-compression flag
   is KEY_COMP_NAME (0x0020). (VALUE_COMP_NAME exists separately as the vk
   flag for value names.) Fix.

## Open spec questions (NOT resolved; do not guess in code)

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
  (docs PR with this STATE update).
- 0004 dual transaction logs design rationale (why two logs, recovery
  ordering). Still pending; write alongside resolving the minor-version
  open question.

## Environment note

This worktree (/home/prozac/projects/libreg-spec) tracks branch
spec/docs-bootstrap; `main` lives in a sibling worktree
(/home/prozac/projects/libreg) so `git checkout main` fails here by design.
The contracts branch was created from the base commit directly.

## What I would do next

- Open the two PRs (docs bootstrap; contracts 0.1.1 PATCH). gh is not
  installed on this box; PRs were pushed and must be created from the
  GitHub compare URLs (see session summary).
- Once a corpus hive is available, resolve open questions 1 and 2 and fold
  the answers into hive-format.md and a follow-up contracts PATCH.
- Draft ADR 0003 when the first security operation lands.
