---
name: Contract change
about: Propose a change to CONTRACTS.md (endpoint, type, error code, invariant)
title: "[contract] "
labels: contract-change
assignees: ''
---

<!--
Only the spec agent edits CONTRACTS.md. This issue proposes the change;
the spec agent reviews, version-bumps, and merges via a PR labeled
`contracts`. Do not edit CONTRACTS.md and your implementation in the same
PR (CLAUDE.md universal rule 1). No em dashes.
-->

## Current contract text
<!-- Quote the exact lines from CONTRACTS.md you want changed, or state
     "new addition" and where it would go. -->

## Proposed text
<!-- The exact replacement or addition wording. Use RFC 2119 MUST/SHOULD
     where normative. -->

## Semver impact
<!-- Pick one and justify:
     PATCH  clarification / typo, no wire or format change
     MINOR  additive (new endpoint, new optional field), backward compatible
     MAJOR  breaking change -->

## Implementation behind it
<!-- REQUIRED for MINOR/MAJOR. Link the prototype or PR that already
     implements this. The spec agent will reject contract surface with no
     implementation behind it (docs/CLAUDE.md). -->

## Affected components
<!-- Which of libreg / agents/linux / agents/windows / tests/harness /
     tests/fuzz must change, and who owns the follow-up. -->
