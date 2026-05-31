<!--
libreg PR. No em dashes anywhere (CLAUDE.md universal rule 4).
Stay in your subtree (rule 2). Cross-subtree or CONTRACTS.md changes are
the spec agent's to review.
-->

## What and why
<!-- One paragraph. What changed and the reason. -->

## Subtree
<!-- Which subtree you own and are changing:
     libreg / agents/linux / agents/windows / tests/harness / tests/fuzz /
     docs+contracts (spec agent). -->

## Contracts
- [ ] This PR does NOT touch CONTRACTS.md, or
- [ ] This PR is labeled `contracts`, bumps the version, and contains NO
      implementation changes (CLAUDE.md universal rule 1).

## Cross-subtree
- [ ] This PR touches only my subtree, or
- [ ] It crosses a boundary and I have added a coordination note below and
      tagged the spec agent for review.

<!-- Coordination note (if crossing boundaries): -->

## Harness
<!-- CLAUDE.md universal rule 3: a feature is not done until the harness is
     green on at least the `semantic` tag. -->
- [ ] Harness run attached or referenced (paste the per-tag summary), or
- [ ] N/A (docs/spec only, or harness not yet able to test this)

## STATE.md
- [ ] I updated my subtree's STATE.md (CLAUDE.md universal rule 6).

## Checklist
- [ ] No em dashes.
- [ ] No invented endpoints, types, or error codes (CLAUDE.md rule 7).
- [ ] I read CONTRACTS.md before any cross-component change (rule 1).
