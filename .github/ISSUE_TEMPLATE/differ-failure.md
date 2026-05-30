---
name: Differ failure
about: Report a harness divergence between the Linux and Windows agents
title: "[differ] "
labels: differ
assignees: ''
---

<!--
File this when the harness reports a divergence. The harness does not
decide which side is correct (tests/harness/CLAUDE.md rule 1); report which
agent diverged from canonical and let the owning agent investigate. Attach
the reproducible artifacts. No em dashes.
-->

## Tag
<!-- One of: semantic, structural, bytewise, roundtrip, recovery, fuzz.
     Reminder: bytewise failure with semantic pass is a WARNING, not a
     failure (CONTRACTS "Test Categories"). Only file if it is a real
     failure for its tag. -->

## Operation that diverged
<!-- The endpoint / operation named in the harness output, e.g.
     value_set REG_MULTI_SZ with embedded null. -->

## Which side diverged from canonical
<!-- linux, windows, or "both differ from each other". Quote the
     differing canonical JSON lines. -->

## Reproducer
<!-- Path to the failure dir written by the harness:
     tests/harness/results/<ts>/failures/<id>/
     It should contain the operation sequence, both hives, both dumps.
     For fuzz findings include the seed and the libreg commit hash. -->

```yaml
# Minimal operation sequence that reproduces (paste here)
```

## curl reproduction
<!-- CLAUDE.md "When in Doubt": reproduce manually with curl against both
     agents before reporting. Paste the two commands and their responses. -->

## Suspected owner
<!-- library / agents-linux / agents-windows. Best guess only; the owning
     agent confirms. -->
