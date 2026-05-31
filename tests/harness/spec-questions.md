# Harness: Open Spec Questions

Questions for the spec agent (issue tag `spec`).

## Resolved in CONTRACTS 0.1.2 / ADR 0003

- **(was 1) Cross-agent `last_write` comparison.** RESOLVED: 0.1.2 states
  timestamps are excluded from semantic equality (option (a)), and additionally
  that every key under a renamed path has `last_write` excluded (the Windows
  oracle emulates rename by subtree copy, which resets descendant timestamps).
  The differ's default `ignore_timestamps: true` drops every `last_write`, which
  subsumes the renamed-path rule. Strict mode remains available.
- **(was 4) Error-code expectations / negative tests.** PARTIALLY RESOLVED:
  0.1.2 adds `KEY_HAS_CHILDREN` for non-recursive delete of a key with subkeys
  (was `ACCESS_DENIED` on the Linux side, `INTERNAL` on the Windows side; both
  now use the new code). The op-level `expect_error: CODE` convention is
  unchanged and still a harness layer, not a wire change.
- **SDDL comparison.** RESOLVED by ADR 0003 and 0.1.2: equality is decided on
  the normalized descriptor (owner, group, DACL always; SACL only when both
  sides report one). Implemented in `src/differ/sddl.rs`. A one-sided SACL is a
  warning, never a `semantic` failure.

## Still open

1. **Bytewise applicability.**
   `bytewise` is only meaningful when both agents produce real hive bytes with
   matching allocator behavior. The current Linux backend is in-memory and does
   not emit a `regf` file, so `bytewise` and most of `structural` (invariants 1
   to 18 over raw bytes) cannot be evaluated against it. Those tags are reported
   honestly (n/a or skipped) rather than counted as passes. No contract change
   needed, but noted so the green report is not misread.

2. **Recovery tag preconditions.**
   The recovery harness (crash injection between log write and primary write)
   needs an agent hook to abort mid-save deterministically. CONTRACTS.md
   mentions a "separate test mode that simulates crashes" but does not define
   the control surface. Requesting a spec for how the harness triggers it.

3. **Dedicated `security` sub-tag for SACL-present cases.**
   ADR 0003 defers (to the harness agent) whether to add a sub-tag so
   SACL-present descriptors can be exercised explicitly once a SACL-readable
   corpus hive exists. Today the one-sided-SACL path is covered only by a unit
   test; no synthetic op sequence emits a two-sided SACL. Revisit with the
   corpus loader.
