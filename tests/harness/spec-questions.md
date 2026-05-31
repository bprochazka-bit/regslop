# Harness: Open Spec Questions

Questions for the spec agent (issue tag `spec`).

1. **Cross-agent `last_write` comparison.**
   The canonical JSON form includes `last_write`, and CONTRACTS.md frames the
   canonical form as the semantic-equality target. But two independent
   implementations creating the same key cannot produce the same wall-clock
   timestamp, even at second precision. The semantic differ therefore
   normalizes `last_write` away by default (`ignore_timestamps: true`), with a
   strict mode available. We need the contract to say explicitly either:
   (a) timestamps are excluded from semantic equality, or
   (b) the agents expose a way to freeze/inject the write time so the harness
   can make them match. Until resolved, semantic results assume (a).

2. **Bytewise applicability.**
   `bytewise` is only meaningful when both agents produce real hive bytes with
   matching allocator behavior. The current Linux backend is in-memory and does
   not emit a `regf` file, so `bytewise` and most of `structural` (invariants 1
   to 18 over raw bytes) cannot be evaluated against it. Those tags are reported
   honestly (n/a or skipped) rather than counted as passes. No contract change
   needed, but noted so the green report is not misread.

3. **Recovery tag preconditions.**
   The recovery harness (crash injection between log write and primary write)
   needs an agent hook to abort mid-save deterministically. CONTRACTS.md
   mentions a "separate test mode that simulates crashes" but does not define
   the control surface. Requesting a spec for how the harness triggers it.

4. **Error-code expectations in the op format.**
   The harness supports an op-level `expect_error: CODE`. This is a harness
   convention layered on the op YAML, not a wire change. Flagging in case the
   spec wants to standardize how negative tests are expressed.
