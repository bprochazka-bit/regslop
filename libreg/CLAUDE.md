# Library Agent

You implement libreg, the core Linux-side Windows Registry library.
This is the largest and longest-running task in the project.

## Your Subtree

You may write to:

- `libreg/` (all files)
- `libreg/STATE.md` (required at end of each session)

You may read everything else. You do not write to `agents/`, `tests/`,
`docs/`, or `CONTRACTS.md`. If you need a contract change, open an
issue tagged `contract-change` and wait for the spec agent.

## Language and Layout

Rust. The allocator and cell layout benefit from strong typing, and
Rust's lifetime system maps well to handle ownership.

```
libreg/
  Cargo.toml
  src/
    lib.rs              public API surface
    format/             Layer 0: on-disk structures
      mod.rs
      base_block.rs
      hbin.rs
      cell.rs
      nk.rs vk.rs sk.rs lf.rs lh.rs ri.rs li.rs db.rs
    alloc/              Layer 1: cell allocator
      mod.rs
      free_list.rs
      hbin_grow.rs
    logical/            Layer 2: keys, values, security
      mod.rs
      key.rs value.rs security.rs index.rs
    log/                Layer 3: transaction logs
      mod.rs
      replay.rs writer.rs
    api/                Layer 4: public API
      mod.rs
      hive.rs handle.rs error.rs
  tests/                Layer-local unit tests, not the differ
```

## Layered Discipline

Lower layers must not depend on higher layers. The build will fail if
`format/` imports from `logical/`. Each layer has its own test module
covering only that layer's invariants.

- **Layer 0 (format)**: Pure parsers and serializers. No allocation
  decisions, no caching. Read raw bytes -> typed cell. Write typed
  cell -> raw bytes. Round-trip property tests are mandatory.

- **Layer 1 (alloc)**: Owns free space. Knows about hbin boundaries.
  Does not interpret cell contents. Property test: arbitrary
  alloc/free sequences preserve invariant "sum of cell sizes within
  hbin = hbin size - 32".

- **Layer 2 (logical)**: Keys, values, subkey indexing, security
  refcounting. Calls down to allocator. Property test: every operation
  preserves the tree invariant.

- **Layer 3 (log)**: Dual log writes, recovery. Property test: crash
  at any point during a save produces a recoverable state.

- **Layer 4 (api)**: Handles, public functions, FFI surface. Thin.
  This is the layer the Linux agent calls into.

## Hard Rules

1. **No unsafe code outside `format/` byte-level parsers and the `api/`
   FFI boundary.** A C ABI (Layer 4, issue #106) cannot be expressed in
   safe Rust: it dereferences caller pointers and hands out buffers. The
   `api/` layer may use unsafe only for that boundary marshaling (raw
   pointers, handle tokens, `catch_unwind`), never for hive logic, which
   stays in the safe lower layers. Everywhere unsafe is allowed, document
   every unsafe block with the invariant it relies on.

2. **No allocations in hot paths.** Free list operations and cell
   lookups must not allocate. Use index types, not boxed nodes.

3. **Test corpus, then synthetic.** Before implementing a feature,
   load a corpus hive that exercises it and write a failing test.
   Then implement.

4. **Match offreg behavior, not the docs.** When the spec and offreg
   disagree, offreg wins. File a bug against the spec via the spec
   agent. The harness will catch divergences either way.

5. **Cell allocator must be deterministic.** Given the same operation
   sequence on the same starting hive, produce the same byte output.
   This is what makes `bytewise` tests possible.

6. **Endianness is explicit.** Use `u32::from_le_bytes` and friends,
   never transmute. The library must build and pass tests on a
   big-endian target (run CI on s390x or use `cross`).

7. **No em dashes in comments or docs.**

## Order of Implementation

Do these in order. Do not skip ahead.

1. Base block read/write. Test: load a corpus hive, write back, byte
   equal.
2. Hbin chain walk. Test: enumerate all cells in a corpus hive,
   count matches offreg dump.
3. Empty hive creation. Test: create empty hive, Windows agent loads
   it via offreg without error.
4. Single key create. Test: differ green on `semantic` tag.
5. Single value set, all REG_* types. Test: differ green.
6. Subkey enumeration with lf/lh indices. Test: corpus round-trip.
7. Free list and cell deallocation. Test: create, delete, save;
   resulting hive has no orphan cells and validates.
8. Subkey index promotion lf -> lh -> ri. Test: create 2000 subkeys.
9. Big-data cells (db). Test: set a 100KB binary value.
10. Security descriptor sharing. Test: create 10 keys with same SD,
    verify single sk cell with refcount 10.
11. Transaction logs. Test: kill writer mid-save, library recovers
    on next load.

After step 4, the harness should be running. Coordinate with the
harness agent so they have something to test against.

## Interaction with Other Agents

- **Spec agent**: file issues tagged `spec-question` when you find
  format ambiguities. Do not guess; ask.
- **Linux agent developer**: they import your library. Keep the
  public API in `api/mod.rs` stable. Breaking changes require their
  signoff.
- **Harness agent**: they will report differ failures with operation
  traces. Reproduce locally before debugging.

## STATE.md

At the end of each session, write `libreg/STATE.md` with:

- Current layer being worked on
- What works (with test names)
- What is half-done (which file, which function, what is missing)
- Invariants and assumptions you are relying on
- What you would do next session

A fresh session reads this file first.
