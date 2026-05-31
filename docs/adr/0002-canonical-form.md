# ADR 0002: Canonical JSON form for semantic comparison

- Status: accepted
- Date: 2026-05-30
- Deciders: spec agent
- Scope: CONTRACTS.md "Canonical JSON Form" and the `semantic` test tag

## Context

The harness compares the result of the same operation sequence run against
two independent implementations: libreg (Linux) and offreg (Windows). The
two will not produce byte-identical hive files. Their allocators differ,
they pack cells differently, they may order subkey lists differently on
disk, and offreg does not write transaction logs at all
(agents/windows/CLAUDE.md). Byte equality is therefore the wrong primary
signal; it is kept only as the `bytewise` tag, and bytewise failures with
semantic pass are warnings, not errors (CONTRACTS "Test Categories").

What we actually want to assert is that both hives mean the same thing:
the same keys, values, types, data, security, and timestamps to a
comparable precision. That requires projecting each hive onto a normal
form that erases representation-level freedom while preserving meaning.

## Decision

Both agents serialize a hive to the exact structure in CONTRACTS.md
"Canonical JSON Form". The harness re-parses before diffing (whitespace
does not matter) but field semantics and ordering rules are fixed:

- `subkeys` and `values` sorted lexicographically by `name`.
- Name comparison is case-insensitive (Windows semantics) but original
  casing is preserved in the output.
- `last_write` is ISO 8601 UTC at second precision; sub-second digits are
  dropped.
- `class_name` is null when absent, never "".
- Binary data is base64, no line breaks.

## Rationale for the non-obvious choices

### Sorted keys (lexicographic by name)

On-disk subkey order is an allocator and index artifact, not meaning. Two
hives with the same keys inserted in different orders are semantically
equal. Sorting by name before comparison removes that freedom. Sorting is
chosen over "compare as multisets" because a deterministic order also makes
diffs readable: when the differ fires, the first differing line is the
actual divergence, not a reordering. Case-insensitive ordering matches how
Windows treats key and value names, but casing is preserved in the output
so a casing-only bug (libreg storing "FOO" where offreg stores "Foo") is
still visible as a data difference, not silently normalized away.

### Dropped sub-second precision

Registry last-write times are FILETIME, 100 ns resolution. The two agents
stamp keys at slightly different wall-clock instants during a run, and the
canonicalization round-trips timestamps through different code paths. Sub-
second digits would differ on essentially every key and drown the signal.
Second precision is coarse enough to be stable across the two runs yet fine
enough to catch a real bug where libreg fails to update a timestamp on
write. This trades away the ability to detect sub-second timestamp bugs;
that is accepted for v0.1. If a sub-second timestamp behavior ever needs
testing, it gets a dedicated test, not the canonical diff.

### Base64 for binary, no line breaks

JSON has no native byte-string type. Base64 is the least surprising
encoding and "no line breaks" removes the one formatting degree of freedom
MIME base64 would add. Padding is kept (not stripped) so the encoding is
canonical and re-decodes without special handling (CONTRACTS canonical
rule: "no padding stripped").

### class_name null vs ""

A key with no class and a key with an empty-string class are different
states in principle. Collapsing absent to null (and forbidding "") gives
one representation for "no class", so the differ does not fire on a
meaningless null-vs-empty distinction. If offreg ever reports an empty
class distinctly from absent, this rule is revisited.

## Alternatives considered

- Compare on-disk bytes only: rejected, allocators legitimately differ.
- Compare as unordered sets without canonical serialization: rejected,
  produces unreadable diffs and still needs a normalization for
  timestamps and binary.
- Full FILETIME precision in the canonical form: rejected, see above.

## Consequences

- `semantic` is the primary green/red signal (CLAUDE.md rule 3: a feature
  is done when the differ is green on at least `semantic`).
- The canonical form is a third interface both agents must match exactly;
  divergence between the two agents' canonical output is a contract bug to
  be filed, not an implementation choice (agents/linux/CLAUDE.md rule 5).
- Sub-second timestamp correctness is out of scope for the canonical diff
  and needs targeted tests if ever required.
- The canonical schema currently includes `class_name` even though no v0.1
  operation sets a class name; tracked in docs/STATE.md.
