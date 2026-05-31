# libreg STATE

Last updated: 2026-05-31 (library agent)

PR #20 (Layer 0 format modules through lf/lh) is MERGED. The branch was
stale at CONTRACTS 0.1.0 and is now synced to current main (0.1.6); this
session added the binary security-descriptor codec on branch
`agent/library-default-sd`.

IMPORTANT for next session: several spec questions below were resolved by
the spec agent in 0.1.1 through 0.1.6 while this branch sat at 0.1.0. They
are annotated inline (RESOLVED / PARTLY RESOLVED). Re-read CONTRACTS.md
(0.1.6) and the new docs/hive-format.md on main before trusting older notes.

## Current layer

Layer 0 (`format/`). Steps 1 and 2 done. Step 3 (empty hive creation) is
IMPLEMENTED and self-validated, but NOT yet verified against offreg (its
acceptance test is harness-gated; see caveat below).

Step 4 (single key create) is in progress: this session added its Layer 0
building blocks, the lf and lh subkey-list leaf cells (`format/lf.rs`,
`format/lh.rs`). The remaining step 4 work is the actual wiring (a child
nk plus a subkey list, with the root nk's `subkeys_list_offset` /
`subkey_count` updated) and harness verification, neither done yet. See
"What I would do next session".

## What works

Crate scaffolding (`Cargo.toml`, `src/lib.rs`) with the layered module
tree stubbed at `format`. No external dependencies.

`src/format/base_block.rs` parses and serializes the hive base block
(`regf`), step 1 of the implementation order.

- `BaseBlock::parse` / `BaseBlock::to_bytes`: byte-exact round trip. The
  two reserved regions (0x070..0x1FC and 0x200..0x1000) are retained as
  raw bytes so unmodelled fields (GUIDs, flags, log/boot fields) survive
  serialization unchanged.
- Modelled fields: primary/secondary seq, last_written FILETIME, major/
  minor version, file_type, file_format, root_cell_offset, hbins_size,
  clustering_factor, file_name (raw UTF-16LE bytes).
- `compute_checksum` / `checksum_valid` / `recompute_checksum`: XOR of the
  127 dwords at 0x000..0x1FC, with the reserved-value rules (0 -> 1,
  0xFFFFFFFF -> 0xFFFFFFFE). Matches offreg/kernel behavior.
- `is_clean()`: primary_seq == secondary_seq.

`src/format/cell.rs` frames cells (step 2). `Cell::parse_at` reads the
signed size field, classifies allocated (negative) vs free (positive),
range-checks against the buffer, rejects zero sizes, and handles the
`i32::MIN` magnitude edge via i64 widening. `is_aligned()` checks 8-byte
alignment without rejecting it at the framing layer.

`src/format/hbin.rs` walks the bin chain (step 2). `HiveBins`/`HbinIter`
iterate bins (validating `hbin` magic, 4096-multiple size, in-bounds);
`Hbin::cells()` / `CellIter` iterate cells within a bin (cells cannot
cross the boundary because they are framed against the bin slice). Cell
offsets are reported relative to the hive bins data using the bin's
declared offset. `walk(data) -> CellStats` returns hbin/allocated/free
counts plus total cell bytes, and enforces invariant 9 (cell sizes sum
to bin payload) as a defensive guard. All iterators are zero-alloc
(Hard Rule 2).

`src/format/nk.rs` parses/serializes key node cells (step 3 building
block). `KeyNode` models all fixed fields plus the raw name bytes
(ASCII vs UTF-16LE per KEY_COMP_NAME). `KeyNode::new_root` builds a root
key (flags KEY_HIVE_ENTRY | KEY_NO_DELETE | KEY_COMP_NAME, empty links).
Flag constants exported. Round-trip and bounds tests.

`src/format/sk.rs` parses/serializes security cells. `SecurityCell`
holds flink/blink/refcount/descriptor; `SecurityCell::lone` builds a
one-element ring (flink=blink=self). `default_security_descriptor()`
builds a minimal self-relative SD (owner/group = Local System S-1-5-18,
NULL DACL) used by the EMPTY-HIVE ROOT only. See caveat: the root SD is
still a placeholder, not confirmed offreg. (The created-KEY default is a
separate, ratified descriptor; see security_descriptor.rs below.)

`src/format/security_descriptor.rs` (this session) is the binary
self-relative SECURITY_DESCRIPTOR codec: typed `Sid`, `Ace`, `Acl`,
`SecurityDescriptor` with byte-exact encode/parse, well-known SIDs (BA, SY,
WD, RC), and the `KEY_ALL_ACCESS` / `KEY_READ` / `CONTAINER_INHERIT_ACE`
constants. `default_key_security_descriptor()` builds the descriptor a
freshly created key carries, ratified in CONTRACTS 0.1.6 (issue #11):
`O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)` (owner
and group Administrators; SYSTEM + Administrators full, Everyone +
Restricted Code read; all container-inheritable; no SACL). 144 bytes.
Verified offline (round-trip + hand-computed SID/ACE bytes + full
structural assertion). Equality is decided on the SDDL-normalized form
(ADR 0003), so byte-equality with offreg is not promised, only that this
binary form yields that SDDL; the harness is the final arbiter. NOT yet
consumed: there is no create path yet (step 4), and the empty-hive root is
deliberately left on its own placeholder (the root SD is a distinct,
unconfirmed offreg question).

`src/format/cell.rs` gained `cell_size_for` and `encode_cell` (size
field + payload, zero-padded to 8 bytes; used on the creation path).

`src/format/base_block.rs` gained `BaseBlock::create(root_cell_offset,
hbins_size, last_written)` for fresh hives (seq 1/1, v1.5, computes
checksum).

`src/format/empty_hive.rs` assembles a complete empty hive (step 3):
base block + one 4096-byte bin (root nk at 0x20, sk at 0x78, trailing
free cell). Offsets computed from actual cell sizes, deterministic.
`build_empty_hive(&EmptyHiveOptions)`; options cover root name, stamp,
and security descriptor so the offreg-correct values can be substituted.
Total file 8192 bytes.

`examples/make_empty_hive.rs` writes an empty hive to a path for manual
offreg testing (`cargo run --example make_empty_hive -- /tmp/empty.hiv`).
Verified: produced bytes match the documented format on hexdump.

`src/format/lf.rs` parses/serializes "lf" fast-leaf subkey lists (step 4
building block). `FastLeaf` holds a `Vec<FastLeafEntry>` of
(key_offset, 4-byte name hint); `name_hint(name_bytes)` extracts the
first four on-disk name bytes, zero padded. Header + 8-byte-element
layout, byte-exact round trip, bounds-checked element count.

`src/format/lh.rs` parses/serializes "lh" hash-leaf subkey lists (the form
offreg writes for v1.5 hives). `HashLeaf` holds (key_offset, name_hash);
`HashLeafEntry::new(offset, name)` computes the hash. `name_hash(&str)`
implements the registry fold `hash = hash*37 + upcase(unit)` over UTF-16
code units in wrapping 32-bit arithmetic (endian-independent). CAVEAT:
only ASCII upcasing is applied; non-ASCII name hashes are unverified
against offreg's `RtlUpcaseUnicodeChar` (new spec question 3 below).

Neither lf nor lh sorts or dedups; the sorted-by-name on-disk invariant is
a Layer 2 (logical) concern. These are pure parsers/serializers, fully
verifiable offline; they do NOT yet decide which list type a create emits
(that is the step 4 logical decision, harness-gated).

Tests (all 53 lib + 2 corpus green, `cargo test`, clippy clean, fmt clean
on touched files):

- `src/format/base_block.rs` unit tests: `parses_known_fields`,
  `round_trip_is_byte_exact`, `rejects_short_buffer`,
  `rejects_bad_signature`, `checksum_special_cases`,
  `recompute_after_mutation_keeps_block_valid`,
  `round_trip_property_many_inputs` (256 pseudo-random blocks via a
  deterministic SplitMix64 LCG; stands in for proptest, no dep, BE-safe).
- `src/format/hbin.rs` unit tests: `walks_single_bin`,
  `walks_multiple_bins`, `cell_offsets_use_declared_offset`,
  `rejects_bad_hbin_signature`, `rejects_unaligned_hbin_size`,
  `rejects_zero_cell_size`, `rejects_bin_shorter_than_declared_size`.
- `tests/base_block_corpus.rs::base_block_round_trips_for_corpus_hives`:
  the literal step 1 test. Scans `../tests/corpus` for files beginning
  with `regf`, round-trips each base block, and checks the checksum.
- `tests/hbin_walk_corpus.rs::cell_walk_for_corpus_hives`: the step 2
  test. Slices the hive bins data by `base_block.hbins_size`, walks all
  bins/cells, prints counts, and (when a sibling `<hive>.cellcount` file
  exists) asserts the total cell count. The offreg-dump cross-check
  proper lives in the harness; this is the offline half.

  Both corpus tests SKIP (pass with a SKIP note) when no corpus is
  present, and FAIL on absence when `LIBREG_REQUIRE_CORPUS=1` is set (CI).

- `src/format/{nk,sk,empty_hive}.rs` unit tests cover round-trips,
  bounds/signature rejection, and full empty-hive structural validation
  (base block valid + clean, cell walk = 2 allocated + 1 free, root nk
  well-formed, sk lone ring refcount 1, deterministic output).

- `src/format/lf.rs` unit tests: `round_trips`, `empty_list_round_trips`,
  `round_trips_through_a_cell` (recovers exact count from padded payload),
  `rejects_short_header`, `rejects_bad_signature`, `rejects_count_past_end`,
  `name_hint_padding`.
- `src/format/lh.rs` unit tests: `round_trips`, `empty_list_round_trips`,
  `round_trips_through_a_cell`, `rejects_bad_signature`,
  `rejects_count_past_end`, `hash_is_case_insensitive_for_ascii`,
  `hash_matches_known_values` (hand-computed 37*h+upcase reference values),
  `hash_distinguishes_different_names`.
- `src/format/security_descriptor.rs` unit tests: `sid_well_known_bytes`
  (hand-computed bytes for S-1-5-18 / S-1-5-32-544 / S-1-1-0 / S-1-5-12),
  `sid_round_trips`, `ace_round_trips_and_sizes`, `acl_round_trips`,
  `default_descriptor_round_trips`, `default_descriptor_structure` (control
  flags, offsets, ACE count/order/masks, total length 144),
  `parse_rejects_truncated_header`, `parse_rejects_sid_past_end`.

## CAVEAT: step 3 is implemented but NOT verified (read before trusting)

The step 3 acceptance test is "the Windows agent loads the hive via
offreg without error". libreg cannot run offreg, and the Windows agent /
harness are not present in this worktree, so this has NOT been verified.
What IS verified is self-consistency: the produced hive passes every
structural check libreg itself can make, and the bytes match the
documented regf format on manual hexdump.

These offreg-specific choices are best-effort guesses (Hard Rule 4 says
match offreg, not docs, but I had no offreg to match against):

1. Default security descriptor (NULL DACL, owner/group = Local System).
   offreg may reject a NULL DACL on load, or write a different default.
2. Root key name "ROOT". offreg may use a different name/marker.
3. Format minor version 5 (v1.5). offreg may emit 1.3 for an empty hive.
4. Base block file name field zeroed; access bits 0; root parent =
   0xFFFFFFFF.

ALL are overridable via `EmptyHiveOptions` (except parent/version, which
are easy to expose if needed). Do NOT mark step 3 closed until the
harness reports the Windows agent loading a libreg empty hive cleanly.

## What is half-done / not started

- Step 4 (single key create) partially started: lf/lh leaf cells exist
  (this session); the create wiring and harness verification do not. See
  next-session plan.
- Steps 5-11 not started. li/ri/db/vk format modules not written yet
  (li/ri belong to step 8, vk to step 5, db to step 9).
- Invariant-9 sum check in `hbin::walk` is defensive: given the cell
  iterator's exact tiling, an under/over-filled bin surfaces as a
  per-cell ZeroCellSize/OutOfBounds error before the sum check fires.
  Kept as a guard; no unit test reaches it directly.
- Big-endian CI (Hard Rule 6): code uses only explicit `from_le_bytes`/
  `to_le_bytes`, no transmute, so it is endian-correct by construction,
  but I have NOT yet run it on s390x / via `cross` (no network/target
  installed in this session). Verify in CI before relying on it.

## Assumptions I am relying on

- Checksum covers the first 508 bytes = 127 dwords (offsets 0x000..0x1FC).
  CONTRACTS 0.1.1 reworded invariant 3 to exactly this (see spec question 1,
  RESOLVED); the implementation matches.
- The corpus is gitignored and downloaded separately; it is currently
  absent in this checkout, so step 1's corpus test ran in SKIP mode. The
  synthetic round-trip and property tests do exercise the code path.
- `docs/hive-format.md` now EXISTS on main (the spec agent wrote it). Cross-
  check field offsets against it before trusting the from-knowledge Suhanov
  notes used so far; not yet done.

## Spec questions to raise (tag spec-question)

1. RESOLVED (CONTRACTS 0.1.1). Invariant 3 was reworded to the precise 127
   little-endian dwords over bytes 0x000..0x1FB with the 0 -> 1 /
   0xFFFFFFFF -> 0xFFFFFFFE quirks. libreg's implementation already matches;
   no change needed.
2. PARTLY RESOLVED. The default security descriptor for a freshly created
   KEY was ratified in 0.1.6 (issue #11) and is implemented this session in
   `security_descriptor.rs`. STILL OPEN for the empty-HIVE ROOT
   specifically: whether offreg gives the root the same descriptor, plus the
   root key NAME and the format MINOR VERSION (1.3 vs 1.5/1.6). The spec
   agent's open question 2 (dual-log minor version, 5 vs 6) overlaps the
   version part and is itself pending a corpus hive. Needs an offreg-created
   reference hive (or harness confirmation) to replace the `empty_hive.rs` /
   `sk.rs` root placeholders. Do NOT assume the root reuses the created-key
   default.
3. STILL OPEN. lh name hash for non-ASCII names: `lh::name_hash` upcases
   only ASCII (a-z); the kernel uses `RtlUpcaseUnicodeChar`. Confirm the
   upcase table offreg applies (and whether comp-name Latin-1 bytes expand
   to UTF-16 before hashing) so non-ASCII subkey names hash to byte-equal lh
   elements. ASCII names are already correct. Not yet raised to the spec
   agent.
4. STILL OPEN (gates step 4). Single-subkey create canonical form: lf vs lh,
   where the list cell is placed (same bin?), and the child nk fields
   (KEY_COMP_NAME for an ASCII name, parent = root offset, security shared
   with root via refcount bump). Needs an offreg reference hive or harness
   confirmation before wiring the create path; Hard Rule 4, do not guess.
   Not yet raised to the spec agent.

## What I would do next session

1. VERIFY step 3 against offreg via the harness/Windows agent before
   moving on (coordinate; resolve spec question 2). Adjust the SD / root
   name / version to whatever offreg accepts. Only then is step 3 green.
2. Step 4: single key create. The lf/lh leaf cells now exist, and the
   created-key default security descriptor is now built
   (`security_descriptor::default_key_security_descriptor`); what is left is
   the wiring. Add a child nk (parent = root offset, KEY_COMP_NAME for an
   ASCII name, its own security_offset sharing the root sk with a refcount
   bump), a subkey-list cell holding one element pointing at it, and set the
   root nk's `subkeys_list_offset` + `subkey_count = 1`.
   Resolve spec question 4 first (lf vs lh, list placement, child fields);
   do not guess, Hard Rule 4. Target: differ green on `semantic`.
   Two ways to get there:
   (a) Quick bootstrap, mirroring `empty_hive.rs`: a deterministic
       fixed-offset `build_single_key_hive` Layer 0 composition. Gives the
       harness agent something concrete to diff immediately (CLAUDE.md
       asks for this after step 4). Cheap, but accumulates unverified
       offreg guesses like step 3 did, so gate it behind the harness.
   (b) Real path: start Layer 1 (alloc). The fixed-offset bootstrap in
       `empty_hive.rs` will not scale to inserts; a single key create that
       grows the bin needs an allocator. This is the durable route and is
       required from step 7 (free list) on regardless.
   Recommendation: do (a) only if the harness agent needs an artifact now;
   otherwise begin (b), since steps 7+ force it anyway.
   Coordinate with the harness agent either way (shared Windows VM).
3. Obtain a corpus hive (even one small NTUSER.DAT) so the step 1 and 2
   corpus tests run for real, not just SKIP. An offreg-created empty hive
   in the corpus would also answer spec question 2 directly. Record
   `<hive>.cellcount` from an offreg dump for the step 2 count check.
4. Consider adding `proptest` as a dev-dependency once dependency policy
   for the corpus/offline build is confirmed; replace the hand-rolled LCG
   property test if so.
