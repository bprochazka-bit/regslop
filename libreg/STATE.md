# libreg STATE

Last updated: 2026-05-31 (library agent)

Merge state: steps 1-5 are on main (allocator #27, key create #33, value set
#37, all MERGED). THIS session (branch `agent/library-offreg-align` off main)
aligns the create path with the offreg REFERENCE HIVES that landed in
`tests/corpus/synthetic/` (offreg-generated; see their PROVENANCE.md). PR
targets main.

BIG NEWS: those reference hives are offreg ground truth and let us verify
output OFFLINE (Hard Rule 4, "match offreg, not docs", finally actionable).
Inspecting them (via the new `examples/dump_hive.rs`) showed the create path
diverged from offreg in several ways, now FIXED this session:

1. Root security descriptor: offreg gives the hive root the SAME descriptor
   as every created key (the ratified default, issue #11), byte-identical to
   `default_key_security_descriptor()`. empty_hive used a NULL-DACL
   placeholder. FIXED: empty_hive root now uses the ratified default. This
   answers spec question 2 and was a SEMANTIC bug (root SDDL mismatched).
2. sk sharing: offreg shares one sk across all keys with an identical
   descriptor, refcount = number of keys (ref_multi.hiv: 6 children, refcount
   7). We allocated a per-key sk. FIXED: `security::ensure_sk` dedups by
   descriptor (step 10 pulled forward because offreg requires it).
3. KEY_COMP_NAME threshold: offreg compresses names with all chars <= U+00FF
   (Latin-1), not just ASCII (ref_latin1.hiv "Cafe-with-acute" is comp-name
   byte 0xE9). We used is_ascii(). FIXED in key.rs and value.rs.
4. Descriptor body order: offreg lays out SACL, DACL, owner, group (DACL
   right after the 20-byte header). We did owner, group, DACL. FIXED:
   `SecurityDescriptor::to_bytes` now matches, so the descriptor is now
   BYTE-identical to offreg's.
5. Root nk flags: offreg's saved standalone root has KEY_COMP_NAME only
   (0x20), not KEY_HIVE_ENTRY|KEY_NO_DELETE (the kernel sets KEY_HIVE_ENTRY
   on mount, not at save). FIXED: `nk::new_root` flags = KEY_COMP_NAME.
6. lh leaf cap is 507 (one hbin of cell space), not ~1013. FIXED:
   LH_MAX_ENTRIES = 507 (matches issue #34 / CONTRACTS 0.1.7).

The lh ASCII name hash already matched offreg exactly (verified
name_hash("Test") == offreg's 0x004269d4). Non-ASCII upcase (full Unicode
RtlUpcaseUnicodeChar) is still bytewise-only and unimplemented (issue #22).

## Current layer

Layer 2 (`logical/`). Layers 0 and 1 in place. Step 3 (empty hive creation)
is IMPLEMENTED and self-validated, but NOT yet verified against offreg
(acceptance is harness-gated; see caveat below).

Steps 4 (key create) and 5 (value set) are IMPLEMENTED and offline-validated
(structural tests below), but their acceptance is "differ green on
`semantic`", which needs the harness/Windows agent (not in this worktree),
so neither is CLOSED yet. The `Hive` API (`create_key`, `set_value`,
`get_value`, `subkeys`, `values`, `to_file`) is the artifact the harness
agent can now drive.

## Layer 2: values (step 5, this session)

`src/format/vk.rs` (Layer 0) parses/serializes value cells: signature, name
length, data size (with the 0x80000000 inline bit), data offset (an offset
or the inline bytes), data type, and flags (VALUE_COMP_NAME). Raw `data_size`
/ `data_offset` words are kept for exact round trip; `new_inline` /
`new_pointer` / `is_inline` / `data_len` / `inline_data` interpret them.

`src/logical/value.rs` implements set/get/enumerate over a key's value list
(a raw u32 array of vk offsets sized by the nk `value_count`):
- `set(key_off, name, type, data)`: creates or replaces a value. Data <= 4
  bytes is stored inline in the vk; larger data goes in a plain data cell
  (db big-data for > 16344 bytes is step 9, returns Unsupported for now).
  Replace frees the old out-of-line data cell and rewrites the vk in place
  (same name => same vk size). New values append to the value list (a fresh
  list cell is allocated and the old one freed) and bump nk `value_count` /
  `values_list_offset`.
- `get` returns `(type, data)`, decoding inline-or-cell. `list_names`
  enumerates value names in stored (insertion) order.
- Data is opaque: callers pass a REG_* type code and raw bytes; the agent
  owns the JSON-to-bytes mapping (CONTRACTS value table). Value names use
  VALUE_COMP_NAME for ASCII (else UTF-16LE), case-insensitive lookup.
  `Hive::set_value` / `get_value` / `values` resolve the path and call in.

Value-list ordering is insertion order (deterministic, Hard Rule 5); it is
not required sorted (the canonical form sorts by name for comparison), so
this is a free, offreg-plausible choice. Confirm against offreg for bytewise.

## Layer 2: the logical key tree (this session)

`src/logical/` turns cells into a key tree, calling DOWN into alloc and
format only (layered discipline). The unit is `Hive` (a `HiveImage` plus
the root offset). Implemented: key creation (single + full path, creating
missing intermediates, idempotent), case-insensitive lookup, name-sorted
subkey enumeration.

- `logical/mod.rs`: `Hive` with `new_empty` / `from_file_bytes` / `to_file`,
  `create_key(path)`, `resolve`, `subkeys`, and `LogicalError`
  (Format / Unsupported / NotFound). `create_key` walks the path, creating
  each missing component: alloc a child nk (parent set, KEY_COMP_NAME for
  ASCII names, security_offset), add its sk, insert it name-sorted into the
  parent's lh, bump the parent's `subkey_count` / `subkeys_list_offset`.
- `logical/key.rs`: nk read/write over the image, `build_child_nk`, name
  encoding (ASCII+KEY_COMP_NAME else UTF-16LE) and decode, case-insensitive
  ordering (`cmp_name` / `name_eq`, ASCII upcasing).
- `logical/index.rs`: `insert_subkey` keeps the parent's lh name-sorted
  (invariant 17), reallocating the list cell and freeing the old one; errors
  before lh -> ri promotion (step 8) rather than emit a leaf offreg rejects.
  `list_entries` reads `(offset, name)` per subkey.
- `logical/security.rs`: `add_sk` allocates a new sk with the ratified
  default descriptor and splices it into the root's sk ring, refcount 1.

Security note: each created key gets its OWN sk (the ratified created-key
default), distinct from the empty-hive root's placeholder SD, so a single
key create yields a 2+ element sk ring. sk dedup/sharing (one sk, summed
refcount) is step 10. The root SD remains the open step-3 placeholder
(spec question 2); this session does not touch it.

## Layer 1: the allocator (prior session)

`src/alloc/` is the deterministic cell allocator over the hive bins data.
It owns free space and hbin boundaries but does not interpret cell contents
(CLAUDE.md Layer 1). Policy is first-fit by lowest offset, which keeps byte
output reproducible (Hard Rule 5).

- `alloc/mod.rs`: `HiveImage` wraps the bins data (`Vec<u8>`, no base
  block). `new_empty()` (one 4096 bin), `from_bins()`, `alloc(payload_len)
  -> offset` (zeroes content, grows a new hbin if nothing fits),
  `free(offset)`, `content`/`content_mut`, `bins`/`bins_size`, and
  `to_hive_file(root_offset, stamp)` which prepends a `BaseBlock::create`
  base block. Offsets point at the cell size field, matching on-disk links.
- `alloc/free_list.rs`: implicit free list (positive-size cells are free, so
  no separate boxed structure, Hard Rule 2). `find_free` (deterministic
  first-fit), `place` (split when the leftover is a whole cell, else take
  the whole cell; requests and free cells are both 8-multiples so a split
  never leaves a sub-8 fragment), `free` (forward + backward coalescing,
  never across an hbin boundary, invariant 10).
- `alloc/hbin_grow.rs`: `grow_for` appends a new 4096-aligned hbin with a

## Layer 1: the allocator (this session)

`src/alloc/` is the deterministic cell allocator over the hive bins data.
It owns free space and hbin boundaries but does not interpret cell contents
(CLAUDE.md Layer 1). Policy is first-fit by lowest offset, which keeps byte
output reproducible (Hard Rule 5).

- `alloc/mod.rs`: `HiveImage` wraps the bins data (`Vec<u8>`, no base
  block). `new_empty()` (one 4096 bin), `from_bins()`, `alloc(payload_len)
  -> offset` (zeroes content, grows a new hbin if nothing fits),
  `free(offset)`, `content`/`content_mut`, `bins`/`bins_size`, and
  `to_hive_file(root_offset, stamp)` which prepends a `BaseBlock::create`
  base block. Offsets point at the cell size field, matching on-disk links.
- `alloc/free_list.rs`: implicit free list (positive-size cells are free, so
  no separate boxed structure, Hard Rule 2). `find_free` (deterministic
  first-fit), `place` (split when the leftover is a whole cell, else take
  the whole cell; requests and free cells are both 8-multiples so a split
  never leaves a sub-8 fragment), `free` (forward + backward coalescing,
  never across an hbin boundary, invariant 10).
- `alloc/hbin_grow.rs`: `grow_for` appends a new 4096-aligned hbin with a
  single trailing free cell (invariants 5 and 9). Only heap growth in the
  module, and not a hot path.

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

Tests (all 88 lib + 2 base/hbin corpus + 4 offreg-compare + 1 vk/value
corpus green, `cargo test`, clippy clean; new files
fmt clean. NOTE: pre-existing fmt drift exists in several `format/*.rs` and
`tests/hbin_walk_corpus.rs` from earlier merges; left untouched per the
"fmt what you touch" convention, so a repo-wide `cargo fmt --check` still
reports diffs there. Worth a separate fmt-only cleanup PR. WATCH OUT:
`rustfmt src/format/mod.rs` follows the `mod` declarations and reformats
every `format/*.rs`; pass only the files you changed, or revert the rest.):

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
- `src/alloc/hbin_grow.rs`: `grows_one_aligned_bin_that_walks`,
  `oversize_request_rounds_up_to_multiple_bins`,
  `second_grow_chains_after_the_first`.
- `src/alloc/mod.rs`: `alloc_in_empty_bin_walks_clean`,
  `content_is_zeroed_and_writable`, `many_allocs_keep_invariant_9`,
  `free_coalesces_with_both_neighbours`, `grows_to_a_second_bin_when_full`,
  `produces_a_loadable_hive_file`, `deterministic_same_sequence_same_bytes`
  (Hard Rule 5), and `property_random_ops_preserve_invariants` (400 random
  alloc/free ops via SplitMix64; after each op `walk` stays green and every
  live cell's tag byte survives, so an overlapping or corrupting allocation
  is caught, not just an invariant-9 tiling break).
- `src/logical/mod.rs`: `create_single_key_under_root` (root count/list,
  one-element lh, child fields), `child_carries_the_ratified_default_security`
  (sk descriptor == ratified default, refcount 1, 2-element ring with
  consistent flink/blink), `nested_path_creates_intermediates`,
  `siblings_are_kept_name_sorted`, `create_is_idempotent`,
  `lookup_is_case_insensitive`, `deterministic_same_sequence_same_bytes`
  (Hard Rule 5), and `tree_invariant_holds_over_random_creates` (120 random
  creates against a model: every node enumerates exactly its children,
  name-sorted; walk green after each op; loadable file).
- `src/format/vk.rs`: `inline_round_trips`, `short_inline_is_zero_padded`,
  `pointer_round_trips`, `round_trips_through_a_cell`, `rejects_bad_signature`,
  `rejects_short_header`, `rejects_name_past_end`.
- `src/logical/mod.rs` (values): `set_and_get_inline_value`,
  `set_and_get_out_of_line_value`, `default_value_uses_empty_name`,
  `setting_same_name_replaces`, `value_lookup_is_case_insensitive`,
  `multiple_values_on_one_key`, `missing_value_is_none`,
  `values_are_byte_deterministic`.
- `src/logical/mod.rs` (security, this session):
  `child_shares_the_root_security_cell` (child points at the root sk,
  refcount 2, lone ring) and `many_keys_share_one_sk_with_summed_refcount`
  (6 children, refcount 7, like ref_multi.hiv).
- `tests/create_matches_offreg.rs` (this session): builds the same keys as
  each offreg reference hive and asserts matching subkey sets and per-key
  security descriptors: `one_ascii_subkey_matches_offreg`,
  `six_ascii_subkeys_match_offreg`, `latin1_name_matches_offreg`,
  `wide_name_matches_offreg`. SKIP if a fixture is absent.
- Examples (this session): `examples/dump_hive.rs` (structure dump of any
  hive, used to read the references) and `examples/make_key_hive.rs` (write a
  hive with given subkeys to a path, for manual offreg/harness testing).

## Step 3/4/5 verification against offreg references (this session)

The earlier "best-effort guesses" for the empty hive are now CONFIRMED or
CORRECTED against the offreg reference hives in tests/corpus/synthetic:

- Root security descriptor: CORRECTED to the ratified default (was a NULL-DACL
  placeholder); now byte-identical to offreg's root sk.
- Root key name "ROOT": CONFIRMED.
- Format minor version 1.5: CONFIRMED (offreg default).
- Root nk flags: CORRECTED to KEY_COMP_NAME only (offreg saves with no
  KEY_HIVE_ENTRY/KEY_NO_DELETE).

The empty-hive layout (root nk @0x20, sk @0x78, sk descriptor bytes, free
@0x120) now matches ref_one_ascii.hiv. The `create_matches_offreg.rs`
integration test confirms libreg's create output matches the references'
logical form (subkey sets, per-key security descriptors) for the one-key,
six-key, Latin-1, and wide-name fixtures.

STILL not byte-identical to offreg (documented bytewise deltas, all
semantically irrelevant):
- last_written timestamp (offreg uses real time; we use a fixed stamp).
- Allocation ORDER: offreg allocates the lh leaf before the child nk
  (lh @0x120, child @0x130); we allocate the child first (child @0x120,
  lh @0x178). Pure allocator ordering; semantics identical.
- offreg fingerprint (the `OfRg` tag at file offset 0xB0 and a serialization
  timestamp near 0x200); informative only, not reproduced.
- Non-ASCII lh name hash (full Unicode upcase); issue #22, bytewise only.

Step 3/4/5 are still not formally CLOSED until the HARNESS loads a libreg
hive via offreg and reports `semantic` green, but the offline evidence is
now strong (byte-identical empty-hive prefix and descriptor, matching tree).

## What is half-done / not started

- Steps 4 (key create) and 5 (value set) IMPLEMENTED in Layer 2 and
  offline-validated; not CLOSED until the harness reports `semantic` green
  (needs the Windows agent / harness, not in this worktree).
- Step 5 partial coverage: set/get/enumerate done; value DELETE not done
  (pairs with key delete, step 7). Big-data (db) values over 16344 bytes
  return Unsupported (step 9). All REG_* types work since data is opaque
  bytes + a type code; the agent maps JSON to bytes.
- lh -> ri promotion (step 8) not done: `insert_subkey` errors past
  LH_MAX_ENTRIES (507, the offreg cap) instead of promoting. Fine until a
  key has more than 507 subkeys. ref_ri.hiv (1100 keys) needs this for read
  (step 6) and write (step 8).
- sk dedup/sharing (the create-side of step 10) DONE this session:
  `security::ensure_sk` reuses a descriptor-equal sk and bumps its refcount,
  matching offreg (ref_multi.hiv: refcount 7 for 6 children). NOT done: the
  refcount DECREMENT and orphan-free on key delete (pairs with step 7).
- No key deletion yet (step 7); the allocator's `free`/coalesce is ready
  for it, but no logical delete path frees an nk/list/sk subtree.
- Steps 6-11 otherwise not started. li/ri/db format modules not written
  (vk now exists). Step 6 is subkey enumeration via lf/lh on a CORPUS hive
  (our create-side lh enumeration already works; step 6 wants a real hive).
- Allocator is a content-agnostic substrate only: it does not update nk
  link fields, refcounts, or counts. That bookkeeping is Layer 2's job.
- Allocator does not yet free into a size-bucketed list; first-fit scans
  the bin chain each call. Correct and deterministic, but O(cells) per
  alloc. A bucketed free list is a future optimization, not needed for the
  current step sizes. `from_bins` trusts its input is well-formed (no
  re-validation); load-path validation belongs to Layer 4.
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
- `docs/hive-format.md` exists on main (the spec agent wrote it). Field
  offsets were CROSS-CHECKED against it this session: base block, hbin,
  cell, nk, sk, lf, lh all match the doc's tables. The doc also confirms
  the nk/hbin/cell offsets and the lh modern-hive choice. Done; no drift.

## Spec questions to raise (tag spec-question)

1. RESOLVED (CONTRACTS 0.1.1). Invariant 3 was reworded to the precise 127
   little-endian dwords over bytes 0x000..0x1FB with the 0 -> 1 /
   0xFFFFFFFF -> 0xFFFFFFFE quirks. libreg's implementation already matches;
   no change needed.
2. ANSWERED by the offreg reference hives (this session). The empty-hive ROOT
   carries the SAME descriptor as a created key (the ratified default, issue
   #11): byte-identical to the root sk in ref_one_ascii.hiv. Root name is
   "ROOT", minor version 1.5, root nk flags KEY_COMP_NAME only. All applied to
   `empty_hive.rs` / `nk::new_root`. The old `sk::default_security_descriptor`
   (NULL-DACL placeholder) is now UNUSED by empty_hive (kept, still has a unit
   test; could be removed). FILE A SPEC NOTE: root nk flags being
   KEY_COMP_NAME only (no KEY_HIVE_ENTRY) contradicts Suhanov's doc; confirmed
   against offreg, so offreg wins (Hard Rule 4), but the spec agent should
   note it in docs/hive-format.md.
3. ANSWERED (issue #22, PR #25). The lh name hash for non-ASCII names is a
   BYTEWISE-only detail: the subkey-list type and hash bytes are invisible
   to the semantic differ. ASCII names already hash correctly, which is all
   `semantic` needs. The exact `RtlUpcaseUnicodeChar` table for non-ASCII
   remains a future bytewise refinement (not blocking any step now); the
   `lh::name_hash` ASCII-only caveat doc still stands.
4. ANSWERED (issue #23, PR #25). For `semantic` the list TYPE and placement
   do not matter, only the logical form (subkey present under parent with
   right name/security/values, siblings name-sorted, invariant 17). For
   bytewise parity write a one-element `lh` sorted by uppercased name; cell
   placement is the allocator's choice (now available). The child nk fields
   (KEY_COMP_NAME for an ASCII name, parent = root offset, shared security)
   are as previously noted. Step 4 wiring is therefore UNBLOCKED; what is
   still missing is only the implementation and harness verification.

## What I would do next session

1. GET THE HARNESS to drive `Hive` and confirm `semantic` green for steps
   3/4/5. Build a `Hive`, create keys/values, `to_file()`, hand the bytes to
   the Windows agent via offreg. Coordinate with the harness/linux-agent devs
   on wiring `Hive` into `agents/linux` (their subtree). The offline evidence
   is now strong (byte-identical empty-hive prefix + descriptor, matching
   tree vs the offreg references), so this should pass.
2. Step 6: subkey enumeration from the CORPUS hives that now exist
   (tests/corpus/synthetic). Our logical layer only reads `lh`; ref_ri.hiv
   uses an `ri` index of `lh` leaves. Add `format/ri.rs` (and `li.rs`) Layer 0
   parsers and make `index::list_entries` dispatch on the cell signature
   (lf/lh/li/ri) so it can enumerate any real hive. `examples/dump_hive.rs`
   already has a partial ri walker to crib from. This is the natural next step
   and is fully offline-testable against ref_ri.hiv.
3. Step 7 (key/value delete + free list): the allocator's free/coalesce is
   ready; add a logical delete that frees the nk, its subkey/value lists, and
   decrements/frees the sk (refcount down, free at 0). Value delete too.
4. Bytewise parity polish (lower priority, all bytewise-only): match offreg's
   allocation order (lh before child nk), the non-ASCII lh hash (full Unicode
   upcase, issue #22). The `dump_hive`/`make_key_hive` examples make this easy
   to check against the references.
5. A small fmt-only PR to clear the pre-existing `cargo fmt` drift in
   `format/*.rs` and `tests/hbin_walk_corpus.rs` (left untouched here per
   "fmt what you touch"), so repo-wide `cargo fmt --check` is clean.
