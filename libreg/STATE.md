# libreg STATE

Last updated: 2026-05-31 (library agent)

Merge state: ALL 11 steps on main; every differential axis GREEN, including
recovery 3/3 (the linux agent wired `/test/crash_save` and the harness drives
it, #73/#74; `/test/crash_save` is in CONTRACTS 0.1.8). The library is
feature-complete.

THIS session (branch `agent/library-recovery-precedence` off main): a recovery
CORRECTNESS fix the operation fuzzer surfaced (issue #93, ratified in CONTRACTS
0.1.9 "Transaction Log Behavior"). My recover() did naive
highest-generation-wins, so a stale `.LOG` left at a reused path (from an
earlier, unrelated hive at a higher sequence) was replayed OVER a freshly saved
clean primary, silently mutating it. CONTRACTS 0.1.9 ratifies: a present, clean
primary is AUTHORITATIVE; a log is replayed only when the primary is dirty,
missing, or corrupt.
- Fix: pre-primary crash points now write a DIRTY primary (primary_seq = new,
  secondary_seq = prev) via the new `Hive::snapshot_with_seqs`, so a real
  interrupted save triggers replay; a clean save writes a clean primary that
  wins on load. `recover()` returns a present+clean+valid primary outright and
  only replays a log when the primary is dirty/missing/corrupt. For a DIRTY
  primary it caps replay at the in-flight generation (primary_seq): a stale log
  ABOVE it (left in the slot the crash did not overwrite, from a prior hive) is
  ignored, replaying the in-flight or last-committed log instead.
- This corrects the #66 simplification (I had skipped the dirty primary and
  relied on highest-gen-wins, which #93 showed is wrong).
- Tests: the issue-#93 case (clean primary + stale gen-50 log -> loads the
  fresh primary), the dirty-primary-replays case, the dirty+stale-above-inflight
  case, all three crash points still recover baseline+M, torn-log, alternation.
  136 lib green; the `crash_recovery` example still recovers baseline+M. The
  agent's adopted API (crash_save_plan -> Vec<(Slot,bytes)>,
  recover(primary,log1,log2)) is
  UNCHANGED; only the bytes/precedence are corrected.

----- recovery prototype (#66) + same-handle gen fix (#69) + example (#70) -----

THIS session (branch `agent/library-recovery-genfix` off main): a CORRECTNESS
FIX to the recovery prototype merged in #66. Re-reading issue #61, the harness
keeps the SAME handle across the baseline `hive_save` and the `crash_save`
(no reload between), but `crash_save_plan` did not advance the in-memory
generation, so two saves on one handle produced the same generation and
`recover` would wrongly prefer the baseline. My #66 tests masked it by
reloading between saves.
- Fix: a completed save (`AfterPrimary`) now advances the handle's generation
  (`crash_save_plan` takes `&mut Hive`; `Hive::set_generation`), so a later
  save/crash on the same handle journals a strictly newer generation. The
  pre-primary crash points do not advance (the save did not commit; the handle
  is discarded after a simulated crash).
- Tests rewritten to run the recovery sequence on a SINGLE handle, matching the
  harness exactly (and so actually exercising the fix). 133 lib + corpus green.

----- step 11 recovery prototype (#66, merged) and earlier below -----

THIS session (branch `agent/library-recovery` off main): STEP 11, the dual-log
crash-recovery PROTOTYPE (`src/log/`, Layer 3), answering issue #61.
- Scheme: a save is a *generation*, a full self-consistent hive snapshot
  (`Hive::snapshot(gen)`, valid checksum) stamped with a sequence number. A
  save journals the new generation to the alternating log slot, then commits
  the primary. `recover(primary, log1, log2)` picks the highest valid
  generation; a torn (bad-checksum) log is ignored, so a clean (log, primary)
  pair always survives (the point of dual logs, ADR 0004 part A).
- API: `Hive::generation()`, `Hive::snapshot(gen)`; `log::{Slot, CrashPoint,
  log_slot_for, crash_save_plan, recover}`. `crash_save_plan(hive, point)`
  returns the ordered `(Slot, bytes)` writes a recoverable save performs,
  truncated at the crash point, for the agent's `/test/crash_save` to execute.
- Tests (src/log/mod.rs): the full issue-#61 recovery sequence for all three
  crash points recovers baseline+M; generation selection (newer log wins); a
  torn log falls back to the clean primary; alternating slots; empty-input
  error. An in-memory `Disk` stand-in mirrors the harness's file writes.
- CAVEAT / for issue #61: this is a FULL-SNAPSHOT journal, so the two
  pre-primary points (after_first_log, after_log_before_primary) recover
  identically; the distinction only matters to a dirty-page delta scheme (a
  future optimization that does not change the recovery contract). Posted the
  prototype contract on issue #61 for the spec/harness/linux agents.

----- panic-safety + load robustness (now merged) and earlier below -----

THIS session (branch `agent/library-content-safety` off main): completed the
PANIC-SAFETY work begun in #59. Every operation on a loaded hive now returns
an error instead of panicking, even when an interior offset (a child offset, a
value/sk/list/data offset) points anywhere.
- Added `HiveImage::try_content(offset) -> Result<&[u8], FormatError>`, a
  bounds-checked sibling of `content` (which stays for create-path offsets the
  allocator just produced). Switched every loaded-data read to it: `read_nk`,
  `read_sk`, vk/lh/li/ri/db parses, value/segment data, and the u32 offset
  arrays (now length-checked). The read helpers already returned `Result`, so
  no signatures changed.
- Tests: a hive whose root nk's subkeys_list_offset (and another whose
  security_offset) points off the end LOADS (the root nk still parses), and the
  operation that dereferences it returns `Format` rather than panicking.
- Combined with #59, libreg no longer panics on any loaded bytes. (The
  create/write path still uses the panicking `content`/`content_mut`, which is
  correct: those offsets come from `alloc`.)

----- #59 load-path hardening (now merged); step 9 + earlier below -----

#59: `from_file_bytes` bounds-checks the bins slice and the root cell;
`Hive::validate() -> Vec<String>` is the offline structural check behind
`GET /hive/validate`.

----- step 9 (big-data) section below; earlier sessions further down -----

STEP 9 (this session): values over 16344 bytes use a db cell.
- `format/db.rs` (Layer 0): the db record (signature, segment count, segment-
  list offset) parse/serialize, plus `DB_MAX_SEGMENT = 16344` (the per-segment
  cap and the plain-vs-db threshold) and `segment_count_for`.
- `logical/value.rs`: `build_vk` now picks inline (<=4 bytes), a single plain
  data cell (<=16344), or a db cell (larger). `write_big_data` splits data into
  16344-byte segment cells, writes a segment-list cell of their offsets, and a
  db cell pointing at it; the vk's data_size is the total length (read uses
  data_size > 16344 to detect a db). `read_data` reassembles the segments.
  `free_value_data`/`free_big_data` free the db + segment list + segment cells
  on delete or replace. The old "Unsupported over 16344" guard is gone.
- Verified (src/logical/mod.rs tests): a 100KB value round-trips (and is
  actually stored as a db cell); the 16344/16345 boundary picks plain vs db;
  big values survive save+reload; deleting or replacing a big value reclaims
  the db, segment list, and every segment cell (allocated-cell count returns to
  baseline). vk/db format round-trips in format/db.rs.

CAVEAT: there is NO db reference hive in tests/corpus/synthetic, so the db
LAYOUT (16344 segment size, the segment-list cell, the db record fields)
follows the docs (Suhanov) and is NOT confirmed byte-for-byte against offreg.
The libreg round trip is verified; whether offreg can LOAD a libreg db hive is
not. Next step: request a 100KB-value reference hive from the corpus/harness
to confirm (and to answer it the way ref_ri.hiv answered ri promotion).

PERF/NOTE: the rebuild is O(n) per insert (O(n^2) to build n subkeys),
because each insert re-reads every sibling's name (leaves store hashes, not
names) and re-lays the whole index. Correct and deterministic, and matches
offreg's leaf partition for sorted input, but a future optimization could
split leaves incrementally. The 1100-key test takes ~3s in debug.

----- earlier sessions below -----

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
- `logical/index.rs`: `insert_subkey` keeps the subkey list name-sorted
  (invariant 17) and promotes lh -> ri of lh leaves past 507 (step 8, rebuilds
  the index each insert); `remove_subkey` rebuilds it without a child (demoting
  ri->lh->none). `list_entries` reads `(offset, name)` per subkey across all
  forms (lf/lh/li/ri). `free_subkey_list` frees a list and its ri leaves.
- `logical/security.rs`: `ensure_sk` shares a descriptor-equal sk (bumping its
  refcount) or allocates+links a new one; `release_sk` decrements on delete
  and unlinks+frees at 0.
- `Hive::set_key_security(path, descriptor)` (branch `agent/library-set-security`,
  resolves issue #52): repoints a key at the sk for a new descriptor
  (`ensure_sk`) and releases its old sk (`release_sk`); setting the same
  descriptor is a no-op. Unblocks the agents' POST /key/security + SDDL
  round-trip. The getter `key_security` already existed.

Security note (CORRECTED by the offreg references): offreg gives the root and
all created keys the SAME ratified default descriptor, shared via ONE sk whose
refcount equals the key count (ref_multi.hiv: 7 for root + 6). The empty-hive
root carries that descriptor too (not a placeholder). spec question 2 is
answered; sk sharing (step 10 create-side) and refcount release (step 7) are
both implemented.

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

Tests (all 116 lib + corpus/integration green: base/hbin, offreg-compare,
enumerate, promote-ri; `cargo test`, clippy clean; new files
fmt clean, and repo-wide `cargo fmt --check` is now CLEAN: the pre-existing
drift in `format/*.rs` and `tests/hbin_walk_corpus.rs` was cleared in a
dedicated fmt-only PR. (WATCH OUT for the future: `rustfmt src/format/mod.rs`
follows the `mod` declarations and reformats every `format/*.rs`; when only
touching one file, pass that file, not mod.rs.)):

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
- Examples: `examples/dump_hive.rs` (structure dump of any hive, used to read
  the references) and `examples/make_key_hive.rs` (write a hive with given
  subkeys to a path, for manual offreg/harness testing).
- `src/format/li.rs` and `src/format/ri.rs` (step 6 enumeration): round-trip,
  cell, bad-signature, and count-past-end tests each.
- `tests/enumerate_corpus.rs` (step 6): `reads_ri_indexed_wide_key`
  (ref_ri.hiv, 1100 keys via an ri, sorted + boundary resolves) and
  `reads_lh_leaf_hives` (the single-leaf lh fixtures).
- `tests/promote_ri.rs` (step 8): `stays_one_lh_leaf_at_507`,
  `promotes_to_ri_at_508` ([507, 1]), `wide_key_matches_ref_ri` (1100 keys ->
  ri [507, 507, 86], walks + reloads, same subkeys as ref_ri.hiv), and
  `promotion_is_deterministic`.
- `src/logical/mod.rs` (delete, step 7): `delete_value_removes_just_that_value`,
  `delete_last_value_drops_the_list` (vk + data + list reclaimed),
  `delete_leaf_key_reclaims_to_empty` (allocated count back to root nk + sk),
  `delete_nonempty_key_requires_recursive`,
  `recursive_delete_removes_the_whole_subtree`, `cannot_delete_root`,
  `delete_decrements_shared_sk_refcount`, `delete_then_recreate`, and
  `delete_is_byte_deterministic`.
- `src/format/db.rs` (step 9): `round_trips`, `round_trips_through_a_cell`,
  `rejects_bad_signature`, `rejects_short_header`,
  `segment_count_matches_threshold`.
- `src/logical/mod.rs` (big data, step 9): `big_value_round_trips_through_a_db_cell`
  (100KB, stored as db), `db_boundary_is_16344` (plain at 16344, db at 16345),
  `big_value_survives_save_and_reload`, `deleting_big_value_reclaims_all_segments`,
  `replacing_big_value_with_small_frees_segments`.

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
- Step 6 (read lf/lh/li/ri) and step 8 (ri promotion on write) BOTH DONE.
  `insert_subkey` rebuilds the index, emitting lh up to 507 then an ri of lh
  leaves; verified against ref_ri.hiv. Because it rebuilds via `list_entries`
  (which reads any form), inserting into a LOADED li/ri/lf hive now works too
  (it comes back out as lh/ri). Only lf/li are never WRITTEN (offreg uses lh).
- sk dedup/sharing (create-side of step 10) and refcount DECREMENT (step 7)
  BOTH DONE: `security::ensure_sk` shares + bumps on create (ref_multi.hiv:
  refcount 7 for 6 children); `security::release_sk` decrements on delete and
  unlinks + frees the cell at 0 (the root's shared sk never reaches 0).
- Step 7 (key/value delete + free list) DONE this session. create/delete now
  round-trips: deleting everything returns the allocated-cell count to the
  empty hive's. No orphan cells (verified by allocated-count + walk; a full
  reachability audit is not run, but the post-order free leaves none).
- db big-data (step 9) DONE this session: values over 16344 bytes split into
  db segments. All cell types (nk/vk/sk/lf/lh/li/ri/db) now exist. CAVEAT: db
  layout is unverified against offreg (no db reference hive yet).
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
   3-9. The linux agent now has a libreg backend (PR #48 on main), so this is
   close: build a `Hive`, create keys/values, `to_file()`, load via offreg in
   the Windows agent, diff canonical form. This is what formally CLOSES the
   steps libreg has implemented offline.
2. Get a db reference hive (a value >= ~100KB) into tests/corpus/synthetic to
   confirm libreg's db layout is offreg-loadable, the way ref_ri.hiv confirmed
   ri promotion. Until then step 9 is offline-verified only.
3. Step 11 (transaction logs / dual-log recovery) is the last unstarted step.
   Steps 1-9 are now implemented (10's create-side sk sharing is done).
4. Bytewise parity polish (lower priority, all bytewise-only): match offreg's
   allocation order (lh before child nk), the non-ASCII lh hash (full Unicode
   upcase, issue #22). The `dump_hive`/`make_key_hive` examples make this easy
   to check against the references.
5. DONE: the fmt-only cleanup landed, so repo-wide `cargo fmt --check` is
   clean. No standing housekeeping items remain.
