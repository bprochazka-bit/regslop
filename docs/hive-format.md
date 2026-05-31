# Windows Registry Hive On-Disk Format

Reference for libreg implementers. Read this instead of deriving the format
from scratch. Where libreg and this document disagree, the document is wrong:
file a `spec-question` issue. Where this document and offreg disagree, offreg
wins (see `libreg/CLAUDE.md` rule 4) and the divergence is a `spec-question`.

## Sources

- Maxim Suhanov, "Windows registry file format specification",
  github.com/msuhanov/regf. Primary reference for all offsets and cell
  layouts below. Retrieved 2026-05-30. Pin the commit hash when you copy a
  number from it into code.
- Google Project Zero, "The Windows Registry Adventure #5: the regf file
  format" (projectzero.google, 2024-12), for kernel-derived details such
  as the subkey leaf split point and offreg fingerprints. Retrieved
  2026-05-30.
- Direct reading of corpus hives (see `tests/corpus`), cited inline as
  "corpus" where a value was confirmed empirically.
- offreg.dll observed behavior via the Windows agent, cited as "offreg"
  where the spec is silent and behavior was established by the harness.

Normative wording follows RFC 2119 (MUST, SHOULD, MAY).

## Units and Conventions

- All multi-byte integers are little-endian unless a field is explicitly a
  big-endian value type (REG_DWORD_BE).
- "Offset" without qualification means a byte offset from the start of the
  hive bins data area (the byte just after the base block), not a file
  offset. A cell at offset N lives at file offset `4096 + N`.
- "Block" is 4096 bytes. The base block is one block. Hive bins are whole
  multiples of one block.
- In this document "the u32 at offset X" means the 4-byte little-endian
  value whose first byte is at byte offset X. CONTRACTS.md invariants 3, 4,
  and 7 use the shorthand "dword X" for the same thing; they are not
  ordinals (not "the Xth dword").

## 1. Base Block (file offset 0, length 4096)

The base block (also "regf header") is the first block of the file. Only
the first 512 bytes carry defined fields; the remainder is reserved.

| Offset | Len | Field                | Notes                                   |
|-------:|----:|----------------------|-----------------------------------------|
| 0      | 4   | signature            | ASCII `regf` (0x66 0x65 0x67 0x66)      |
| 4      | 4   | primary sequence     | incremented before a write              |
| 8      | 4   | secondary sequence   | incremented after a successful write    |
| 12     | 8   | last written         | Windows FILETIME (100 ns since 1601)    |
| 20     | 4   | major version        | 1                                       |
| 24     | 4   | minor version        | 3, 4, 5, or 6 (see Versions below)      |
| 28     | 4   | file type            | 0 = primary, 1 = log                    |
| 32     | 4   | file format          | 1 = direct memory load                  |
| 36     | 4   | root cell offset     | offset of the root nk cell              |
| 40     | 4   | hive bins data size  | total bytes of all hbins, excludes base |
| 44     | 4   | clustering factor    | 1 on modern hives                       |
| 48     | 64  | file name            | UTF-16LE, last 31 path chars, may pad 0 |
| 112    | ... | reserved             | see Suhanov for v1.5+ recovery fields   |
| 508    | 4   | checksum             | see below                               |

A clean hive (one not awaiting log recovery) MUST have
`primary sequence == secondary sequence` (CONTRACTS invariant 2).

### Checksum (offset 508)

The checksum is the XOR of the first 127 little-endian u32 values of the
base block, that is the 508 bytes from offset 0 through 507 inclusive. Two
quirks, both required to match offreg:

- if the computed value is `0x00000000`, store `0x00000001`
- if the computed value is `0xFFFFFFFF`, store `0xFFFFFFFE`

Source: Suhanov, "Base block" (confirmed 2026-05-30). CONTRACTS invariant 3
abbreviates this as "XOR of dwords 0..507"; that means the 127 dwords
spanning bytes 0..507, not 508 separate dwords.

### Versions

- minor 3: Windows XP era, single .LOG recovery.
- minor 4: Windows Vista/7.
- minor 5: Windows 8.
- minor 6: Windows 8.1+ with dual logging (.LOG1/.LOG2).

RESOLVED against the corpus: offreg-10.0.22621 writes minor version **5**
for a freshly created and saved hive (all four `tests/corpus/synthetic/*.hiv`
base blocks read minor 5, major 1, sequence 1/1, no logs). So the differ's
oracle emits v1.5, and libreg should write minor 5 to match (Hard Rule 4);
this is consistent with CONTRACTS "v1.5 hives". Minor 6 is the live-kernel
on-disk variant for active dual-log hives; offreg's `ORSaveHive` does not
produce it, and offreg writes no transaction logs at all
(agents/windows/CLAUDE.md), so minor 6 is out of scope for the differential
tests and relevant only to libreg's own recovery tag (ADR 0004).

### offreg fingerprint (informative)

Hives written by offreg.dll carry two identifying artifacts in the base
block: the ASCII tag `OfRg` at file offset 0xB0 and a serialization
timestamp near offset 0x200 (Project Zero, "regf file format", retrieved
2026-05-30). These are informative only: the harness compares the canonical
form, not these bytes, and libreg is not expected to reproduce them. Useful
when eyeballing which tool produced a hive during a `bytewise`
investigation.

## 2. Hive Bin (hbin)

The hive bins data area is a chain of hbins starting at file offset 4096.
Each hbin is a whole multiple of one block (4096 bytes).

| Offset | Len | Field            | Notes                                  |
|-------:|----:|------------------|----------------------------------------|
| 0      | 4   | signature        | ASCII `hbin`                           |
| 4      | 4   | offset           | this hbin's offset from start of bins  |
| 8      | 4   | size             | hbin size in bytes, multiple of 4096   |
| 12     | 8   | reserved         |                                        |
| 20     | 8   | timestamp        | only meaningful in the first hbin      |
| 28     | 4   | spare / unused   |                                        |
| 32     | ... | cells            | back to back until `size`              |

The hbin header is 32 bytes (0x20). The cell region is `size - 32` bytes.
The sum of the cell sizes in an hbin equals `size - 32` (CONTRACTS
invariant 9). No cell crosses an hbin boundary (invariant 10).

## 3. Cells

A cell is the allocation unit inside an hbin.

| Offset | Len | Field   | Notes                                        |
|-------:|----:|---------|----------------------------------------------|
| 0      | 4   | size    | signed i32; see sign rule                    |
| 4      | ... | content | `abs(size) - 4` bytes                         |

Sign rule (CONTRACTS invariant 6, confirmed against Suhanov 2026-05-30):

- size negative -> cell is allocated (in use). Usable length `-size`.
- size positive -> cell is free/unallocated. Length `+size`.

Cell sizes are padded to a multiple of 8 bytes. The first two bytes of an
allocated cell's content are usually a 2-byte ASCII type signature
(`nk`, `vk`, `sk`, `lf`, `lh`, `li`, `ri`, `db`); value-data cells and
class-name cells have no signature (they are raw bytes).

### 3.1 nk (key node)

The structural heart of the hive. One nk per registry key.

Signature `nk` (0x6b6e). Key fields, offsets relative to cell content
(after the 4-byte size):

| Off | Len | Field                  | Notes                                  |
|----:|----:|------------------------|----------------------------------------|
| 0   | 2   | signature `nk`         |                                        |
| 2   | 2   | flags                  | see flag table                         |
| 4   | 8   | last written           | FILETIME                               |
| 12  | 4   | access bits / spare    | version dependent                      |
| 16  | 4   | parent                 | offset of parent nk (root: -1/0)       |
| 20  | 4   | subkey count (stable)  |                                        |
| 24  | 4   | subkey count (volatile)| not persisted to primary; usually 0    |
| 28  | 4   | subkeys list offset    | offset of lf/lh/li/ri, or -1           |
| 32  | 4   | volatile subkeys offset|                                        |
| 36  | 4   | value count            |                                        |
| 40  | 4   | values list offset     | offset of a value-list cell, or -1     |
| 44  | 4   | security (sk) offset   | offset of the sk cell                  |
| 48  | 4   | class name offset      | offset of class-name cell, or -1       |
| 52  | 4   | max subkey name len    | cached                                 |
| 56  | 4   | max subkey class len   | cached                                 |
| 60  | 4   | max value name len     | cached                                 |
| 64  | 4   | max value data len     | cached                                 |
| 68  | 4   | work var               | runtime only                           |
| 72  | 2   | key name length        | bytes                                  |
| 74  | 2   | class name length      | bytes                                  |
| 76  | ... | key name               | encoding per KEY_COMP_NAME flag        |

nk flags (Suhanov, "Key node", confirmed 2026-05-30):

| Value  | Name             | Meaning                                  |
|-------:|------------------|------------------------------------------|
| 0x0001 | KEY_VOLATILE     | volatile key (not written to primary)    |
| 0x0002 | KEY_HIVE_EXIT    | mount point out of this hive             |
| 0x0004 | KEY_HIVE_ENTRY   | root of the hive                         |
| 0x0008 | KEY_NO_DELETE    | cannot be deleted                        |
| 0x0010 | KEY_SYM_LINK     | symbolic link key                        |
| 0x0020 | KEY_COMP_NAME    | key name is ASCII/Latin-1 (else UTF-16LE)|
| 0x0040 | KEY_PREDEF_HANDLE| predefined handle                        |

The compressed-name flag is KEY_COMP_NAME (0x0020). CONTRACTS invariant 16
names it "VALUE_COMP_NAME"; that is a typo, tracked in docs/STATE.md and
the contracts patch PR. When set, the key name is Latin-1; when clear,
UTF-16LE (CONTRACTS invariant 16, otherwise correct).

### 3.2 vk (value)

One vk per named value. Signature `vk` (0x6b76).

| Off | Len | Field             | Notes                                       |
|----:|----:|-------------------|---------------------------------------------|
| 0   | 2   | signature `vk`    |                                             |
| 2   | 2   | name length       | bytes; 0 means the default value (name "")  |
| 4   | 4   | data size         | see inline-data rule                         |
| 8   | 4   | data offset       | offset of data cell, or inline data          |
| 12  | 4   | data type         | REG_* constant                              |
| 16  | 2   | flags             | bit 0 = VALUE_COMP_NAME (name is ASCII)     |
| 18  | 2   | spare             |                                             |
| 20  | ... | value name        | encoding per flags; absent if name length 0 |

Data storage:

- If `data size` has its top bit (0x80000000) set, the data is stored
  inline in the `data offset` field itself and the low bits give the
  length (0 to 4 bytes). Used for small values such as REG_DWORD.
- Otherwise `data offset` points to a data cell holding the raw bytes, or
  to a db (big data) cell when the data exceeds 16344 bytes (see 3.6).

The default value uses name "" (CONTRACTS: name `""`, never `"(Default)"`).

### 3.3 sk (security)

Holds a self-relative SECURITY_DESCRIPTOR shared by one or more keys.
Signature `sk` (0x6b73).

| Off | Len | Field            | Notes                                       |
|----:|----:|------------------|---------------------------------------------|
| 0   | 2   | signature `sk`   |                                             |
| 2   | 2   | reserved         |                                             |
| 4   | 4   | flink            | next sk offset (forward link)               |
| 8   | 4   | blink            | previous sk offset (backward link)          |
| 12  | 4   | reference count  | number of nk cells pointing here            |
| 16  | 4   | descriptor size  | bytes of the security descriptor            |
| 20  | ... | descriptor       | self-relative SECURITY_DESCRIPTOR           |

sk cells form a doubly linked circular list (CONTRACTS invariant 13).
Reference counts MUST be exact: no orphan sk cells (refcount 0) and no
dangling nk -> sk pointers (invariant 14). Identical descriptors SHOULD be
shared by a single sk cell with the refcount summed (libreg step 10).

On the wire the descriptor transits as SDDL (CONTRACTS "Security");
conversion to/from the self-relative binary form is the agent's job. See
ADR 0003 for why SDDL over binary on the wire.

The default descriptor offreg gives a freshly created key, ratified in
CONTRACTS 0.1.6 (issue #11), is verified byte-for-content against the
synthetic corpus (the `sk` cell in every `tests/corpus/synthetic/*.hiv`):
144 bytes, control `0x8004` (SE_SELF_RELATIVE | SE_DACL_PRESENT, no SACL),
owner and group `S-1-5-32-544` (Administrators), and a 4-ACE DACL, each
container-inheritable: `S-1-5-18` KEY_ALL_ACCESS, `S-1-5-32-544`
KEY_ALL_ACCESS, `S-1-1-0` KEY_READ, `S-1-5-12` KEY_READ. That is exactly
`O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)`.

For `bytewise` parity, note offreg's body order: the header is followed by
the DACL (offset 0x14), then the owner SID, then the group SID. A producer
that lays owner/group before the DACL yields the same SDDL but different
bytes, which `semantic` accepts and `bytewise` does not.

### 3.4 Subkey list cells: lf, lh, li, ri

A key's subkeys are indexed by a list cell pointed to from the nk
"subkeys list offset". Four forms:

- `lf` (0x666c) fast leaf: array of (subkey nk offset, 4-byte name hint).
  The hint is the first 4 ASCII chars of the subkey name.
- `lh` (0x686c) hash leaf: array of (subkey nk offset, 4-byte name hash).
  Used by modern hives (minor version > 4). The hash is the rolling fold
  `hash = (hash*37 + RtlUpcaseUnicodeChar(unit)) & 0xFFFFFFFF` over the
  name's UTF-16 code units; see "lh name hash (verified)" below for the
  upcasing detail.
- `li` (0x696c) index leaf: array of subkey nk offsets, no hint/hash.
  CONTRACTS invariant 11 expects li "only when loading old hives"; libreg
  SHOULD write lh.
- `ri` (0x6972) index root: array of offsets to other subkey list cells
  (lf/lh/li). Used to chain multiple leaf lists when one leaf is not
  enough. An ri MUST NOT point at another ri, and a non-root list MUST NOT
  point at an ri (Suhanov, "Subkeys list").

All leaf forms store entries sorted by subkey name, case-insensitive, so
binary search is valid (CONTRACTS invariant 17). For ri, each referenced
leaf is internally sorted and the leaves are in key order.

#### What the differ compares (semantic vs bytewise)

The on-disk subkey-list TYPE (lf vs lh vs li vs ri) and the 4-byte name
hint/hash each entry carries are NOT part of the canonical JSON form
(CONTRACTS "Canonical JSON Form"), which records subkey names and their
recursive contents. They are therefore invisible to the `semantic` differ
and to the `structural` checks the harness runs today (only invariant 17,
list sortedness, is observable from a dump; invariant 11 promotion is
skipped). They affect only `bytewise` equality, which is a warning rather
than a failure and is not evaluated while an agent backend emits no regf
bytes.

What this means for an implementation (libreg):

- For `semantic`, the gating tag, a created subkey needs the correct
  logical form only: it appears under its parent with the right name,
  security, and values, and siblings stay name-sorted (invariant 17). The
  list type and the hash bytes do not matter.
- For `bytewise` parity with offreg, write an `lh` leaf for the v1.5+ hives
  this project targets (minor version > 4), entries sorted by uppercased
  name; a single subkey is a one-element lh. Exact cell placement (which
  bin, grow vs add) is an allocator choice, not specified here.
- The exact non-ASCII name-hash upcasing (`RtlUpcaseUnicodeChar`) is a
  bytewise-only detail; now pinned below from the corpus (issue #22).

#### Single-subkey create: what offreg emits (verified, issue #23)

Verified against `tests/corpus/synthetic/ref_one_ascii.hiv` and
`ref_multi.hiv` (offreg-10.0.22621). Creating subkeys under the root of a
fresh hive produces:

- An `lh` list always, even for a single subkey (offreg never emits `lf`
  for a v1.5 create). A second subkey grows the same lh, kept name-sorted.
- Cells allocated in the root's hbin in the order: root `nk`, `sk`, `lh`,
  then the child `nk`(s). (Placement is offreg's allocator behavior; it
  matters only for `bytewise`.)
- Each child `nk` shares the root's `sk`: its security offset points at the
  root sk and the sk reference count rises by one per key (refcount 2 for
  one child, 7 for six). offreg allocates no per-key sk when the descriptor
  is identical.
- The child `nk` sets `KEY_COMP_NAME` for a compressible name (see the hash
  note below), parent = root nk offset. The root `nk` gets
  `subkey_count = N` and its subkeys-list offset pointing at the lh.

#### lh name hash (verified, issue #22)

Verified against `ref_latin1.hiv` (subkey `Café`) and `ref_wide.hiv` (subkey
`{Omega}mega`). The hash folds the name's UTF-16 code units with
`hash = (hash*37 + RtlUpcaseUnicodeChar(unit)) & 0xFFFFFFFF`, using the full
Unicode upcase table, not ASCII-only:

- `Café` hashes to 0x352f57, which requires upcasing the code unit U+00E9
  (e-acute) to U+00C9 (E-acute). ASCII-only upcasing would leave U+00E9 and
  yield 0x352f77, so the fixture distinguishes the two.
- A `KEY_COMP_NAME` (compressed, 1 byte/char) name is expanded byte to
  UTF-16 code unit before hashing: `Café` is stored as the Latin-1 bytes
  `43 61 66 e9` but hashed as the units U+0043 U+0061 U+0066 U+00E9.
- offreg sets `KEY_COMP_NAME` iff every character is <= U+00FF; otherwise the
  name is stored uncompressed as UTF-16LE (verified by `ref_wide.hiv`, whose
  Greek-capital-Omega name clears the flag).

ASCII names were already correct; this pins the non-ASCII case.

#### Promotion threshold (approximate; confirm against offreg)

CONTRACTS invariant 11 states "lf/lh for < 1015 entries, ri for > 1015".
Suhanov's spec gives no explicit count. Kernel-derived analyses
(CmpSplitLeaf) put the real figures near, but not exactly at, 1015:

- a hash/fast leaf (lh/lf) holds up to about 1013 entries; once that is
  exceeded the kernel builds a two-level tree with an `ri` index root
  pointing at leaves
- index leaves (li) are reported to split earlier (around 508 entries)

So CONTRACTS "1015" is in the right neighbourhood but off by a couple, and
the precise split point is version and implementation dependent (sources
disagree on the exact number). Treat it as offreg-defined: libreg MUST
match whatever offreg produces (libreg/CLAUDE.md rule 4), and the harness
2000-subkey test (libreg step 8) establishes the real boundary
empirically. Do not hardcode 1015. Tracked as an open spec question in
docs/STATE.md.

Sources (retrieved 2026-05-30): Suhanov spec "Subkeys list"; Google
Project Zero "The Windows Registry Adventure #5"; Eric Zimmerman's
Registry parser. They differ on the exact number, which is itself the
reason to defer to offreg.

### 3.5 Value list

A key's values are indexed by a value-list cell: a packed array of u32
offsets, each pointing to a vk cell. No signature; it is a raw offset
array sized by the nk "value count". Order is the value enumeration order;
the canonical form sorts by name for comparison (CONTRACTS canonical form).

### 3.6 db (big data)

Signature `db` (0x6264). Used only for value data larger than 16344 bytes
(0x3FD8), and only when the base block minor version is greater than 3
(Suhanov, "Big data"). CONTRACTS invariant 12 states the size threshold.

| Off | Len | Field             | Notes                                      |
|----:|----:|-------------------|--------------------------------------------|
| 0   | 2   | signature `db`    |                                            |
| 2   | 2   | segment count     | number of data segments                    |
| 4   | 4   | segment list off  | offset of a cell holding u32 segment offs  |

The data is split into 16344-byte segments; the segment list cell holds
the offset of each segment's data cell. Reassembly concatenates segments
in order. Values at or below 16344 bytes use a single plain data cell, not
a db cell.

### 3.7 Class name and value data cells

Class-name cells and value-data cells have no type signature; they are raw
bytes whose length is given by the referencing field (nk class length, vk
data size). Class-name strings are UTF-16LE (CONTRACTS invariant 15).

## 4. Encoding Rules Summary

- Key names: Latin-1 if KEY_COMP_NAME set, else UTF-16LE (invariant 16).
- Value names: Latin-1 if vk VALUE_COMP_NAME (flags bit 0) set, else
  UTF-16LE.
- Class names: UTF-16LE (invariant 15).
- REG_SZ / REG_EXPAND_SZ / REG_LINK data: UTF-16LE, conventionally
  null-terminated; the terminator is part of the stored bytes.
- REG_MULTI_SZ: UTF-16LE strings, each null-terminated, the whole block
  double-null-terminated. offreg's ORSetValue expects exactly this; see
  agents/windows/CLAUDE.md "offreg gotchas".
- Integers in fields and REG_DWORD/REG_QWORD data: little-endian, except
  REG_DWORD_BE which is big-endian.

## 5. Mapping to CONTRACTS Invariants

| Invariant | Covered by section          |
|-----------|-----------------------------|
| 1 magic regf            | 1                |
| 2 seq numbers equal     | 1                |
| 3 checksum              | 1 (Checksum)     |
| 4 hive bins data size   | 1, 2             |
| 5 hbin magic + size     | 2                |
| 6 cell sign             | 3                |
| 7 cell tree from root   | 1 (root offset), 3.1 |
| 8 free list             | 3 (sign rule); allocator is libreg-internal |
| 9 cell size sum         | 2                |
| 10 no cell spans hbin   | 2                |
| 11 list promotion       | 3.4 (threshold offreg-defined) |
| 12 db threshold         | 3.6              |
| 13 sk linked list       | 3.3              |
| 14 sk refcounts         | 3.3              |
| 15 class UTF-16LE       | 3.7, 4           |
| 16 key name encoding    | 3.1, 4 (flag name typo noted) |
| 17 lists sorted         | 3.4              |
| 18 logs present/valid   | CONTRACTS "Transaction Log Behavior" |

## 6. Open Items

Tracked in docs/STATE.md:

1. Invariant 11 promotion threshold (1015 approximate; real lh/lf max near
   1013, li near 508; defer to offreg).
2. Exact on-disk minor version libreg writes for dual logging (3 vs 6 vs
   CONTRACTS "v1.5"). Confirm against corpus.
3. Whether the v0.1 canonical form should expose the nk class name (it is
   in the canonical schema as `class_name` but no operation sets it yet).
