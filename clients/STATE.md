# Clients STATE

Last updated: 2026-06-01 (clients agent)

## What this subtree is

The Linux client utilities on top of libreg: `reg`, `sc`, and `regedit`,
modeled on the Windows tools. A cargo workspace at `clients/` with four crates:
`cli-core` (shared library), `reg`, `sc`, `regedit`. They link `libreg` by path
and have no external crate dependencies (the build environment has no registry
cache, and the project is Debian-first / native-binary), so the small amount of
JSON and HTTP regedit needs is hand-rolled.

## What works (this session)

Everything below builds clean (`cargo build`), is clippy-clean
(`cargo clippy --all-targets`), and `cli-core` has 22 green unit tests.

### cli-core (shared)
- `path`: parse `HKLM\...` / `HKEY_LOCAL_MACHINE\...` registry paths (long and
  short root names, case-insensitive), reject remote `\\host\` paths.
- `mount`: the mount map binding roots/subpaths to hive files
  (`$LIBREG_HIVES` or `~/.config/libreg/hives.conf`), longest-prefix
  resolution, persistent load/save, and a `--hive FILE` override.
- `value`: REG_* type codec (name <-> code, CLI `/d` data parsing for SZ /
  EXPAND_SZ / DWORD (dec+hex) / DWORD_BE / QWORD / BINARY (hex) / MULTI_SZ /
  NONE, and display formatting). String types are UTF-16LE on disk.
- `regfile`: `.reg` (Windows Registry Editor Version 5.00) export and import.
  Export is UTF-16LE with BOM (matches real `reg export`); import accepts
  UTF-16LE/BE and UTF-8, handles continued hex lines, key and value deletions.
- `sddl`: binary security descriptor <-> SDDL string, mirroring the agent codec
  (`agents/linux/src/sddl.rs`) so tokens match the harness/agents (ADR 0003).
  Built on libreg's public `format::security_descriptor` types. Round-trips the
  ratified default descriptor and custom owner/group/DACL forms.
- `structure`: on-disk format inspection (base block fields, cell statistics,
  and a cell map with signatures: nk/vk/sk/lf/lh/li/ri/db). Built on libreg's
  public `format` layer, so it reads the real bytes of any hive (including
  offreg-written ones). One unit test.
- `session`: open a hive file into `libreg::logical::Hive`, dump a key or a
  whole subtree, copy subtrees, and save.

### reg
- Subcommands: query, add (`/v` `/ve` `/t` `/d` `/s` `/f`), delete
  (`/v` `/ve` `/va`, whole-key), copy (`/s`, same-file and cross-file), save,
  restore, load, unload (manage mounts), export, import, compare.
- query supports `/v` `/ve` `/s`, a content search `/f Pattern` with scope
  (`/k` keys, `/d` data, default keys+value-names+data), `/c` case-sensitive,
  `/e` exact, and a `/t Type` filter. Search prints an "End of search: N
  match(es)" line and exits 1 when nothing matches.
- add: a bare `reg add KEY` (no `/v`) on a *new* key leaves an empty default
  value (REG_SZ ""), matching reg.exe (RegCreateKeyEx then a default set). A
  bare add of an existing key does not clobber its default; `/v` sets only the
  named value; nested adds put the default only on the leaf. This resolves the
  harness client-differential finding filed against the clients (see main's
  `tests/harness/STATE.md`, the `add_nested_keys` note).
- compare supports `/s` and the output modes `/oa` `/od` (default) `/os` `/on`,
  prints "Result Compared: Identical/Different", and exits 0 when identical, 2
  when different (matching reg.exe).
- Switch parsing distinguishes reg.exe `/v` switches from Unix `/abs/paths`
  (a switch has no further `/` or `.` and is short).
- Verified end to end: add/query(recursive)/export/import round trip, mount via
  `reg load` then query through the mount map, value delete, `/f` searches with
  scope/case/exact, `/t` filtering, and compare exit codes.

### sc (offline service config over a SYSTEM hive)
- Verbs: create, config, delete, qc, query (static fields), description. The
  `key= value` (space-after-equals) syntax is supported, plus the combined
  `key=value` form. `--hive` and `--controlset N` may appear before or after
  the verb.
- Maps type/start/error tokens (own/share/kernel/..., boot/system/auto/..,
  normal/severe/..) to the right REG_DWORD values; binPath -> ImagePath
  (REG_EXPAND_SZ), depend -> DependOnService (REG_MULTI_SZ, `/`-separated),
  DisplayName/obj/group -> REG_SZ.
- `sc create` defaults `ObjectName` to `LocalSystem` (REG_SZ) for win32
  service types (own/share, and types carrying those bits) when `obj=` is not
  given, matching sc.exe; driver types (kernel/filesys) get no ObjectName, and
  an explicit `obj=` is always honored. Resolves the harness
  client-differential finding (issue #78). `sc config` is unchanged (it writes
  only the fields you pass).
- Runtime verbs (start/stop/pause/continue/control) fail with a clear
  "not available on offline hives" message (no live SCM).
- Verified: create/qc/config/query/delete, and `reg query` reads the exact
  REG values sc wrote (same real regf hive, cross-tool interop confirmed).

### packaging (Debian-first, rule 5)
- `packaging/build-deb.sh` builds two `.deb` packages with `dpkg-deb` only (no
  external tooling): `libreg-tools` (reg, sc, man pages, example mount map) and
  `libreg-regedit` (regedit, man page, systemd unit, `/etc/libreg/regedit.conf`
  conffile, `/var/lib/libreg`). Man pages in `packaging/man/`, the unit and
  config in `packaging/systemd` and `packaging/conf`.
- Verified: both packages build, install via `dpkg -i`, the installed
  `/usr/bin/reg` and `/usr/bin/sc` run, the unit and conffile land correctly,
  and the packages remove cleanly. The regedit package does not auto-start the
  service (no auth; loopback bind by default; enable with systemctl when ready).

### regedit (web)
- Standalone server (std-only HTTP in `http.rs`, std-only JSON in `json.rs`),
  links libreg through cli-core. Roots come from the mount map or `--hive`.
- REST: `/api/roots`, `/api/key` (subkeys + typed values), `/api/validate`
  (libreg structural check), `/api/security` (GET returns SDDL plus the raw
  self-relative descriptor as hex, which Windows regedit does not surface),
  `/api/setsecurity` (POST, edit permissions via SDDL), `/api/structure`
  (base block + cell map), `/api/tree` (recursive subtree dump), `/api/diff`
  (compare two roots/subtrees), `/api/export` (.reg download), and POST
  `/api/setvalue` `/api/deletevalue` `/api/createkey` `/api/deletekey` (each
  opens the file, mutates, saves).
- Single-page UI (`static/index.html`): lazy tree browser, value table with
  add/edit/delete, new-key, validate, an editable SDDL permissions dialog, an
  on-disk structure inspector (base block facts + scrollable cell map), a diff
  dialog, and export-subtree.
- Verified: server serves the UI and all read/validate/setvalue endpoints; a
  POSTed value persists; security reads as SDDL and an edited SDDL persists and
  re-validates; the structure view shows base block + cells and visualizes a
  big-data (db) cell from a 40KB value; diff reports added/removed keys.

## Assumptions

- `--hive FILE` treats the file's root as the path's predefined root (so
  `reg add --hive f HKLM\Software\X` puts content under `\Software\X`, and the
  matching mount is `HKLM = f`). The mount map is the recommended path for
  Windows-identical syntax; `--hive` is the one-off override. Documented in
  `clients/CLAUDE.md`; worth a short note in user docs.
- libreg's `logical::Hive` is the integration surface (same as the Linux
  agent uses). A stable `api/` Layer 4 would be cleaner but is not required.
- `reg save`/`restore` copy a subtree to/from a fresh hive whose root is the
  saved key. This is logically correct; it is not byte-identical to a Windows
  `reg save` (which snapshots the on-disk subtree), but canonical/semantic
  content matches.

## What I would do next

1. Harness client-differential mode (a harness-subtree change, so coordinate):
   run a command with our `reg`/`sc` and the real Windows tool on the VM,
   diff resulting hives in canonical form. This is the intended acceptance bar
   (`semantic` green) and would formally validate the clients, not just the
   local smoke tests.
2. SDDL display and editing in regedit: DONE this session (cli-core `sddl`
   module + `/api/security` GET returning SDDL + `/api/setsecurity` POST + an
   editable dialog). A future refinement is a structured ACE table editor
   instead of a raw SDDL text field, and rendering the SACL when present.
3. regedit structure inspector: DONE this session (`/api/structure` base block
   + cell map with db visualization, `/api/tree`, `/api/diff`, and the UI). A
   future refinement is decoding each cell's interior (nk name, vk type/value,
   sk refcount) on click, and a side-by-side value-level diff view.
4. `reg query` search flags (`/f` `/k` `/d` `/c` `/e` `/t`) and `reg compare`
   output modes (`/oa` `/od` `/os` `/on`) with exit codes: DONE this session.
   Remaining reg.exe flags are lower value (`/z`, `/se`, `/reg:32|64`).
5. `.deb` packaging for reg/sc and a systemd unit + `.deb` for regedit:
   DONE this session (`packaging/`). Future: CI to build and attach the debs,
   and a source package (debian/ dir) if upstreaming to a Debian repo.
6. Per-tool unit/integration tests beyond cli-core (currently covered by
   end-to-end smoke runs).
