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
- `session`: open a hive file into `libreg::logical::Hive`, dump a key or a
  whole subtree, copy subtrees, and save.

### reg
- Subcommands: query (`/v` `/ve` `/s`), add (`/v` `/ve` `/t` `/d` `/s` `/f`),
  delete (`/v` `/ve` `/va`, whole-key), copy (`/s`, same-file and cross-file),
  save, restore, load, unload (manage mounts), export, import, compare.
- Switch parsing distinguishes reg.exe `/v` switches from Unix `/abs/paths`
  (a switch has no further `/` or `.` and is short).
- Verified end to end: add/query(recursive)/export/import round trip, mount via
  `reg load` then query through the mount map, value delete.

### sc (offline service config over a SYSTEM hive)
- Verbs: create, config, delete, qc, query (static fields), description. The
  `key= value` (space-after-equals) syntax is supported, plus the combined
  `key=value` form. `--hive` and `--controlset N` may appear before or after
  the verb.
- Maps type/start/error tokens (own/share/kernel/..., boot/system/auto/..,
  normal/severe/..) to the right REG_DWORD values; binPath -> ImagePath
  (REG_EXPAND_SZ), depend -> DependOnService (REG_MULTI_SZ, `/`-separated),
  DisplayName/obj/group -> REG_SZ.
- Runtime verbs (start/stop/pause/continue/control) fail with a clear
  "not available on offline hives" message (no live SCM).
- Verified: create/qc/config/query/delete, and `reg query` reads the exact
  REG values sc wrote (same real regf hive, cross-tool interop confirmed).

### regedit (web)
- Standalone server (std-only HTTP in `http.rs`, std-only JSON in `json.rs`),
  links libreg through cli-core. Roots come from the mount map or `--hive`.
- REST: `/api/roots`, `/api/key` (subkeys + typed values), `/api/validate`
  (libreg structural check), `/api/security` (raw self-relative descriptor as
  hex, a thing Windows regedit does not surface), `/api/export` (.reg
  download), and POST `/api/setvalue` `/api/deletevalue` `/api/createkey`
  `/api/deletekey` (each opens the file, mutates, saves).
- Single-page UI (`static/index.html`): lazy tree browser, value table with
  add/edit/delete, new-key, validate, security, and export-subtree.
- Verified: server serves the UI and all read/validate/setvalue endpoints;
  a POSTed value persists to the hive file.

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
2. SDDL decode/edit in regedit: render the raw descriptor as SDDL and an ACE
   table, and allow editing (libreg has `set_key_security`). Needs an
   SDDL<->binary codec in cli-core (the Linux agent has one in
   `agents/linux/src/sddl.rs` to mirror, not import).
3. regedit structure inspector: surface the hbin/cell walk and big-data (db)
   layout (libreg's format layer can drive this); add a canonical-dump and
   two-hive diff view.
4. Flesh out `reg query` search flags (`/f` `/k` `/d` `/c` `/e`) and
   `reg compare` output modes (`/oa` `/od` `/os` `/on`).
5. `.deb` packaging for reg/sc and a systemd unit + `.deb` for regedit-web
   (Debian-first rule 5).
6. Per-tool unit/integration tests beyond cli-core (currently covered by
   end-to-end smoke runs).
