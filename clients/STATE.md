# Clients STATE

Last updated: 2026-06-02 (clients agent)

## Latest session (2026-06-02, part 3): regsc rename

Renamed the service tool from `winsc` to **`regsc`** so it sits in the reg* tool
family alongside `reg`, `regedit`, and `regmount`. (It had briefly shipped as
`winsc`; the original reason for moving off the bare name `sc` is the clash with
the `sc` spreadsheet calculator on Debian and Ubuntu, which still holds.) The
crate, binary, and man page are now `regsc` (`clients/regsc/`, `/usr/bin/regsc`,
`regsc.1`). The sc.exe verb grammar is unchanged, and the conditional `sc` alias
(added on install only when no other package owns the name, removed on uninstall
only if it still points at `regsc`) is unchanged. The notes below that say
"winsc" predate this and now read "regsc"; the harness should point `--sc-bin`
at `target/release/regsc`.

## Latest session (2026-06-02, part 2): regmount

Added a new tool, **`regmount`**, to libreg-tools: a mount-map generator. The
user passes a path (a hive file or a directory of hives, for example a mounted
`System32\config` or a user profile); it inspects each file, identifies the
registry root/subpath it belongs at, prints a `hives.conf`-format map to stdout,
and with `-o FILE` also writes it (refusing to overwrite without `-f`).

- Identification lives in `cli-core/src/identify.rs` (`identify_hive`), so it is
  reusable and unit tested. Two signals: the standard hive file name (SYSTEM,
  SOFTWARE, SAM, SECURITY, COMPONENTS, DRIVERS, DEFAULT, NTUSER.DAT,
  UsrClass.dat, BCD) and the top-level key shape (Select+ControlSet => SYSTEM,
  Microsoft+Classes => SOFTWARE, SAM+Domains => SAM, Policy => SECURITY,
  Software+Environment/Control Panel => user hive, Local Settings/`.ext` =>
  user classes). File name is primary; contents confirm it or classify a
  nonstandard name. A readable hive we cannot place returns `mount: None` (not an
  error) so a scan can surface it.
- `regmount` (`regmount/src/main.rs`): directory scan skips registry log and
  transaction companions (`*.LOG`/`.LOG1`/`.LOG2`/`.regtrans-ms`/`.blf`), is
  optionally recursive (`-r`), comments out hives it cannot place and any whose
  mount point duplicates one already mapped (so the result stays a valid map),
  prints the map to stdout and a summary plus skips to stderr.
- cli-core gained 5 identify unit tests (35 total now, all green). Verified end
  to end: a synthetic `config/` dir produced a correct map, the map drove a real
  `reg query` (round trip), single-file mode, the overwrite guard, `--force`,
  and the single-file-not-a-hive error all behave.
- Packaging: `regmount` and `regmount.1` are added to `libreg-tools`
  (build-deb.sh, README, man); workspace member added.

## Latest session (2026-06-02, part 1)

Two operator-facing changes:

1. **`sc` renamed to `regsc`.** The service tool's crate, binary, and man page
   are now `regsc` (`clients/regsc/`, `/usr/bin/regsc`, `regsc.1`). This avoids
   the name clash with the `sc` spreadsheet calculator that Debian and Ubuntu
   ship. The verb grammar is unchanged and sc.exe-identical. `libreg-tools`
   postinst adds a `/usr/bin/sc` symlink to `regsc` (and a `sc.1.gz` man symlink)
   only when no `sc` command already exists; postrm removes those symlinks only
   if they still point at `regsc`. So on a clean box `sc create ...` still works;
   where the calculator is installed, users invoke `regsc`. The harness should
   point `--sc-bin` at `target/release/regsc`.
2. **`regedit` is no longer a systemd service.** It is a local desktop-style
   tool: it binds, prints its URL, and opens the UI in the default browser
   (xdg-open / gio / sensible-browser / x-www-browser / www-browser, best
   effort). `--no-browser` skips the launch and just prints the URL (use on
   headless hosts). The TCP listener is bound before the browser launches, so
   the connection is never refused. The systemd unit and `/etc/libreg/regedit.conf`
   were removed; `libreg-regedit` now ships only the binary and man page (no
   maintainer scripts, no state dir). It still binds 127.0.0.1 by default.

Both packages build with `packaging/build-deb.sh` and were inspected with
`dpkg-deb -c`/`-I`. Workspace builds clean, clippy-clean, tests pass. regsc
create/qc and regedit (both `--no-browser` and default) were smoke tested.

## What this subtree is

The Linux client utilities on top of libreg: `reg`, `regsc`, `regedit`, and
`regmount`. The first three are modeled on the Windows tools; `regmount` is a
libreg-specific mount-map generator. A cargo workspace at `clients/` with five
crates: `cli-core` (shared library), `reg`, `regsc`, `regedit`, `regmount`. They
link `libreg` by path and have no external crate dependencies (the build
environment has no registry cache, and the project is Debian-first /
native-binary), so the small amount of JSON and HTTP regedit needs is
hand-rolled.

## What works (this session)

Everything below builds clean (`cargo build`), is clippy-clean
(`cargo clippy --all-targets`), and `cli-core` has 35 green unit tests
(including 5 new `identify` tests added with regmount this session). See the
latest-session notes above for the regsc rename and the regmount addition.

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
- add: a bare `reg add KEY` (no `/v`) stamps an empty default value (REG_SZ ""),
  matching reg.exe (RegCreateKeyEx then a default set). This now applies whether
  the key is new (#71) or already exists but has no default yet (#84); the empty
  default is set only when absent, so a bare add stays idempotent and never
  clobbers an existing (non-empty) default. `/v` sets only the named value;
  nested adds put the default only on the leaf. This resolves the harness
  client-differential findings filed against the clients (#71, #84).
- compare supports `/s` and the output modes `/oa` `/od` (default) `/os` `/on`,
  prints "Result Compared: Identical/Different", and exits 0 when identical, 2
  when different (matching reg.exe).
- Switch parsing distinguishes reg.exe `/v` switches from Unix `/abs/paths`
  (a switch has no further `/` or `.` and is short).
- Verified end to end: add/query(recursive)/export/import round trip, mount via
  `reg load` then query through the mount map, value delete, `/f` searches with
  scope/case/exact, `/t` filtering, and compare exit codes.

### regsc (offline service config over a SYSTEM hive)
(Binary renamed from `sc` to `regsc` in the 2026-06-02 session; verb grammar
unchanged. See the latest-session note at the top.)
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
  external tooling): `libreg-tools` (reg, regsc, man pages, example mount map,
  plus a postinst/postrm that manage the conditional `sc` alias) and
  `libreg-regedit` (regedit + man page only). Man pages in `packaging/man/`.
  (The systemd unit and `packaging/conf/regedit.conf` were removed in the
  2026-06-02 session; regedit is no longer a service.)
- Verified: both packages build and were inspected with `dpkg-deb -c`/`-I`.
  `libreg-tools` ships `/usr/bin/regsc` with the conditional-`sc`-alias scripts;
  `libreg-regedit` ships only `/usr/bin/regedit` and its man page (no maintainer
  scripts, no conffile, no state dir). regedit binds 127.0.0.1 by default.

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
5. `.deb` packaging for reg/regsc and a `.deb` for regedit: DONE
   (`packaging/`). regedit ships as a browser-launching tool, not a service
   (changed 2026-06-02). Future: CI to build and attach the debs, and a source
   package (debian/ dir) if upstreaming to a Debian repo.
6. Per-tool unit/integration tests beyond cli-core (currently covered by
   end-to-end smoke runs).
