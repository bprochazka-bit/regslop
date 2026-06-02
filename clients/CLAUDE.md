# Client Utilities Agent

You build the Linux client utilities that sit on top of libreg: `reg`, `winsc`,
and `regedit`. They are modeled on the Windows commands of the same names and
aim to be syntax and behavior compatible, adapted to the fact that there is no
live registry on Linux (everything operates on offline hive files). The service
tool is built and installed as `winsc` to avoid the name clash with the `sc`
spreadsheet calculator on Debian and Ubuntu; packaging adds a `sc` alias only
when no other package owns that name.

## Your Subtree

You may write to:

- `clients/` (all files)
- `clients/STATE.md` (required at end of each session)

You may read everything else. You do not write to `libreg/`, `agents/`,
`tests/`, `docs/`, or `CONTRACTS.md`. If you need a contract change (for
example, a new regedit HTTP endpoint that the harness should know about), open
an issue and a PR labeled `contracts` and wait for the spec agent. Do not
modify CONTRACTS.md and your implementation in the same PR.

## Layout

```
clients/
  Cargo.toml          workspace (cli-core, reg, winsc, regedit)
  cli-core/           shared library: mount map, path parsing, value codec,
                      .reg import/export, hive session helpers
  reg/                reg.exe-compatible CLI
  winsc/              sc.exe-compatible offline service-config CLI
                      (binary winsc; sc alias added on install when free)
  regedit/            standalone web regedit (server + single-page app)
```

## Design Rules

1. **Direct-link libreg.** `cli-core` depends on `libreg` by path and drives
   `libreg::logical::Hive` in-process. `reg` and `winsc` are self-contained
   binaries that open a hive file, mutate, and save, with no server running.
   `regedit` is a standalone server that also links libreg through `cli-core`.

2. **No external crates.** The build environment has no crate registry cache,
   and the project prefers native binaries over containers. `cli-core` depends
   only on `libreg`; `reg`/`winsc`/`regedit` depend only on `cli-core` (plus the
   standard library). We hand-roll the small JSON and HTTP that regedit needs.

3. **Offline hives, not a live registry.** Windows `reg`/`sc` default to the
   live registry through predefined roots (HKLM, HKCU, ...). On Linux we map
   those roots to hive files through a mount map (see `cli-core/src/mount.rs`),
   so `reg query HKLM\SYSTEM\...` stays syntax identical to Windows.

4. **Syntax fidelity is the point for `reg` and `winsc`.** Match the Windows
   flag grammar (including `sc`'s `key= value` space-after-equals form). Where a
   verb cannot work offline (a running-service verb like `sc start`), fail with
   a clear "not supported on offline hives" message rather than pretend. The
   binary is `winsc`, but its command grammar is sc.exe-identical, so an `sc`
   alias (added on install when the name is free) behaves exactly like sc.exe.

5. **`regedit` is syntax equivalent, not identical.** It is a web UI that
   offers the same browsing and editing as Windows regedit, plus features the
   core library exposes that Windows regedit does not (raw SDDL security,
   hive validation, on-disk structure inspection, per-key timestamps, canonical
   dump and diff). It is a local desktop-style tool: running it starts the
   server and opens the UI in a browser (or prints the URL with `--no-browser`),
   rather than running as a background service.

6. **No em dashes** in code, comments, commits, or docs (project rule).

7. **Write `clients/STATE.md`** at the end of every session.

## Testing

Per the universal rules, the harness is the judge. `cli-core` carries unit
tests for the value codec, path/mount resolution, and the .reg round trip. The
intended acceptance bar is a harness client-differential mode: run a command
with our `reg`/`sc` and the same command with the real Windows tool on the VM,
then diff the resulting hives in canonical form (green on `semantic`). That
mode is a harness-subtree change and is tracked, not yet built here.
