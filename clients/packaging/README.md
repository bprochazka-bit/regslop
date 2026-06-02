# Packaging

Debian packages for the libreg client utilities, built with `dpkg-deb` only
(no external cargo tooling, in keeping with the project's native-binary,
no-registry-cache constraints). Targets Debian 13.

## Build

```bash
clients/packaging/build-deb.sh
```

This builds the release binaries and writes two packages to
`clients/target/deb/`:

- **libreg-tools** `/usr/bin/reg`, `/usr/bin/winsc`, `/usr/bin/regmount`, their
  man pages, and an example mount map in `/usr/share/doc/libreg-tools/`. On
  install, a `sc` alias for `winsc` is added only when no other package owns
  that name.
- **libreg-regedit** `/usr/bin/regedit` and its man page. regedit is a local
  desktop-style tool, not a service: run it and it opens the editor in your
  browser.

## Install

```bash
sudo dpkg -i clients/target/deb/libreg-tools_0.1.0_amd64.deb
sudo dpkg -i clients/target/deb/libreg-regedit_0.1.0_amd64.deb
```

Then just run the tools:

```bash
regmount /mnt/win/Windows/System32/config -o ~/.config/libreg/hives.conf
reg query HKLM\\SYSTEM\\...      # reg
winsc qc <service>               # or `sc qc <service>` if the alias was added
regedit                          # opens the editor in your browser
```

`regmount` inspects a hive file or a directory of hives and prints a ready to
use mount map (and writes one with `-o`), so you do not have to hand-author
`hives.conf`.

`regedit` binds 127.0.0.1 and opens your browser once it is listening. Pass
`--no-browser` on a headless host (it prints the URL to open by hand), and only
bind a non-loopback address behind an authenticating reverse proxy, since it
has no authentication of its own.

## Notes

- The service binary is installed as `winsc`, not `sc`, because Debian and
  Ubuntu ship `sc` (the spreadsheet calculator). The package adds a `/usr/bin/sc`
  symlink to `winsc` only when no `sc` command already exists, and removes that
  symlink on uninstall only if it still points at `winsc`. `reg` and `regedit`
  keep their Windows command names; check for local conflicts before deploying
  widely.
- The packages depend only on `libc6`; everything else is statically linked
  into the native binaries.
- On a build host with `fakeroot`, run the script under `fakeroot` for correct
  ownership without root. Run as root otherwise (dpkg-deb uses
  `--root-owner-group`).
