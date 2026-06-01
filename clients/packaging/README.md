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

- **libreg-tools** `/usr/bin/reg`, `/usr/bin/sc`, their man pages, and an
  example mount map in `/usr/share/doc/libreg-tools/`.
- **libreg-regedit** `/usr/bin/regedit`, its man page, a systemd unit
  (`/lib/systemd/system/regedit.service`), and a conffile
  (`/etc/libreg/regedit.conf`). Creates `/var/lib/libreg` for hives and the
  mount map.

## Install

```bash
sudo dpkg -i clients/target/deb/libreg-tools_0.1.0_amd64.deb
sudo dpkg -i clients/target/deb/libreg-regedit_0.1.0_amd64.deb
```

The regedit package installs but does not auto-start the service (it is a
network service with no authentication). Enable it when ready:

```bash
sudo systemctl enable --now regedit
```

Edit `/etc/libreg/regedit.conf` to set the bind address, port, and any extra
arguments, then `systemctl restart regedit`. The unit binds 127.0.0.1 by
default; only expose regedit behind an authenticating reverse proxy.

## Notes

- Binaries are installed as `reg`, `sc`, and `regedit` to match the Windows
  command names. There are no same-named binaries in a base Debian install, but
  check for local conflicts before deploying widely.
- The packages depend only on `libc6`; everything else is statically linked
  into the native binaries.
- On a build host with `fakeroot`, run the script under `fakeroot` for correct
  ownership without root. Run as root otherwise (dpkg-deb uses
  `--root-owner-group`).
