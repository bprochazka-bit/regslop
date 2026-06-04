# libreg Debian packaging

Packages the libreg C ABI (Layer 4 `api/`, the `cdylib` from issue #106) as
installable `.deb` artifacts, so native bindings load it off a normal system
install instead of a repo-relative `target/` path.

## Build

```bash
libreg/packaging/build-deb.sh
```

Uses only `dpkg-deb` (no external cargo tooling), matching
`clients/packaging/build-deb.sh`. Output lands in `libreg/target/deb/`:

- **`liblibreg0`** (runtime): the shared object at
  `/usr/lib/<multiarch>/liblibreg.so.0.MINOR.PATCH` with the
  `liblibreg.so.0` SONAME symlink. `ldconfig` runs on install/remove so the
  linker cache resolves the SONAME. This is what the Python `ctypes` binding
  `dlopen`s by name (`liblibreg.so.0`).
- **`liblibreg-dev`**: `libreg.h` to `/usr/include` and the `liblibreg.so`
  development symlink (so `cc -llibreg` resolves). Depends on the exact
  matching `liblibreg0`.

## SONAME and versioning

The SONAME (`liblibreg.so.0`) is stamped at link time via
`RUSTFLAGS=-Clink-arg=-Wl,-soname,...`; a plain `cargo build` sets none, so the
dev build is unaffected. The major in the SONAME and the `liblibreg0`
package-name suffix only bump on an incompatible C ABI change; the file carries
the full version, so minor revisions coexist under one SONAME.

## Verify

```bash
dpkg-deb -I libreg/target/deb/liblibreg0_*.deb      # control + Depends
dpkg-deb -c libreg/target/deb/liblibreg0_*.deb      # the SONAME symlink chain
dpkg-deb -c libreg/target/deb/liblibreg-dev_*.deb   # header + dev symlink

# Link a C consumer against the -dev tree and run it against the runtime,
# by name, with no repo target/ and no $LIBREG_LIBRARY:
root=/tmp/libreg-root; rm -rf "$root"
dpkg-deb -x libreg/target/deb/liblibreg0_*.deb "$root"
dpkg-deb -x libreg/target/deb/liblibreg-dev_*.deb "$root"
cc -I "$root/usr/include" libreg/tests/ffi/smoke.c \
   -L "$root/usr/lib/x86_64-linux-gnu" -llibreg -o /tmp/smoke
LD_LIBRARY_PATH="$root/usr/lib/x86_64-linux-gnu" /tmp/smoke
```
