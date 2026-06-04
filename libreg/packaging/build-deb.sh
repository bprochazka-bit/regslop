#!/usr/bin/env bash
#
# Build Debian packages for the libreg C ABI shared library, using only
# dpkg-deb (no external cargo tooling, in keeping with the project's
# native-binary, no-registry-cache constraints). Produces two packages under
# libreg/target/deb:
#
#   liblibreg0       the runtime shared object, installed to the multiarch
#                    library path as liblibreg.so.0.MINOR.PATCH with the
#                    liblibreg.so.0 SONAME symlink. This is what a native
#                    binding (the Python ctypes binding, clients) dlopen's by
#                    name once installed.
#   liblibreg-dev    the C header (libreg/include/libreg.h -> /usr/include) and
#                    the liblibreg.so development symlink, for building C
#                    consumers against the library. Depends on the exact
#                    matching liblibreg0.
#
# The SONAME (liblibreg.so.0) is stamped at link time via RUSTFLAGS; a plain
# `cargo build` does not set one, so the normal dev build is unaffected. The
# major version in the SONAME and the runtime package name (liblibreg0) only
# bumps on an incompatible C ABI change; the file carries the full version so
# several minor revisions can coexist under one SONAME.
#
# Run from anywhere; paths resolve relative to this script.
set -euo pipefail

# Full version from Cargo.toml; SOMAJOR is the ABI major (the SONAME suffix and
# the runtime package-name suffix).
VERSION="0.1.0"
SOMAJOR="0"
MAINTAINER="libreg maintainers <bprochazka@verostech.com>"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"                       # the libreg/ crate
arch="$(dpkg --print-architecture)"
multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || gcc -dumpmachine)"
libdir="usr/lib/$multiarch"
out="$root/target/deb"

soname="liblibreg.so.$SOMAJOR"                       # what the binding loads
realname="liblibreg.so.$VERSION"                     # the actual file on disk

echo ">> building the cdylib with SONAME $soname"
# Stamp the SONAME at link time; a plain cargo build leaves it unset.
( cd "$root" && RUSTFLAGS="-Clink-arg=-Wl,-soname,$soname" cargo build --release )

built="$root/target/release/liblibreg.so"
if ! readelf -d "$built" 2>/dev/null | grep -q "Library soname: \[$soname\]"; then
  echo "!! built library is missing SONAME $soname" >&2
  exit 1
fi

rm -rf "$out"
mkdir -p "$out"

stage=""

# Write DEBIAN/control, computing the installed size from the staged data tree.
write_control() {
  local pkg="$1" depends="$2" desc="$3"
  local size_kb
  size_kb="$(du -k -s --exclude=DEBIAN "$stage" | cut -f1)"
  mkdir -p "$stage/DEBIAN"
  {
    echo "Package: $pkg"
    echo "Version: $VERSION"
    echo "Section: libs"
    echo "Priority: optional"
    echo "Architecture: $arch"
    [ -n "$depends" ] && echo "Depends: $depends"
    echo "Maintainer: $MAINTAINER"
    echo "Installed-Size: $size_kb"
    echo "$desc"
  } > "$stage/DEBIAN/control"
}

build_pkg() {
  local pkg="$1"
  echo ">> packaging $pkg"
  dpkg-deb --root-owner-group --build "$stage" "$out/${pkg}_${VERSION}_${arch}.deb" >/dev/null
}

# --------------------------------------------------------------- liblibreg0
# Runtime: the versioned shared object plus its SONAME symlink. ldconfig (run
# from the maintainer script) refreshes the linker cache so the binding finds
# it by SONAME without a path.
stage="$out/stage-runtime"
mkdir -p "$stage/$libdir"
install -m 0644 "$built" "$stage/$libdir/$realname"
ln -s "$realname" "$stage/$libdir/$soname"

mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
[ "$1" = "configure" ] && ldconfig || true
exit 0
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
{ [ "$1" = "remove" ] || [ "$1" = "purge" ]; } && ldconfig || true
exit 0
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/postrm"

write_control "liblibreg$SOMAJOR" "libc6" \
  "Description: libreg Windows registry hive library (C ABI runtime)
 The shared object for libreg, a cross-platform Windows Registry hive library.
 This package provides the stable C ABI (the liblibreg.so.$SOMAJOR SONAME) that
 native language bindings, such as the Python ctypes binding, load at run time.
 Install liblibreg-dev to build C consumers against it."
build_pkg "liblibreg$SOMAJOR"

# ------------------------------------------------------------- liblibreg-dev
# Development: the public header and the unversioned .so symlink a linker
# resolves with -llibreg. Depends on the exact runtime it describes.
stage="$out/stage-dev"
mkdir -p "$stage/usr/include" "$stage/$libdir"
install -m 0644 "$root/include/libreg.h" "$stage/usr/include/libreg.h"
ln -s "$soname" "$stage/$libdir/liblibreg.so"

write_control "liblibreg-dev" "liblibreg$SOMAJOR (= $VERSION)" \
  "Description: libreg Windows registry hive library (C ABI development files)
 The C header (libreg.h) and the liblibreg.so development symlink for building
 native consumers against libreg's stable C ABI. See the symbol and ownership
 rules in docs/ffi-abi.md. Runtime code is in liblibreg$SOMAJOR."
build_pkg "liblibreg-dev"

echo
echo ">> done. Packages in $out:"
ls -1 "$out"/*.deb
