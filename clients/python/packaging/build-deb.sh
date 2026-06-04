#!/usr/bin/env bash
#
# Build the Debian package for the libreg Python binding, using only dpkg-deb
# (no external tooling, in keeping with the project's native-binary,
# no-registry-cache, Debian-first constraints). Produces one package under
# clients/python/target/deb:
#
#   python3-libreg   the `libreg` Python package, installed to the system
#                    dist-packages path. Pure Python (Architecture: all); it
#                    loads the C ABI shared object at run time, so it depends on
#                    liblibreg0 (built by libreg/packaging/build-deb.sh) and
#                    loads liblibreg.so.0 by SONAME off a normal install.
#
# Run from anywhere; paths resolve relative to this script.
set -euo pipefail

VERSION="0.1.0"
MAINTAINER="libreg maintainers <bprochazka@verostech.com>"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"          # the clients/python/ package
out="$root/target/deb"

# Pure-Python package: architecture independent, no compile step. The C ABI it
# binds is shipped separately as liblibreg0 (libreg/packaging).
arch="all"
pkg="python3-libreg"

rm -rf "$out"
mkdir -p "$out"
stage="$out/stage"

# The importable package goes to the system dist-packages path (where Debian's
# system python3 looks), shipping only the runtime modules (not tests/examples).
destpkg="$stage/usr/lib/python3/dist-packages/libreg"
mkdir -p "$destpkg"
for mod in "$root"/libreg/*.py; do
  install -m 0644 "$mod" "$destpkg/$(basename "$mod")"
done

# Docs.
install -D -m 0644 "$root/README.md" "$stage/usr/share/doc/$pkg/README.md"

# Control, with the installed size computed from the staged data tree.
size_kb="$(du -k -s --exclude=DEBIAN "$stage" | cut -f1)"
mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<EOF
Package: $pkg
Version: $VERSION
Section: python
Priority: optional
Architecture: $arch
Depends: python3:any, liblibreg0 (>= $VERSION)
Maintainer: $MAINTAINER
Installed-Size: $size_kb
Description: Native Python binding for libreg (Windows registry hive library)
 A native, in-process Python binding for libreg. It links the libreg C ABI
 (the liblibreg0 shared object) through the standard library's ctypes and
 exposes every registry operation libreg offers: hive lifecycle, keys, values,
 SDDL security descriptors, validation, and a canonical dump. Pure Python with
 no third-party dependencies; the C ABI is provided by liblibreg0, which this
 package loads by SONAME (liblibreg.so.0) at run time. Set \$LIBREG_LIBRARY to
 override the library location.
EOF

echo ">> packaging $pkg"
dpkg-deb --root-owner-group --build "$stage" "$out/${pkg}_${VERSION}_${arch}.deb" >/dev/null

echo
echo ">> done. Package in $out:"
ls -1 "$out"/*.deb
