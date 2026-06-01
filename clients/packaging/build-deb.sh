#!/usr/bin/env bash
#
# Build Debian packages for the libreg client utilities, using only dpkg-deb
# (no external cargo tooling, in keeping with the project's native-binary,
# no-registry-cache constraints). Produces two packages under target/deb:
#
#   libreg-tools     /usr/bin/reg, /usr/bin/sc, man pages, example mount map
#   libreg-regedit   /usr/bin/regedit, man page, systemd unit, /etc config
#
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

VERSION="0.1.0"
MAINTAINER="libreg maintainers <bprochazka@verostech.com>"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"          # the clients/ workspace
arch="$(dpkg --print-architecture)"
out="$root/target/deb"

echo ">> building release binaries"
( cd "$root" && cargo build --release )

rm -rf "$out"
mkdir -p "$out"

# install_file SRC DEST MODE: copy into the current staging tree.
stage=""
install_file() {
  local src="$1" dest="$stage$2" mode="$3"
  install -D -m "$mode" "$src" "$dest"
}

# Write DEBIAN/control, computing the installed size from the data tree.
write_control() {
  local pkg="$1" desc_short="$2" depends="$3" extra="$4"
  local size_kb
  size_kb="$(du -k -s --exclude=DEBIAN "$stage" | cut -f1)"
  mkdir -p "$stage/DEBIAN"
  {
    echo "Package: $pkg"
    echo "Version: $VERSION"
    echo "Section: utils"
    echo "Priority: optional"
    echo "Architecture: $arch"
    echo "Depends: $depends"
    echo "Maintainer: $MAINTAINER"
    echo "Installed-Size: $size_kb"
    echo "$desc_short"
  } > "$stage/DEBIAN/control"
  [ -n "$extra" ] && printf '%s' "$extra" >> /dev/null || true
}

gz() { gzip -9 -n -c "$1" > "$2"; }

build_pkg() {
  local pkg="$1"
  echo ">> packaging $pkg"
  dpkg-deb --root-owner-group --build "$stage" "$out/${pkg}_${VERSION}_${arch}.deb" >/dev/null
}

# ---------------------------------------------------------------- libreg-tools
stage="$out/stage-tools"
mkdir -p "$stage"
install_file "$root/target/release/reg" /usr/bin/reg 0755
install_file "$root/target/release/sc"  /usr/bin/sc  0755
gz "$here/man/reg.1" /tmp/reg.1.gz && install_file /tmp/reg.1.gz /usr/share/man/man1/reg.1.gz 0644
gz "$here/man/sc.1"  /tmp/sc.1.gz  && install_file /tmp/sc.1.gz  /usr/share/man/man1/sc.1.gz  0644
install_file "$here/conf/hives.conf.example" /usr/share/doc/libreg-tools/hives.conf.example 0644
write_control "libreg-tools" \
  "Description: Offline Windows registry tools (reg, sc)
 reg and sc read and edit Windows registry hive files on Linux. They are
 modeled on the Windows reg.exe and sc.exe and operate on offline hives,
 mapping registry roots to files through a mount map." \
  "libc6" ""
build_pkg "libreg-tools"

# -------------------------------------------------------------- libreg-regedit
stage="$out/stage-regedit"
mkdir -p "$stage"
install_file "$root/target/release/regedit" /usr/bin/regedit 0755
gz "$here/man/regedit.1" /tmp/regedit.1.gz && install_file /tmp/regedit.1.gz /usr/share/man/man1/regedit.1.gz 0644
install_file "$here/systemd/regedit.service" /lib/systemd/system/regedit.service 0644
install_file "$here/conf/regedit.conf" /etc/libreg/regedit.conf 0644
# State directory the systemd unit makes writable for hives and the mount map.
mkdir -p "$stage/var/lib/libreg"

# Preserve operator edits to the config file.
mkdir -p "$stage/DEBIAN"
echo "/etc/libreg/regedit.conf" > "$stage/DEBIAN/conffiles"

# Maintainer scripts: reload systemd, never auto-start a network service.
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  echo "regedit installed. Enable it with: systemctl enable --now regedit"
fi
exit 0
EOF
cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop regedit.service 2>/dev/null || true
fi
exit 0
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"

write_control "libreg-regedit" \
  "Description: Web-based offline registry editor (regedit)
 A browser based registry editor for offline hive files, modeled on the
 Windows registry editor, with editable SDDL security, hive validation, an
 on-disk structure inspector, and a two-hive diff. Ships a systemd unit that
 binds loopback by default." \
  "libc6" ""
build_pkg "libreg-regedit"

echo
echo ">> done. Packages in $out:"
ls -1 "$out"/*.deb
