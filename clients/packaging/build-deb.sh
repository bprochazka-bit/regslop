#!/usr/bin/env bash
#
# Build Debian packages for the libreg client utilities, using only dpkg-deb
# (no external cargo tooling, in keeping with the project's native-binary,
# no-registry-cache constraints). Produces two packages under target/deb:
#
#   libreg-tools     /usr/bin/reg, /usr/bin/winsc, /usr/bin/regmount, man
#                    pages, example mount map. winsc gets a `sc` alias only
#                    when no other package owns that name (Debian and Ubuntu
#                    ship `sc`, the calculator).
#   libreg-regedit   /usr/bin/regedit and its man page. regedit is a local
#                    desktop-style tool that opens a browser, not a service.
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
install_file "$root/target/release/reg"      /usr/bin/reg      0755
install_file "$root/target/release/winsc"    /usr/bin/winsc    0755
install_file "$root/target/release/regmount" /usr/bin/regmount 0755
gz "$here/man/reg.1"      /tmp/reg.1.gz      && install_file /tmp/reg.1.gz      /usr/share/man/man1/reg.1.gz      0644
gz "$here/man/winsc.1"    /tmp/winsc.1.gz    && install_file /tmp/winsc.1.gz    /usr/share/man/man1/winsc.1.gz    0644
gz "$here/man/regmount.1" /tmp/regmount.1.gz && install_file /tmp/regmount.1.gz /usr/share/man/man1/regmount.1.gz 0644
install_file "$here/conf/hives.conf.example" /usr/share/doc/libreg-tools/hives.conf.example 0644

# Maintainer scripts: add a `sc` alias for winsc only when nothing else owns
# that name. Debian and Ubuntu ship `sc` (the spreadsheet calculator), so we
# never overwrite an existing command, and we only remove an alias we created.
mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if [ ! -e /usr/bin/sc ] && ! command -v sc >/dev/null 2>&1; then
    ln -s winsc /usr/bin/sc
    if [ -e /usr/share/man/man1/winsc.1.gz ] && [ ! -e /usr/share/man/man1/sc.1.gz ]; then
      ln -s winsc.1.gz /usr/share/man/man1/sc.1.gz
    fi
    echo "winsc: installed a 'sc' alias (no conflicting 'sc' command was found)."
  else
    echo "winsc: a 'sc' command already exists; invoke this tool as 'winsc'."
  fi
fi
exit 0
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  if [ -L /usr/bin/sc ] && [ "$(readlink /usr/bin/sc)" = "winsc" ]; then
    rm -f /usr/bin/sc
  fi
  if [ -L /usr/share/man/man1/sc.1.gz ] && [ "$(readlink /usr/share/man/man1/sc.1.gz)" = "winsc.1.gz" ]; then
    rm -f /usr/share/man/man1/sc.1.gz
  fi
fi
exit 0
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/postrm"

write_control "libreg-tools" \
  "Description: Offline Windows registry tools (reg, winsc, regmount)
 reg and winsc read and edit Windows registry hive files on Linux. They are
 modeled on the Windows reg.exe and sc.exe and operate on offline hives,
 mapping registry roots to files through a mount map. regmount inspects hive
 files and generates that mount map. winsc is installed under that name to
 avoid the clash with the sc spreadsheet calculator; a sc alias is added on
 install when no other package owns the name." \
  "libc6" ""
build_pkg "libreg-tools"

# -------------------------------------------------------------- libreg-regedit
stage="$out/stage-regedit"
mkdir -p "$stage"
install_file "$root/target/release/regedit" /usr/bin/regedit 0755
gz "$here/man/regedit.1" /tmp/regedit.1.gz && install_file /tmp/regedit.1.gz /usr/share/man/man1/regedit.1.gz 0644
# regedit is a local desktop-style tool: run it, it opens a browser. No systemd
# unit, no system-wide config, no state directory; the mount map is per-user
# ($LIBREG_HIVES or ~/.config/libreg/hives.conf).

write_control "libreg-regedit" \
  "Description: Web-based offline registry editor (regedit)
 A browser based registry editor for offline hive files, modeled on the
 Windows registry editor, with editable SDDL security, hive validation, an
 on-disk structure inspector, and a two-hive diff. Run it from a terminal and
 it opens the editor in your browser; it binds loopback by default." \
  "libc6" ""
build_pkg "libreg-regedit"

echo
echo ">> done. Packages in $out:"
ls -1 "$out"/*.deb
