#!/bin/sh
# Packages target/release/vulnhound as target/debian/vulnhound_<version>-1_<arch>.deb.
#
# Build the binary on the oldest release it should run on (CI uses Debian 11, glibc 2.31): the
# package then installs on Debian 11+ and Ubuntu 20.04+. Needs git, dpkg-deb and objdump.
set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
bin=${1:-$top/target/release/vulnhound}
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$top/Cargo.toml" | head -n1)
arch=$(dpkg --print-architecture)
# As in the RPM changelog: whoever made the commit that is packaged.
maintainer=$(git -C "$top" log -1 --format='%an <%ae>')
# The newest glibc symbol version the binary uses.
glibc=$(objdump -T "$bin" | sed -n 's/.*GLIBC_\([0-9.]*\).*/\1/p' | sort -V | tail -n1)
test -n "$version" && test -n "$glibc"

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"
doc=$root/usr/share/doc/vulnhound
install -Dm0755 "$bin" "$root/usr/bin/vulnhound"
install -Dm0644 "$top/README.md" "$doc/README.md"
{
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: vulnhound"
    echo "Source: https://github.com/MarkHmnv/vulnhound"
    echo
    echo "Files: *"
    echo "Copyright: $(sed -n 's/^Copyright (c) //p' "$top/LICENSE" | head -n1)"
    echo "Comment: The binary includes these Rust crates, under their own licenses:"
    (cd "$top" && cargo tree --locked -e normal --prefix none --format ' {p}: {l}' \
        --target "$(rustc -vV | sed -n 's/^host: //p')" | sed 's/ (.*)//' | sort -u)
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' "$top/LICENSE"
} > "$doc/copyright"
printf 'vulnhound (%s-1) stable; urgency=medium\n\n  * Release %s\n\n -- %s  %s\n' \
    "$version" "$version" "$maintainer" "$(git -C "$top" log -1 --format=%cD)" |
    gzip -9n > "$doc/changelog.Debian.gz"

mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: vulnhound
Version: $version-1
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $(du -sk --exclude=DEBIAN "$root" | cut -f1)
Depends: libc6 (>= $glibc), libgcc-s1, apt
Section: admin
Priority: optional
Homepage: https://github.com/MarkHmnv/vulnhound
Description: Vulnerability scanner for Linux and Windows hosts
 Reports known CVEs of the installed packages, the updates that fix them,
 fixes not released yet and third-party packages that are outdated.
EOF

mkdir -p "$top/target/debian"
out=$top/target/debian/vulnhound_${version}-1_${arch}.deb
dpkg-deb --root-owner-group -Zxz --build "$root" "$out" > /dev/null
echo "$out"
