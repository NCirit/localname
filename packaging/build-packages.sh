#!/bin/sh
# Build .deb and (when rpmbuild exists) .rpm packages from a prebuilt binary.
#   packaging/build-packages.sh VERSION ARCH BINARY OUTDIR
# ARCH is the Rust architecture: x86_64 or aarch64.
set -eu
version=$1 arch=$2 binary=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
case "$arch" in
    x86_64) deb_arch=amd64 ;;
    aarch64) deb_arch=arm64 ;;
    *) echo "unsupported architecture $arch" >&2; exit 2 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stage=$work/deb
install -Dm0755 "$binary" "$stage/usr/bin/localname"
install -Dm0644 "$root/packaging/systemd/localname.service" "$stage/usr/lib/systemd/system/localname.service"
install -Dm0644 "$root/packaging/systemd/localname.sysusers" "$stage/usr/lib/sysusers.d/localname.conf"
install -Dm0644 "$root/packaging/systemd/localname.tmpfiles" "$stage/usr/lib/tmpfiles.d/localname.conf"
install -Dm0644 "$root/README.md" "$stage/usr/share/doc/localname/README.md"
for file in SKILL.md agents/openai.yaml; do
    install -Dm0644 "$root/skills/localname/$file" "$stage/usr/share/localname-skills/localname/$file"
done
mkdir -p "$stage/DEBIAN"
for script in postinst prerm postrm; do
    install -m0755 "$root/packaging/deb/$script" "$stage/DEBIAN/$script"
done
size=$(du -sk "$stage/usr" | cut -f1)
cat > "$stage/DEBIAN/control" <<CONTROL
Package: localname
Version: $version
Architecture: $deb_arch
Maintainer: localname maintainers <noreply@github.com>
Installed-Size: $size
Depends: systemd
Section: net
Priority: optional
Homepage: https://github.com/NCirit/localname
Description: Fast, safe, friendly names for local networks
 localname gives devices on a home network memorable names such as nas.home.arpa:
 an authoritative local DNS zone with forwarding, guided router setup, an optional
 HTTP/WebSocket proxy, and explicit HTTPS trust modes.
CONTROL
find "$stage" -exec touch -h -d @"${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group -Zxz --build "$stage" "$out/localname_${version}_${deb_arch}.deb" >/dev/null
echo "$out/localname_${version}_${deb_arch}.deb"

if command -v rpmbuild >/dev/null; then
    source=$work/rpm-source
    mkdir -p "$source"
    cp "$binary" "$source/localname"
    cp "$root/packaging/systemd/localname.service" "$root/packaging/systemd/localname.sysusers" \
        "$root/packaging/systemd/localname.tmpfiles" "$root/README.md" "$source/"
    for file in SKILL.md agents/openai.yaml; do
        install -Dm0644 "$root/skills/localname/$file" "$source/skills/localname/$file"
    done
    rpmbuild --quiet -bb "$root/packaging/rpm/localname.spec" \
        --define "_topdir $work/rpmbuild" \
        --define "localname_version $(echo "$version" | tr - '~')" \
        --define "localname_arch $arch" \
        --define "localname_source $source" \
        --define "_build_id_links none"
    find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$out/" \;
    ls "$out"/*.rpm
fi
