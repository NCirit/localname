#!/bin/sh
# Package install, upgrade from 0.1.0 (config schema 1), reboot, removal, and purge, for
# .deb on Debian and .rpm on Fedora under systemd (M5).
set -eu
cd "$(dirname "$0")/../.."
old_commit=${LOCALNAME_OLD_COMMIT:-cd8fc7d}
# The upgrade target is whatever this tree builds.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
work=$(mktemp -d)
trap 'rm -rf "$work"; docker rm -f localname-pkg >/dev/null 2>&1 || true' EXIT
git archive "$old_commit" | tar -x -C "$work" --one-top-level=old
docker build -q -f tests/packaging/Dockerfile.build --build-arg CACHE=old --target export --output "type=local,dest=$work/old-bin" "$work/old" >/dev/null
docker build -q -f tests/packaging/Dockerfile.build --target export --output "type=local,dest=$work/new-bin" . >/dev/null
rm -rf tests/packaging/out && mkdir -p tests/packaging/out
for build in "0.1.0 old-bin" "$version new-bin"; do
    set -- $build
    docker run --rm -v "$PWD:/src:ro" -v "$work/$2:/bin-in:ro" -v "$PWD/tests/packaging/out:/out" fedora:41 sh -c \
        "dnf install -y -q rpm-build dpkg >/dev/null 2>&1 && SOURCE_DATE_EPOCH=0 /src/packaging/build-packages.sh $1 x86_64 /bin-in/localname /out >/dev/null"
done
ls tests/packaging/out

boot() {
    docker start localname-pkg >/dev/null 2>&1 || docker run -d --name localname-pkg --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$1" >/dev/null
    for _ in $(seq 1 100); do
        state=$(docker exec localname-pkg systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return ;; esac
        sleep 0.2
    done
}
phase() { docker exec -e LOCALNAME_VERSION="$version" localname-pkg "/usr/local/bin/$1"; }
reboot() { docker stop localname-pkg >/dev/null; boot "$1"; }

docker build -q -f tests/packaging/Dockerfile.debian -t localname-pkg-debian . >/dev/null
boot localname-pkg-debian
phase deb-phase1.sh
phase deb-phase2.sh
reboot localname-pkg-debian
phase deb-phase3.sh
docker rm -f localname-pkg >/dev/null

docker build -q -f tests/packaging/Dockerfile.fedora -t localname-pkg-fedora . >/dev/null
boot localname-pkg-fedora
phase rpm-phase1.sh
reboot localname-pkg-fedora
phase rpm-phase2.sh
echo "packages: all upgrade paths passed"
