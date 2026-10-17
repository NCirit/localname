#!/bin/sh
# Container upgrade (M5): a 0.1.0 image writes state to a volume; the current image serves
# it unchanged, migrates on the next write, and keeps older revisions restorable.
set -eu
cd "$(dirname "$0")/../.."
old_commit=${LOCALNAME_OLD_COMMIT:-cd8fc7d}
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
work=$(mktemp -d)
volume=localname-upgrade-$$
cleanup() {
    docker rm -f localname-upgrade >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
git archive "$old_commit" | tar -x -C "$work"
docker build -q --target runtime -t localname:upgrade-old "$work" >/dev/null
docker build -q --target runtime -t localname:upgrade-new . >/dev/null
start() {
    docker run -d --name localname-upgrade -v "$volume:/var/lib/localname" \
        -e LOCALNAME_LISTEN=127.0.0.1:5354 -e LOCALNAME_ADVERTISE_ADDRESS=192.168.1.10 \
        --entrypoint /bin/sh "$1" /usr/local/bin/container-entrypoint >/dev/null
    for _ in $(seq 1 50); do
        docker exec localname-upgrade localname --config /var/lib/localname/config.toml status --output json 2>/dev/null \
            | grep -q '"daemon":{' && return
        sleep 0.2
    done
    docker logs localname-upgrade >&2
    exit 1
}
L() { docker exec localname-upgrade localname --config /var/lib/localname/config.toml "$@"; }
resolve() { L resolve "$1" --server 127.0.0.1:5354 --output json; }

start localname:upgrade-old
L add nas 192.168.1.20 >/dev/null
L add printer 192.168.1.30 >/dev/null
docker rm -f localname-upgrade >/dev/null

start localname:upgrade-new
L version | grep -q "localname $version"
resolve nas | grep -q 192.168.1.20
resolve printer | grep -q 192.168.1.30
L add tv 192.168.1.40 --output json | grep -q '"status":"passed"'
L config show | grep -q '^schema = 2'
L rollback 1 --output json | grep -q '"status":"passed"'
if resolve printer | grep -q 192.168.1.30; then echo "rollback across schemas failed" >&2; exit 1; fi
echo "container: 0.1.0 volume upgraded to $version"
