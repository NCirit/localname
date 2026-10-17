#!/bin/sh
# Boot the packaged unit under systemd in a disposable container, then "reboot" it.
set -eu
cd "$(dirname "$0")/../.."
docker build -q -f tests/systemd/Dockerfile -t localname-systemd-test . >/dev/null
docker rm -f localname-systemd >/dev/null 2>&1 || true
trap 'docker rm -f localname-systemd >/dev/null 2>&1 || true' EXIT
start() {
    docker start localname-systemd >/dev/null 2>&1 || docker run -d --name localname-systemd \
        --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock localname-systemd-test >/dev/null
    for _ in $(seq 1 50); do
        state=$(docker exec localname-systemd systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return ;; esac
        sleep 0.2
    done
}
start
docker exec localname-systemd /usr/local/bin/check || {
    docker exec localname-systemd journalctl -u localname --no-pager
    exit 1
}
docker stop localname-systemd >/dev/null
start
docker exec localname-systemd /usr/local/bin/after-reboot
