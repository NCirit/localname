#!/bin/sh
# Client split DNS on Linux: apply, reboot, roll back, reboot (M3b).
set -eu
cd "$(dirname "$0")/../../.."
docker build -q -f tests/client/linux/Dockerfile -t localname-client-linux . >/dev/null
docker rm -f localname-client >/dev/null 2>&1 || true
trap 'docker rm -f localname-client >/dev/null 2>&1 || true' EXIT
boot() {
    docker start localname-client >/dev/null 2>&1 || docker run -d --name localname-client \
        --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock localname-client-linux >/dev/null
    for _ in $(seq 1 100); do
        state=$(docker exec localname-client systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return ;; esac
        sleep 0.2
    done
    echo "systemd did not finish booting" >&2
    exit 1
}
phase() {
    docker exec localname-client "/usr/local/bin/$1" || {
        docker exec localname-client sh -c 'resolvectl status --no-pager; journalctl -u systemd-resolved -u localname --no-pager | tail -50'
        exit 1
    }
}
reboot() {
    docker stop localname-client >/dev/null
    boot
}
boot
phase phase1
reboot
phase phase2
reboot
phase phase3
